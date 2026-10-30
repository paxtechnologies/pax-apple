// SPDX-License-Identifier: GPL-3.0-only
// One blocked-apps list for Mac and iPhone (1.3). An account has ONE list on the Pax server
// (GET /v1/apps). Pax for Mac and this app both show it, whichever device an app was added on,
// each app labelled "Added on your Mac" / "Added on iPhone".
//
// The rules, the same everywhere:
//   * Adding is instant. Removing goes only through the server's turn-off wait (the person you
//     trust is emailed first, fail closed). Nothing is ever removed on this device alone, and an
//     app never leaves the list here before the server's own clock is past its wait
//     (AppRemoval.reconcile).
//   * Merge, never subtract: this device's list is the server's list plus anything added here
//     that hasn't reached the server yet. Those are sent once (a backfill for apps blocked before
//     the server had a list, then any add whose send failed).
//   * On a device set up from a Mac, apps added on the Mac are shown read-only: they come off
//     only from Pax on that Mac, through the wait. Apps added on the phone are applied by the
//     phone's own Screen Time layer (PhoneAppLayer), in its own named store, so the Mac's
//     profile stays in charge and its blocks always win.
//   * A server without the list (404) keeps the 1.2 behaviour exactly: the local list, no
//     labels, no removal, and nothing new on a device set up from a Mac.
//
// Performance: the list shows straight away from a small cache in the App Group (AppsCacheStore,
// read on first use, never at launch). It's refreshed in the background with ETag/304
// (AppsRefresher, an actor: the request and the decoding run off the main thread), only on
// foreground or pull to refresh, never on a timer. Nothing here is on the DNS path.
import Foundation

/// Where an app was added (GET /v1/apps "source").
enum AppSource: String, Codable, Equatable {
    case mac
    case iphone
}

/// One row of Blocked apps.
struct AppRow: Equatable, Identifiable {
    var bundleID: String
    var name: String
    /// nil when the server has no list (no labels, as in 1.2).
    var source: AppSource?
    /// A removal waiting on the server (from this device or another one).
    var pending: PendingAppRemoval?
    /// Remove is offered (the server keeps the list, nothing waiting, and not read-only here).
    var removable: Bool
    /// Added on the Mac and shown on a device set up from that Mac: removed only from the Mac.
    var macOnly: Bool
    /// Already on the server's list (false: added here, not sent yet).
    var onServer: Bool
    var id: String { bundleID.lowercased() }
}

enum AppsSync {
    static func key(_ bundleID: String) -> String { bundleID.lowercased() }

    /// The server's word for where an app was added. An older answer without one: added here if
    /// this device has it, otherwise on a device set up from a Mac it counts as the Mac's
    /// (read-only, the careful reading), and elsewhere as a phone's.
    static func source(of a: BlockedAppInfo, inLocal: Bool, macSetUp: Bool) -> AppSource {
        if let s = a.source.flatMap(AppSource.init(rawValue:)) { return s }
        if inLocal { return .iphone }
        return macSetUp ? .mac : .iphone
    }

    /// A removal the server says is waiting for this app.
    static func serverPending(_ a: BlockedAppInfo) -> PendingAppRemoval? {
        guard let r = a.pending_removal, r.status == "pending", r.action == AppRemoval.action else { return nil }
        return PendingAppRemoval(bundleID: a.bundle_id, requestID: r.request_id, effectiveAt: r.effective_at)
    }

    /// The one list, as this device shows it: the server's apps in the server's order, then any
    /// added here that the server doesn't have yet. Without a server list: the local list (1.2).
    static func rows(local: [BlockedApp], pending: [PendingAppRemoval], server: AppsViewInfo?,
                     serverHasList: Bool, macSetUp: Bool) -> [AppRow] {
        let localByKey = Dictionary(local.map { (key($0.bundleID), $0) }, uniquingKeysWith: { a, _ in a })
        func localPending(_ b: String) -> PendingAppRemoval? { pending.first { key($0.bundleID) == key(b) } }

        guard serverHasList, let server else {
            return local.map { a in
                let p = localPending(a.bundleID)
                return AppRow(bundleID: a.bundleID, name: a.name, source: nil, pending: p,
                              removable: serverHasList && p == nil,
                              macOnly: false, onServer: false)
            }
        }
        var out: [AppRow] = []
        var seen = Set<String>()
        for a in server.apps {
            let k = key(a.bundle_id)
            guard !seen.contains(k) else { continue }
            seen.insert(k)
            let mine = localByKey[k]
            let src = source(of: a, inLocal: mine != nil, macSetUp: macSetUp)
            let macOnly = macSetUp && src == .mac && mine == nil
            let p = serverPending(a) ?? localPending(a.bundle_id)
            let name = [a.name, mine?.name, AppCatalog.entry(bundleID: a.bundle_id)?.name]
                .compactMap { $0 }.first { !$0.isEmpty } ?? a.bundle_id
            out.append(AppRow(bundleID: mine?.bundleID ?? a.bundle_id, name: name, source: src, pending: p,
                              removable: !macOnly && p == nil, macOnly: macOnly, onServer: true))
        }
        for a in local where !seen.contains(key(a.bundleID)) {
            seen.insert(key(a.bundleID))
            let p = localPending(a.bundleID)
            // Not on the server yet: Remove would first put it there, then start the wait.
            out.append(AppRow(bundleID: a.bundleID, name: a.name, source: .iphone, pending: p,
                              removable: p == nil, macOnly: false, onServer: false))
        }
        return out
    }

    /// Apps on the server's list this device should also block (merge, never subtract): every app
    /// it doesn't have yet, except, on a device set up from a Mac, the Mac's own (its profile
    /// applies them). Protected IDs are never taken in.
    static func toAdopt(local: [BlockedApp], server: AppsViewInfo, macSetUp: Bool) -> [BlockedApp] {
        var have = Set(local.map { key($0.bundleID) })
        var out: [BlockedApp] = []
        for a in server.apps {
            let k = key(a.bundle_id)
            guard !have.contains(k), !AppBlockRules.isProtected(a.bundle_id), AppBlockRules.isBundleID(a.bundle_id) else { continue }
            if macSetUp && source(of: a, inLocal: false, macSetUp: true) == .mac { continue }
            have.insert(k)
            let name = (a.name ?? "").isEmpty ? (AppCatalog.entry(bundleID: a.bundle_id)?.name ?? a.bundle_id) : a.name!
            out.append(BlockedApp(bundleID: a.bundle_id, name: name))
        }
        return out
    }

    /// Apps blocked here that the server's list doesn't have: sent to it (POST /v1/apps). The first
    /// time this is the backfill of apps blocked before the server had a list. Never one with a
    /// removal waiting here, and never one the server refused (422, protected).
    static func toPush(local: [BlockedApp], pending: [PendingAppRemoval], server: AppsViewInfo,
                       refused: Set<String>) -> [BlockedApp] {
        let listed = Set(server.apps.map { key($0.bundle_id) })
        let waiting = Set(pending.map { key($0.bundleID) })
        return local.filter { a in
            let k = key(a.bundleID)
            return !listed.contains(k) && !waiting.contains(k) && !refused.contains(k) && !AppBlockRules.isProtected(a.bundleID)
        }
    }

    /// Bundle IDs already on the one list (for "That app is already blocked").
    static func listedIDs(_ rows: [AppRow]) -> [String] { rows.map { $0.bundleID } }
}

/// Where Blocked apps shows, and what a device set up from a Mac may do there.
enum AppsAccess {
    /// A device set up from a Mac shows Blocked apps only when the server keeps the one list
    /// (1.2 behaviour otherwise: not shown).
    static func shows(macSetUp: Bool, serverHasList: Bool) -> Bool { !macSetUp || serverHasList }

    /// The phone's own Screen Time layer on a device set up from a Mac: asked for once, only when
    /// the person first adds an app there, and never again (asking a second time lifts the
    /// delete block). Never on a device this app set up itself (that has its own, from set-up).
    static func shouldAskScreenTime(macSetUp: Bool, alreadyAsked: Bool, approved: Bool) -> Bool {
        macSetUp && !alreadyAsked && !approved
    }
}

// MARK: - The cache (App Group) and the background refresh

/// What this device last read from GET /v1/apps, kept in the App Group so the list shows at once.
struct AppsCache: Codable, Equatable {
    /// nil: never asked; false: the server has no list (404); true: it has one.
    var hasList: Bool?
    var view: AppsViewInfo?
    var etag: String?
    /// Apps the server refused (422, protected): never sent again.
    var refused: [String] = []
    /// The one-time backfill of apps blocked before the server had a list was sent.
    var backfilled = false

    init() {}

    private enum K: String, CodingKey { case hasList, view, etag, refused, backfilled }

    /// Every field on its own: an unreadable cache is just an empty one (it's only a cache).
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: K.self)
        hasList = (try? c.decodeIfPresent(Bool.self, forKey: .hasList)) ?? nil
        view = (try? c.decodeIfPresent(AppsViewInfo.self, forKey: .view)) ?? nil
        etag = (try? c.decodeIfPresent(String.self, forKey: .etag)) ?? nil
        refused = ((try? c.decodeIfPresent([String].self, forKey: .refused)) ?? nil) ?? []
        backfilled = ((try? c.decodeIfPresent(Bool.self, forKey: .backfilled)) ?? nil) ?? false
    }
}

/// The cache in the App Group's defaults. Small (at most a few hundred short entries), read
/// synchronously on first use: no network, nothing awaited.
struct AppsCacheStore {
    static let key = "pax.apps.v1"
    var defaults: UserDefaults

    init(defaults: UserDefaults = Pax.shared) { self.defaults = defaults }

    func load() -> AppsCache {
        guard let d = defaults.data(forKey: Self.key),
              let c = try? JSONDecoder().decode(AppsCache.self, from: d) else { return AppsCache() }
        return c
    }

    func save(_ c: AppsCache) {
        if let d = try? JSONEncoder().encode(c) { defaults.set(d, forKey: Self.key) }
    }

    func update(_ change: (inout AppsCache) -> Void) {
        var c = load()
        change(&c)
        save(c)
    }
}

/// One answer from GET /v1/apps.
enum AppsFetch: Equatable {
    /// 304: nothing changed since the ETag sent.
    case notModified
    case list(AppsViewInfo, etag: String?)
    /// 404/405: the server has no blocked-apps list (1.2 behaviour).
    case noList
}

/// The sign-in is no longer valid (401): the app offers "Sign in to Pax again".
enum AppsFetchError: Error, Equatable {
    case signedOut
}

/// The network side, so the refresh can be tested without it (PaxAPI conforms in the app).
protocol AppsFetching: AnyObject {
    func fetchApps(etag: String?) async throws -> AppsFetch
}

/// What a refresh found.
enum AppsRefreshResult: Equatable {
    /// `fresh`: read just now (200). false: the cached list, unchanged (304), whose server clock
    /// is older than the real one, so it can only ever keep an app longer, never drop it early.
    case list(AppsViewInfo, fresh: Bool)
    case noList
    case signedOut
    case failed
}

/// The background refresh. An actor, so the request and the JSON decoding never run on the main
/// thread; overlapping calls share one request (no duplicates, no loops). Errors keep the cache.
actor AppsRefresher {
    private let fetcher: AppsFetching
    private let store: AppsCacheStore
    private var inFlight: Task<AppsRefreshResult, Never>?

    init(fetcher: AppsFetching, store: AppsCacheStore = AppsCacheStore()) {
        self.fetcher = fetcher
        self.store = store
    }

    func refresh() async -> AppsRefreshResult {
        if let t = inFlight { return await t.value }
        let t = Task { await self.fetchOnce() }
        inFlight = t
        let r = await t.value
        inFlight = nil
        return r
    }

    private func fetchOnce() async -> AppsRefreshResult {
        let cache = store.load()
        // An ETag only means something next to the list it came with.
        let etag = cache.view == nil || cache.hasList != true ? nil : cache.etag
        do {
            switch try await fetcher.fetchApps(etag: etag) {
            case .notModified:
                guard let v = cache.view else { store.update { $0.etag = nil }; return .failed }
                return .list(v, fresh: false)
            case .list(let v, let tag):
                store.update { c in
                    c.hasList = true
                    c.view = v
                    c.etag = tag
                }
                return .list(v, fresh: true)
            case .noList:
                store.update { c in
                    c.hasList = false
                    c.view = nil
                    c.etag = nil
                }
                return .noList
            }
        } catch AppsFetchError.signedOut {
            return .signedOut
        } catch {
            return .failed
        }
    }
}
