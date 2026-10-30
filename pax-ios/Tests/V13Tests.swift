// SPDX-License-Identifier: GPL-3.0-only
// 1.3: one blocked-apps list for Mac and iPhone (AppsSync). Merge never subtracts, labels say where
// each app was added, a server without the list (404) keeps the 1.2 behaviour, ETag/304 refresh in
// the background, a device set up from a Mac sees the Mac's apps read-only and asks for Screen
// Time once, and nothing on the launch path waits for the network.
import XCTest

private func app(_ b: String, _ name: String? = nil, source: String? = nil, pendingUntil: Int? = nil) -> BlockedAppInfo {
    BlockedAppInfo(bundle_id: b, name: name,
                   pending_removal: pendingUntil.map {
                       BlocklistRequestInfo(request_id: "req-\(b)", action: "unblock_app", domain: nil,
                                            status: "pending", effective_at: $0, seconds_remaining: nil)
                   },
                   source: source)
}

final class OneListTests: XCTestCase {
    private let baidu = BlockedApp(bundleID: "com.baidu.BaiduMobile", name: "Baidu")
    private let kik = BlockedApp(bundleID: "com.kik.chat", name: "Kik")

    func testServerListMergedWithLocalAndLabelled() {
        let server = AppsViewInfo(now: 100, apps: [app("com.burbn.instagram", "Instagram", source: "mac"),
                                                   app("com.baidu.baidumobile", "Baidu", source: "iphone")])
        let rows = AppsSync.rows(local: [baidu, kik], pending: [], server: server, serverHasList: true, macSetUp: false)
        // Server order first, then what this device added that the server doesn't have yet.
        XCTAssertEqual(rows.map { $0.name }, ["Instagram", "Baidu", "Kik"])
        XCTAssertEqual(rows.map { $0.source }, [.mac, .iphone, .iphone])
        XCTAssertEqual(rows.map { $0.onServer }, [true, true, false])
        // Case-insensitive: Baidu is one row, with this device's spelling of its ID.
        XCTAssertEqual(rows[1].bundleID, "com.baidu.BaiduMobile")
        XCTAssertEqual(Set(rows.map { $0.id }).count, rows.count)
        XCTAssertEqual(PaxCopy.blockedAppsAdded(.mac, isPad: false), "Added on your Mac")
        XCTAssertEqual(PaxCopy.blockedAppsAdded(.iphone, isPad: false), "Added on iPhone")
        XCTAssertFalse(PaxCopy.blockedAppsAdded(.iphone, isPad: true).contains("this iPhone"))
    }

    func testOlderAnswerWithoutSource() {
        let a = app("com.example.app")
        XCTAssertEqual(AppsSync.source(of: a, inLocal: true, macSetUp: true), .iphone)
        XCTAssertEqual(AppsSync.source(of: a, inLocal: false, macSetUp: true), .mac)        // careful: read-only
        XCTAssertEqual(AppsSync.source(of: a, inLocal: false, macSetUp: false), .iphone)
        XCTAssertEqual(AppsSync.source(of: app("x.y", source: "weird"), inLocal: false, macSetUp: false), .iphone)
    }

    func test404KeepsThe12Behaviour() {
        // No server list: the local list exactly, no labels, no removal.
        let rows = AppsSync.rows(local: [baidu], pending: [], server: nil, serverHasList: false, macSetUp: false)
        XCTAssertEqual(rows.count, 1)
        XCTAssertNil(rows[0].source)
        XCTAssertFalse(rows[0].removable)
        // A stale cached view is ignored when the server says it has no list.
        let stale = AppsViewInfo(now: 1, apps: [app("com.burbn.instagram", source: "mac")])
        XCTAssertEqual(AppsSync.rows(local: [baidu], pending: [], server: stale, serverHasList: false, macSetUp: false).count, 1)
        // A device set up from a Mac doesn't show Blocked apps at all (1.2), until the server has the list.
        XCTAssertFalse(HomeLayout.protection(macSetUp: true).contains(.blockedApps))
        XCTAssertFalse(HomeLayout.protection(macSetUp: true, appsList: false).contains(.blockedApps))
        XCTAssertEqual(HomeLayout.protection(macSetUp: true, appsList: false), [.blockedSites, .youtube])
        XCTAssertEqual(PaxCopy.blockedAppsFooter(serverHasList: false),
                       "Adding an app is instant. Blocked apps stay blocked: removing one comes with a Pax update, "
                        + "and will take your turn-off wait.")
    }

    func testMacSetUpShowsTheListAndOnlyAddsToIt() {
        let mac = HomeLayout.all(macSetUp: true, appsList: true)
        XCTAssertTrue(mac.contains(.blockedApps))
        for item in [SettingsItem.lockScreenTime, .encryptedDNS, .appsToClose, .computerSetup] {
            XCTAssertFalse(mac.contains(item), "\(item)")
        }
        XCTAssertEqual(mac.last, .turnOff)
        // A device this app set up is unchanged.
        XCTAssertEqual(HomeLayout.protection(macSetUp: false, appsList: true), HomeLayout.protection(macSetUp: false))
        XCTAssertTrue(AppsAccess.shows(macSetUp: false, serverHasList: false))
        XCTAssertFalse(AppsAccess.shows(macSetUp: true, serverHasList: false))
        XCTAssertTrue(AppsAccess.shows(macSetUp: true, serverHasList: true))
    }

    func testMacAddedAppsAreReadOnlyOnAMacSetUp() {
        let server = AppsViewInfo(now: 100, apps: [app("com.burbn.instagram", "Instagram", source: "mac"),
                                                   app("com.baidu.BaiduMobile", "Baidu", source: "iphone")])
        let rows = AppsSync.rows(local: [baidu], pending: [], server: server, serverHasList: true, macSetUp: true)
        XCTAssertTrue(rows[0].macOnly)
        XCTAssertFalse(rows[0].removable)
        XCTAssertFalse(rows[1].macOnly)
        XCTAssertTrue(rows[1].removable)
        // And removal itself only for the phone's own apps (the Mac's aren't in its list).
        var p = PaxPolicy()
        p.macSetUp = true
        p.blockedApps = [baidu]
        XCTAssertFalse(AppRemoval.canRemove("com.burbn.instagram", policy: p, serverHasList: true))
        XCTAssertTrue(AppRemoval.canRemove("com.baidu.BaiduMobile", policy: p, serverHasList: true))
        // On a device this app set up, a Mac-added app can be removed, through the wait.
        let phone = AppsSync.rows(local: [], pending: [], server: server, serverHasList: true, macSetUp: false)
        XCTAssertFalse(phone[0].macOnly)
        XCTAssertTrue(phone[0].removable)
        // A Mac-added app already "Blocked" here: no second add.
        XCTAssertEqual(AppBlockRules.problem("com.burbn.instagram", policy: p, listed: AppsSync.listedIDs(rows)), .alreadyBlocked)
    }

    func testMergeNeverSubtracts() {
        let server = AppsViewInfo(now: 100, apps: [app("com.burbn.instagram", "Instagram", source: "mac"),
                                                   app("ph.telegra.Telegraph", nil, source: "iphone"),
                                                   app("COM.KIK.CHAT", "Kik", source: "iphone"),
                                                   app("com.apple.Preferences", "Settings", source: "iphone")])
        // A device this app set up blocks everything on the list it doesn't have yet.
        let adopt = AppsSync.toAdopt(local: [kik], server: server, macSetUp: false)
        XCTAssertEqual(adopt.map { $0.bundleID }, ["com.burbn.instagram", "ph.telegra.Telegraph"])
        XCTAssertEqual(adopt[1].name, "Telegram")                        // the catalog's name when none came
        // A Mac set-up leaves the Mac's apps to the Mac's profile.
        XCTAssertEqual(AppsSync.toAdopt(local: [], server: server, macSetUp: true).map { $0.bundleID },
                       ["ph.telegra.Telegraph", "COM.KIK.CHAT"])
        // An app missing from the server list never comes off here without a removal (no subtract).
        var p = PaxPolicy()
        p.blockedApps = [baidu]
        let r = AppRemoval.reconcile(local: p.pendingAppRemovals, blocked: p.blockedApps, server: server)
        XCTAssertEqual(r.removeNow, [])
    }

    func testBackfillSendsOnlyWhatTheServerLacks() {
        let server = AppsViewInfo(now: 100, apps: [app("com.Baidu.BaiduMobile", source: "iphone")])
        let tinder = BlockedApp(bundleID: "com.cardify.tinder", name: "Tinder")
        let pending = [PendingAppRemoval(bundleID: "com.kik.chat", requestID: "r", effectiveAt: 500)]
        let push = AppsSync.toPush(local: [baidu, kik, tinder, BlockedApp(bundleID: "com.apple.Maps", name: "Maps")],
                                   pending: pending, server: server, refused: [])
        XCTAssertEqual(push, [tinder])
        XCTAssertEqual(AppsSync.toPush(local: [tinder], pending: [], server: server, refused: ["com.cardify.tinder"]), [])
        XCTAssertEqual(AppsSync.toPush(local: [baidu], pending: [], server: server, refused: []), [])
    }

    func testRemovalStartedElsewhereWaitsForTheServersClock() {
        // Another device asked to remove Baidu: shown as removing, and it stays until the server
        // drops it AND its clock is past the wait.
        var p = PaxPolicy()
        p.blockedApps = [baidu]
        let during = AppsViewInfo(now: 500, apps: [app("com.baidu.BaiduMobile", "Baidu", source: "iphone", pendingUntil: 1_000)])
        let r1 = AppRemoval.reconcile(local: p.pendingAppRemovals, blocked: p.blockedApps, server: during)
        XCTAssertEqual(r1.removeNow, [])
        XCTAssertEqual(r1.pending.map { $0.effectiveAt }, [1_000])
        _ = AppRemoval.apply(r1, to: &p)
        let rows = AppsSync.rows(local: p.blockedApps, pending: p.pendingAppRemovals, server: during, serverHasList: true, macSetUp: false)
        XCTAssertEqual(rows[0].pending?.effectiveAt, 1_000)
        XCTAssertFalse(rows[0].removable)
        // Gone from a list whose clock is earlier than the wait: still blocked (a stale 304 view too).
        XCTAssertEqual(AppRemoval.reconcile(local: p.pendingAppRemovals, blocked: p.blockedApps,
                                            server: AppsViewInfo(now: 999, apps: [])).removeNow, [])
        let after = AppRemoval.reconcile(local: p.pendingAppRemovals, blocked: p.blockedApps, server: AppsViewInfo(now: 1_000, apps: []))
        XCTAssertEqual(after.removeNow, ["com.baidu.BaiduMobile"])
    }

    func testScreenTimeAskedOnceOnlyOnAMacSetUp() {
        XCTAssertTrue(AppsAccess.shouldAskScreenTime(macSetUp: true, alreadyAsked: false, approved: false))
        XCTAssertFalse(AppsAccess.shouldAskScreenTime(macSetUp: true, alreadyAsked: true, approved: false))   // never again
        XCTAssertFalse(AppsAccess.shouldAskScreenTime(macSetUp: true, alreadyAsked: false, approved: true))
        XCTAssertFalse(AppsAccess.shouldAskScreenTime(macSetUp: false, alreadyAsked: false, approved: false))
        // Remembered with the policy; older data reads as not asked.
        var p = PaxPolicy()
        p.macSetUp = true
        p.phoneAppsAuthAsked = true
        XCTAssertTrue(PaxPolicy.decode(try? JSONEncoder().encode(p)).phoneAppsAuthAsked)
        XCTAssertFalse(PaxPolicy.decode(Data(#"{"macSetUp": true}"#.utf8)).phoneAppsAuthAsked)
    }

    func testPhoneLayerHasOnlyThePhonesOwnApps() {
        var p = PaxPolicy()
        p.macSetUp = true
        p.blockedApps = [baidu, BlockedApp(bundleID: "org.paxpeace.pax", name: "Pax"),
                         BlockedApp(bundleID: "com.8bit.bitwarden", name: "Bitwarden"), baidu]
        let ids = AppBlockRules.phoneLayerBundleIDs(p)
        XCTAssertEqual(ids, ["com.baidu.BaiduMobile"])
        XCTAssertTrue(Pax.bypassAppBundleIDs.allSatisfy { !ids.contains($0) })    // the Mac's profile has those
        XCTAssertTrue(AppBlockRules.isProtected("com.apple.mobilesafari"))
        XCTAssertFalse(AppBlockRules.isProtected("com.baidu.BaiduMobile"))
    }

    func testDecodesTheOneListAndOlderAnswers() throws {
        let json = #"{"now": 1700000000, "apps_version": 7, "apps": [{"bundle_id": "com.burbn.instagram", "name": "Instagram", "added_at": 1699990000, "source": "mac", "device_id": "dev-1", "pending_removal": null}, {"bundle_id": "com.baidu.BaiduMobile", "name": "Baidu", "source": "iphone", "pending_removal": {"request_id": "r9", "action": "unblock_app", "domain": "com.baidu.BaiduMobile", "status": "pending", "effective_at": 1700600000, "seconds_remaining": 600000}}]}"#
        let v = try JSONDecoder().decode(AppsViewInfo.self, from: Data(json.utf8))
        XCTAssertEqual(v.apps_version, 7)
        XCTAssertEqual(v.apps[0].source, "mac")
        XCTAssertEqual(v.apps[0].device_id, "dev-1")
        XCTAssertEqual(AppsSync.serverPending(v.apps[1])?.effectiveAt, 1_700_600_000)
        let old = try JSONDecoder().decode(AppsViewInfo.self, from: Data(#"{"now": 5, "apps": [{"bundle_id": "com.kik.chat"}]}"#.utf8))
        XCTAssertNil(old.apps_version)
        XCTAssertNil(old.apps[0].source)
    }
}

// MARK: - cache, ETag, background refresh, launch path

private final class FakeFetcher: AppsFetching {
    var answers: [Result<AppsFetch, Error>]
    private(set) var etags: [String?] = []
    init(_ answers: [Result<AppsFetch, Error>]) { self.answers = answers }
    func fetchApps(etag: String?) async throws -> AppsFetch {
        etags.append(etag)
        guard !answers.isEmpty else { throw URLError(.notConnectedToInternet) }
        return try answers.removeFirst().get()
    }
}

/// Holds every request until the test lets it go: the network "never answers" meanwhile.
private final class GateFetcher: AppsFetching {
    private let lock = NSLock()
    private var waiting: [CheckedContinuation<Void, Never>] = []
    private var _calls = 0
    var calls: Int { lock.lock(); defer { lock.unlock() }; return _calls }
    let answer: AppsFetch
    init(_ answer: AppsFetch) { self.answer = answer }
    func fetchApps(etag: String?) async throws -> AppsFetch {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            lock.lock(); _calls += 1; waiting.append(c); lock.unlock()
        }
        return answer
    }
    func release() {
        lock.lock(); let w = waiting; waiting = []; lock.unlock()
        w.forEach { $0.resume() }
    }
}

final class AppsRefreshTests: XCTestCase {
    private func store() -> AppsCacheStore {
        AppsCacheStore(defaults: UserDefaults(suiteName: "pax.tests.\(UUID().uuidString)")!)
    }
    private let v1 = AppsViewInfo(now: 100, apps: [BlockedAppInfo(bundle_id: "com.kik.chat", name: "Kik", source: "iphone")], apps_version: 1)

    func testETagIsSentAnd304KeepsTheCachedList() async {
        let s = store()
        let f = FakeFetcher([.success(.list(v1, etag: "\"v1\"")), .success(.notModified)])
        let r = AppsRefresher(fetcher: f, store: s)
        let first = await r.refresh()
        XCTAssertEqual(first, .list(v1, fresh: true))
        XCTAssertEqual(s.load().etag, "\"v1\"")
        XCTAssertEqual(s.load().hasList, true)
        let second = await r.refresh()
        XCTAssertEqual(second, .list(v1, fresh: false))          // 304: the cache, not fresh
        XCTAssertEqual(f.etags, [nil, "\"v1\""])
    }

    func test404ClearsTheListAndSaysSo() async {
        let s = store()
        s.save({ var c = AppsCache(); c.hasList = true; c.view = v1; c.etag = "\"v1\""; return c }())
        let f = FakeFetcher([.success(.noList)])
        let result = await AppsRefresher(fetcher: f, store: s).refresh()
        XCTAssertEqual(result, .noList)
        XCTAssertEqual(s.load().hasList, false)
        XCTAssertNil(s.load().view)
        XCTAssertNil(s.load().etag)
    }

    func testErrorsKeepTheCacheAnd401SignsOut() async {
        let s = store()
        s.save({ var c = AppsCache(); c.hasList = true; c.view = v1; c.etag = "\"v1\""; return c }())
        let offline = await AppsRefresher(fetcher: FakeFetcher([.failure(URLError(.timedOut))]), store: s).refresh()
        XCTAssertEqual(offline, .failed)
        XCTAssertEqual(s.load().view, v1)
        let out = await AppsRefresher(fetcher: FakeFetcher([.failure(AppsFetchError.signedOut)]), store: s).refresh()
        XCTAssertEqual(out, .signedOut)
        XCTAssertEqual(s.load().view, v1)
    }

    func testNoETagWithoutACachedList() async {
        let s = store()
        s.save({ var c = AppsCache(); c.etag = "\"orphan\""; return c }())
        let f = FakeFetcher([.success(.notModified)])
        _ = await AppsRefresher(fetcher: f, store: s).refresh()
        XCTAssertEqual(f.etags, [nil])
    }

    func testOverlappingRefreshesShareOneRequest() async throws {
        let s = store()
        let g = GateFetcher(.list(v1, etag: nil))
        let r = AppsRefresher(fetcher: g, store: s)
        async let a = r.refresh()
        async let b = r.refresh()
        for _ in 0..<200 where g.calls == 0 { try await Task.sleep(nanoseconds: 5_000_000) }
        try await Task.sleep(nanoseconds: 50_000_000)
        g.release()
        let (ra, rb) = await (a, b)
        XCTAssertEqual(ra, rb)
        XCTAssertEqual(g.calls, 1)
    }

    func testCacheIsTolerant() {
        let s = store()
        XCTAssertEqual(s.load(), AppsCache())                                  // nothing saved
        s.defaults.set(Data("not json".utf8), forKey: AppsCacheStore.key)
        XCTAssertEqual(s.load(), AppsCache())                                  // unreadable: empty
        var c = AppsCache()
        c.hasList = true
        c.view = v1
        c.refused = ["com.example.x"]
        c.backfilled = true
        s.save(c)
        XCTAssertEqual(s.load(), c)
    }

    /// The launch path never waits for the network: the cached list is read synchronously while a
    /// refresh is still waiting on the server, and the cache read is not async at all.
    func testLaunchPathDoesNotAwaitTheNetwork() async throws {
        let s = store()
        s.save({ var c = AppsCache(); c.hasList = true; c.view = v1; return c }())
        // Compile-time: the cache read is a plain synchronous function.
        let read: (AppsCacheStore) -> AppsCache = { $0.load() }
        let g = GateFetcher(.list(AppsViewInfo(now: 200, apps: []), etag: nil))
        let r = AppsRefresher(fetcher: g, store: s)
        let background = Task { await r.refresh() }
        for _ in 0..<200 where g.calls == 0 { try await Task.sleep(nanoseconds: 5_000_000) }
        XCTAssertEqual(g.calls, 1)                              // the request is out and hasn't answered
        XCTAssertEqual(read(s).view, v1)                        // the list shows anyway
        let rows = AppsSync.rows(local: [], pending: [], server: read(s).view, serverHasList: read(s).hasList == true, macSetUp: false)
        XCTAssertEqual(rows.map { $0.bundleID }, ["com.kik.chat"])
        g.release()
        _ = await background.value
    }

    /// The same promise checked in the app's own code: AppModel.init and onActive start the
    /// refresh without awaiting it, and the cache is only read on first use, not in init.
    func testAppModelLaunchStartsTheRefreshWithoutAwaitingIt() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("App/AppModel.swift")
        guard let src = try? String(contentsOf: url, encoding: .utf8) else {
            throw XCTSkip("App sources not readable from the test bundle here")
        }
        func body(after marker: String) -> String {
            guard let r = src.range(of: marker) else { return "" }
            let rest = src[r.upperBound...]
            let end = rest.range(of: "\n    }\n")?.lowerBound ?? rest.endIndex
            return String(rest[..<end])
        }
        let initBody = body(after: "    init() {")
        XCTAssertFalse(initBody.isEmpty)
        XCTAssertFalse(initBody.contains("await"))
        for call in ["appsStore", "appsRefresher", "refreshApps", "startAppsRefresh", "loadAppsCache", "fetchApps", "URLSession"] {
            XCTAssertFalse(initBody.contains(call), "\(call) in init")
        }
        let onActive = body(after: "    func onActive() async {")
        XCTAssertTrue(onActive.contains("startAppsRefresh()"))
        XCTAssertFalse(onActive.contains("await refreshApps"))
        XCTAssertFalse(onActive.contains("await self.refreshApps"))
        XCTAssertTrue(src.contains("    func startAppsRefresh() {"), "startAppsRefresh is not async")
        XCTAssertFalse(src.contains("func startAppsRefresh() async"))
    }
}
