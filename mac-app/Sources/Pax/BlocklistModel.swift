// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import SwiftUI
import PaxCore

/// State for the "Blocked sites" screen. Adds are instant; removals start the
/// wait (v0.8.9: one rule everywhere, by default the user's own wait, partner told
/// first) and can be cancelled until it ends.
@MainActor
final class BlocklistModel: ObservableObject {
    @Published var view: BlocklistView?
    @Published var newSite = ""
    @Published var busy = false
    @Published var errorMessage: String?
    /// v0.7.0: a classified failure with its support code.
    @Published var failure: PaxError?
    private var lastAction: (() -> Void)?
    @Published var notice: String?
    /// v0.5 built-in categories (remote desktop on/off with the wait).
    @Published var categories: CategoriesView?
    /// Local time when `view` was fetched; with `view.now` this corrects countdowns
    /// for a Mac clock that disagrees with the server.
    private(set) var fetchedAt = Date()

    /// v0.8.0: the server (iPhones, or a Mac on the server path) or pax-guard
    /// (a Mac on local escrow) keeps the list; both answer the same way.
    private let client: @MainActor () -> BlocklistBackend?

    init(client: @escaping @MainActor () -> BlocklistBackend?) {
        self.client = client
    }

    var signedIn: Bool { client() != nil }
    private var server: EscrowClient? {
        guard let e = client() as? EscrowClient, e.token != nil else { return nil }
        return e
    }
    var blocked: [BlockedSite] { view?.blocked ?? [] }
    var allowed: [AllowedSite] { view?.allowed ?? [] }
    var pendingExceptions: [BlocklistRequest] { view?.pending.filter { $0.action == "allow" } ?? [] }
    var pendingRemovals: [BlocklistRequest] { view?.pending.filter { $0.action == "unblock" } ?? [] }
    /// v0.8.8: say honestly where a site added here is blocked. This Mac on local escrow
    /// keeps its own list; the server's list reaches iPhones/iPads set up with Pax's filter
    /// (0.8.8 and later) within seconds, but not phones set up with CleanBrowsing directly.
    var scopeText: String {
        if client() is EscrowClient {
            return "Sites you add here are blocked within seconds on every iPhone and iPad set up with Pax's "
                + "filter (Pax 0.8.8 or later). Phones set up earlier only block the sites chosen during set-up."
        }
        // v0.8.9: this Mac's list syncs with the account (on by default, Home switch).
        return "Sites you add here are blocked on this Mac at once, and on your iPhone and iPad within seconds "
            + "while \"Sync blocked sites across devices\" is on. Unblocking takes your turn-off wait, and your partner is told first."
    }
    /// v0.8.16: plain words ("3 days"), not a clock ("72h 00m 00s").
    var delayText: String { TurnOffWait.duration(seconds: view?.limits.delay_seconds ?? 72 * 3600) }
    var normalisedNewSite: String? { DomainInput.normalise(newSite) }

    func remaining(_ r: BlocklistRequest, at now: Date) -> Int {
        guard let view else { return r.seconds_remaining }
        return Countdown.remaining(effectiveAt: r.effective_at, serverNow: view.now, fetchedAt: fetchedAt, now: now)
    }

    private func perform(_ work: @escaping (BlocklistBackend) async throws -> BlocklistView?) {
        guard let c = client() else {
            errorMessage = "Protect a device first: your list belongs to your Pax account."
            return
        }
        busy = true
        errorMessage = nil
        failure = nil
        lastAction = { [weak self] in self?.perform(work) }
        Task {
            do {
                if let v = try await work(c) { apply(v) } else { apply(try await c.blocklist()) }
            } catch {
                failure = PaxErrorClassifier.classify(error)
            }
            busy = false
        }
    }

    private func apply(_ v: BlocklistView) {
        view = v
        fetchedAt = Date()
    }

    func refresh() {
        perform { _ in nil }
        refreshCategories()
    }

    // MARK: v0.5 categories

    var remoteDesktop: PaxCategory? { categories?.remoteDesktop }

    func refreshCategories() {
        guard let c = server else { return }       // categories are a server feature
        Task {
            do { categories = try await c.categories() } catch { /* older server: no section */ }
        }
    }

    /// On: immediate. Off: starts the wait; the pending request shows with Cancel.
    func setRemoteDesktop(blocked: Bool) {
        guard let c = server else { return }
        busy = true
        errorMessage = nil
        Task {
            do {
                let v = try await c.setCategory("remote_desktop", enabled: blocked)
                categories = v
                if let r = v.request {
                    notice = "Remote desktop stays blocked for \(Countdown.string(seconds: r.seconds_remaining)). "
                        + "You can cancel any time before then."
                } else if blocked {
                    notice = "Remote desktop is blocked again on all your devices."
                }
            } catch {
                failure = PaxErrorClassifier.classify(error)
            }
            busy = false
        }
    }

    func retry() {
        let action = lastAction
        failure = nil
        action?()
    }

    func cancelCategoryRequest(_ request: BlocklistRequest) {
        cancel(request)
        refreshCategories()
    }

    func remainingCategory(_ r: BlocklistRequest, at now: Date) -> Int {
        guard let v = categories else { return r.seconds_remaining }
        return Countdown.remaining(effectiveAt: r.effective_at, serverNow: v.now, fetchedAt: fetchedAt, now: now)
    }

    func add() {
        guard let site = normalisedNewSite else {
            errorMessage = "Enter a website such as example.com."
            return
        }
        perform { [weak self] c in
            let r = try await c.blockSite(site)
            await MainActor.run {
                self?.newSite = ""
                self?.notice = r.created ? "\(r.domain) is blocked on all your devices." : "\(r.domain) was already blocked."
            }
            return r.list
        }
    }

    // MARK: v0.7.0 Import list

    /// Room left on the account's list (2,000 by default).
    var importCap: Int {
        guard let v = view else { return BulkSiteImport.maxPerImport }
        return max(0, v.limits.max_blocked - v.blocked.count)
    }
    var blockedDomains: Set<String> { Set(blocked.map(\.domain)) }
    @Published var importDone = 0
    @Published var importTotal = 0

    /// Adds every site at once, one request each (adds are instant, like a single
    /// add). Stops at the first failure, e.g. a full list, and says what happened.
    func importSites(_ sites: [String], skipped: Int) {
        guard let c = client() else {
            errorMessage = "Protect a device first: your list belongs to your Pax account."
            return
        }
        busy = true
        errorMessage = nil
        failure = nil
        notice = nil
        importDone = 0
        importTotal = sites.count
        lastAction = { [weak self] in self?.importSites(sites, skipped: skipped) }
        Task {
            var added = 0
            do {
                for site in sites {
                    let r = try await c.blockSite(site)
                    if r.created { added += 1 }
                    importDone += 1
                    if importDone == sites.count || importDone % 25 == 0 { apply(r.list) }
                }
                notice = "Added \(added) site\(added == 1 ? "" : "s"). They're blocked on all your devices."
                    + (skipped > 0 ? " \(skipped) line\(skipped == 1 ? " wasn't a website and was" : "s weren't websites and were") skipped." : "")
            } catch {
                failure = PaxErrorClassifier.classify(error)
                notice = added > 0 ? "Added \(added) of \(sites.count) before stopping." : nil
                if let v = try? await c.blocklist() { apply(v) }
            }
            importTotal = 0
            busy = false
        }
    }

    func requestRemoval(_ site: BlockedSite) {
        perform { [weak self] c in
            let r = try await c.requestUnblock(site.domain)
            await MainActor.run {
                self?.notice = "\(site.display_domain) stays blocked for \(Countdown.string(seconds: r.request.seconds_remaining)). You can cancel any time before then."
            }
            return r.list
        }
    }

    func requestException(_ raw: String) {
        guard let site = DomainInput.normalise(raw) else {
            errorMessage = "Enter a website such as example.com."
            return
        }
        guard let c = client() else {
            errorMessage = "Protect a device first: your list belongs to your Pax account."
            return
        }
        busy = true
        errorMessage = nil
        failure = nil
        notice = nil
        lastAction = { [weak self] in self?.requestException(raw) }
        Task {
            do {
                let r = try await c.requestAllow(site)
                apply(r.list)
                notice = "\(site) will be allowed in \(Countdown.string(seconds: r.request.seconds_remaining)). "
                    + "You can cancel any time before then."
            } catch {
                let e = PaxErrorClassifier.classify(error)
                if e.isRestrictedSite {
                    // v0.8.1: refused straight away. No countdown, no retry: just the sentence.
                    errorMessage = e.info.message
                    lastAction = nil
                } else {
                    failure = e
                }
            }
            busy = false
        }
    }

    func removeException(_ site: AllowedSite) {
        perform { c in try await c.removeAllow(site.domain) }
    }

    func cancel(_ request: BlocklistRequest) {
        perform { [weak self] c in
            let v = try await c.cancelBlocklistRequest(request.request_id)
            await MainActor.run { self?.notice = "Cancelled. Nothing changes." }
            return v
        }
    }
}
