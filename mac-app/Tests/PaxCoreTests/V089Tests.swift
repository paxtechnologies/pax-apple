// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.9: blocked sites sync across devices (on by default, one switch), linking
/// this Mac's pax-guard to the account with no extra steps, one wait minimum (24 h)
/// and a wait picker that only offers what the path in use accepts.
final class V089Tests: XCTestCase {

    // MARK: Wait limits

    func testStandardLimitsAreOneDayToAYear() {
        XCTAssertEqual(WaitLimits.standard.dayRange, 1...365)
        XCTAssertEqual(WaitLimits.standard.choices([1, 3, 7]), [1, 3, 7])
        XCTAssertTrue(WaitLimits.standard.allows(days: 1))
        XCTAssertFalse(WaitLimits.standard.allows(days: 366))
    }

    func testOlderServerHidesTheOneDayChoice() {
        // The 0.8.8 bug: the app offered 24 hours and the server refused it (PAX-ESCROW-002).
        let old = WaitLimits.legacyServer
        XCTAssertEqual(old.dayRange, 3...365)
        XCTAssertEqual(old.choices([1, 3, 7]), [3, 7])
        XCTAssertEqual(old.clamp(days: 1), 3)
        XCTAssertEqual(old.clamp(days: 400), 365)
    }

    func testLimitsFromHealth() {
        let h: [String: Any] = ["ok": true, "wait_limits": ["min_wait_seconds": 86_400, "max_wait_seconds": 31_536_000]]
        XCTAssertEqual(WaitLimits.fromHealth(h), .standard)
        XCTAssertEqual(WaitLimits.fromHealth(["ok": true]), .legacyServer)
        XCTAssertEqual(WaitLimits.fromHealth(nil), .legacyServer)
        let odd: [String: Any] = ["wait_limits": ["min_wait_seconds": 7_200, "max_wait_seconds": 10 * 86_400]]
        XCTAssertEqual(WaitLimits.fromHealth(odd).dayRange, 1...10)
    }

    func testEscrowCodeTwoNoLongerMentionsThreeDays() {
        let info = PaxErrorCatalog.info("PAX-ESCROW-002")
        XCTAssertFalse(info.cause.contains("production minimum is 3 days"))
        XCTAssertTrue(info.action.contains("24 hours"))
    }

    // MARK: Sync

    let on = #"{"ok": true, "sync": {"enabled": true, "linked": false, "account_email": null, "last_ok": null, "queued": 0, "pending": 0, "delay_seconds": null, "interval": 15}}"#

    func testSyncStatusAndSwitch() async throws {
        let t = FakeGuardTransport([
            "sync.get": on,
            "sync.set": #"{"ok": true, "sync": {"enabled": false, "linked": true, "queued": 0, "pending": 0}}"#,
        ])
        let g = GuardClient(transport: t)
        let s = try await g.syncStatus()
        XCTAssertTrue(s.enabled)
        XCTAssertFalse(s.linked)
        let off = try await g.setSync(false)
        XCTAssertFalse(off.enabled)
        XCTAssertEqual(t.sent.last?["enabled"] as? Bool, false)
    }

    func testLinkSendsTokenOnlyOverTheSocket() async throws {
        let t = FakeGuardTransport([
            "sync.link": #"{"ok": true, "sync": {"enabled": true, "linked": true, "account_email": "me@example.com"}}"#,
        ])
        let s = try await GuardClient(transport: t).linkSync(serverURL: "https://api.paxpeace.com/",
                                                             token: "pxs_abc", accountEmail: "me@example.com")
        XCTAssertTrue(s.linked)
        XCTAssertEqual(t.sent.last?["token"] as? String, "pxs_abc")
        XCTAssertEqual(t.sent.last?["server_url"] as? String, "https://api.paxpeace.com/")
    }

    func testWhenToLink() {
        let unlinked = GuardClient.SyncStatus(enabled: true, linked: false)
        let linked = GuardClient.SyncStatus(enabled: true, linked: true)
        let off = GuardClient.SyncStatus(enabled: false, linked: false)
        XCTAssertTrue(ListSyncLinker.shouldLink(localKey: true, protected: true, hasAccount: true, status: unlinked))
        XCTAssertFalse(ListSyncLinker.shouldLink(localKey: true, protected: true, hasAccount: true, status: linked))
        XCTAssertFalse(ListSyncLinker.shouldLink(localKey: true, protected: true, hasAccount: true, status: off))
        XCTAssertFalse(ListSyncLinker.shouldLink(localKey: true, protected: true, hasAccount: false, status: unlinked))
        XCTAssertFalse(ListSyncLinker.shouldLink(localKey: false, protected: true, hasAccount: true, status: unlinked))
        XCTAssertFalse(ListSyncLinker.shouldLink(localKey: true, protected: false, hasAccount: true, status: unlinked))
        // An older pax-guard (no sync.get answer) is never linked.
        XCTAssertFalse(ListSyncLinker.shouldLink(localKey: true, protected: true, hasAccount: true, status: nil))
    }

    func testCalmWording() {
        XCTAssertTrue(ListSyncLinker.detail(GuardClient.SyncStatus(enabled: false, linked: true)).contains("Nothing was unblocked"))
        XCTAssertTrue(ListSyncLinker.detail(GuardClient.SyncStatus(enabled: true, linked: true)).contains("within seconds"))
    }

    func testOfflineRemovalCodeIsCalm() {
        XCTAssertEqual(PaxErrorCatalog.info("PAX-DNS-013").message,
                       "Pax couldn't reach your Pax account, so nothing changed.")
    }

    func testBlocklistViewWithSyncStillDecodes() throws {
        let json = #"{"now": 10, "blocked": [{"domain": "a.example", "display_domain": "a.example", "added_at": 1, "pending_removal": {"request_id": "r1", "action": "unblock", "domain": "a.example", "display_domain": "a.example", "status": "pending", "created_at": 1, "effective_at": 86401, "seconds_remaining": 86391}}], "allowed": [], "pending": [], "limits": {"max_blocked": 2000, "max_allowed": 200, "delay_seconds": 86400}, "sync": {"enabled": true, "linked": true}}"#
        let v = try JSONDecoder().decode(BlocklistView.self, from: Data(json.utf8))
        XCTAssertEqual(v.blocked.first?.pending_removal?.request_id, "r1")
        XCTAssertEqual(v.limits.delay_seconds, 86_400)
    }
}
