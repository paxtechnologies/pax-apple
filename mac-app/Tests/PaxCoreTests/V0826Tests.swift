// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.26: an iPhone's or iPad's Home card follows the server, not the set-up record.
final class V0826Tests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func map(released: Bool = false, removal: String? = nil, left: Int = 0,
                     trial: EscrowClient.DeviceStatus.TrialState? = nil, checkingIn: Bool? = nil,
                     lastSeen: String? = nil, usesPaxFilter: Bool? = true) -> PhoneStatus.State {
        PhoneStatus.state(released: released, removalStatus: removal, secondsLeft: left, trial: trial,
                          checkingIn: checkingIn, lastSeen: lastSeen, usesPaxFilter: usesPaxFilter, now: now)
    }

    func testStatusMapping() {
        XCTAssertEqual(map(), .protected)
        XCTAssertEqual(map(checkingIn: true), .protected)
        XCTAssertEqual(map(checkingIn: nil), .protected)                 // unknown is never "quiet"
        let trial = EscrowClient.DeviceStatus.TrialState(active: true, until: 1_800_003_600)
        XCTAssertEqual(map(trial: trial), .trial(until: 1_800_003_600))
        XCTAssertEqual(map(removal: "pending", left: 600), .turningOff(secondsLeft: 600, notifying: false))
        XCTAssertEqual(map(removal: "notifying", left: 600), .turningOff(secondsLeft: 600, notifying: true))
        // Turned off: released by any route, or a revealed request.
        XCTAssertEqual(map(released: true), .turnedOff)
        XCTAssertEqual(map(removal: "revealed"), .turnedOff)
        XCTAssertEqual(map(released: true, removal: "pending", left: 30), .turnedOff)
        XCTAssertEqual(map(released: true, checkingIn: false), .turnedOff)
        // Not checking in, only for a phone on Pax's own filter.
        XCTAssertEqual(map(checkingIn: false, lastSeen: "2026-10-15"), .notCheckingIn(lastSeen: "2026-10-15"))
        XCTAssertEqual(map(checkingIn: false, usesPaxFilter: nil), .notCheckingIn(lastSeen: nil))
        XCTAssertEqual(map(checkingIn: false, usesPaxFilter: false), .protected)
        // A running turn-off wait wins over quiet; quiet wins over the trial line.
        XCTAssertEqual(map(removal: "pending", left: 5, checkingIn: false), .turningOff(secondsLeft: 5, notifying: false))
        XCTAssertEqual(map(trial: trial, checkingIn: false), .notCheckingIn(lastSeen: nil))
        // Lapsed / cancelled requests aren't returned as active: protected.
        XCTAssertEqual(map(removal: "cancelled"), .protected)
    }

    func testDecodesServerFieldsAndOlderServers() throws {
        let base = #"{"device_id":"d1","name":"Ruben's iPhone","platform":"ios","installed_at":1,"grace_until":2,"#
            + #""in_grace_period":false,"removal_request":null"#
        // 0.8.26: released, last_seen, checking_in.
        let a = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data((base
            + #","released_at":5,"released":true,"last_seen":null,"checking_in":null}"#).utf8))
        XCTAssertEqual(PhoneStatus.state(a, secondsLeft: 0, now: now), .turnedOff)
        let b = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data((base
            + #","released_at":null,"released":false,"last_seen":"2026-10-15","checking_in":false}"#).utf8))
        XCTAssertEqual(PhoneStatus.state(b, secondsLeft: 0, now: now), .notCheckingIn(lastSeen: "2026-10-15"))
        // An older server: no new keys; released_at alone still means turned off (the 0.8.25 bug).
        let c = try JSONDecoder().decode(EscrowClient.DeviceStatus.self,
                                         from: Data((base + #","released_at":5}"#).utf8))
        XCTAssertNil(c.released)
        XCTAssertNil(c.checking_in)
        XCTAssertTrue(PhoneStatus.isReleased(c))
        XCTAssertEqual(PhoneStatus.state(c, secondsLeft: 0, now: now), .turnedOff)
        let d = try JSONDecoder().decode(EscrowClient.DeviceStatus.self,
                                         from: Data((base + #","released_at":null}"#).utf8))
        XCTAssertEqual(PhoneStatus.state(d, secondsLeft: 0, now: now), .protected)
    }

    func testWordsAreCalm() {
        XCTAssertEqual(PhoneStatus.headline(.turnedOff), "Turned off")
        XCTAssertEqual(PhoneStatus.headline(.notCheckingIn(lastSeen: nil)), "Not checking in")
        XCTAssertEqual(PhoneStatus.headline(.protected), "Protected")
        XCTAssertEqual(PhoneStatus.offLine(name: "Ruben's iPhone"), "Pax is off on Ruben's iPhone.")
        XCTAssertEqual(PhoneStatus.quietLine, "It may have been reset or removed.")
        XCTAssertEqual(PhoneStatus.removeMessageOff, "This removes it from the list on this Mac.")
        XCTAssertEqual(PhoneStatus.removeMessageProtected, "This only tidies the list on this Mac. Pax stays on the device.")
        XCTAssertEqual(PhoneStatus.sidebarLabel(.turningOff(secondsLeft: 9, notifying: false)), "Turn-off wait")
        let all = [PhoneStatus.offHint(isIPad: false), PhoneStatus.removeMessageQuiet, PhoneStatus.notFoundLine,
                   PhoneStatus.headline(.turnedOff), PhoneStatus.quietLine]
        for s in all { XCTAssertFalse(s.lowercased().contains("unlock"), s) }
        XCTAssertEqual(PhoneStatus.lastSeenLine("2026-10-15", locale: Locale(identifier: "en_GB")), "Last seen Thu 15 Oct")
        XCTAssertNil(PhoneStatus.lastSeenLine("junk"))
        XCTAssertNil(PhoneStatus.lastSeenLine(nil))
    }

    func testFreshnessNeverLooksFreshWhenStale() {
        XCTAssertNil(PhoneStatus.freshness(lastChecked: nil, failed: false, now: now))
        XCTAssertEqual(PhoneStatus.freshness(lastChecked: nil, failed: true, now: now),
                       "Couldn't reach Pax to check just now.")
        XCTAssertEqual(PhoneStatus.freshness(lastChecked: now.addingTimeInterval(-5), failed: false, now: now),
                       "Checked just now")
        XCTAssertEqual(PhoneStatus.freshness(lastChecked: now.addingTimeInterval(-12 * 60), failed: false, now: now),
                       "Last checked 12 min ago")
        XCTAssertEqual(PhoneStatus.freshness(lastChecked: now.addingTimeInterval(-3 * 3600), failed: true, now: now),
                       "Last checked 3 h ago · couldn't reach Pax just now")
        XCTAssertEqual(PhoneStatus.freshness(lastChecked: now.addingTimeInterval(-5), failed: true, now: now),
                       "Last checked just now · couldn't reach Pax just now")
        XCTAssertEqual(PhoneStatus.freshness(lastChecked: now.addingTimeInterval(-2 * 86_400), failed: false, now: now),
                       "Last checked 2 days ago")
    }

    func testRefreshButtonIsRateLimited() {
        XCTAssertTrue(PhoneStatus.canRefresh(lastTap: nil, now: now))
        XCTAssertFalse(PhoneStatus.canRefresh(lastTap: now.addingTimeInterval(-3), now: now))
        XCTAssertFalse(PhoneStatus.canRefresh(lastTap: now.addingTimeInterval(-9.9), now: now))
        XCTAssertTrue(PhoneStatus.canRefresh(lastTap: now.addingTimeInterval(-10), now: now))
        XCTAssertTrue(PhoneStatus.canRefresh(lastTap: now.addingTimeInterval(60), now: now))   // clock moved back
    }
}
