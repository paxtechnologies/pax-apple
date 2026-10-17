// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.16: plain words for the turn-off wait.
final class V0816Tests: XCTestCase {
    func testSetupWordingSaysWhatTheWaitIsFor() {
        XCTAssertEqual(TurnOffWait.setupTitle, "How long should turning Pax off take?")
        XCTAssertTrue(TurnOffWait.setupHelp.contains("you'll ask first, then wait this long before it turns off"))
        XCTAssertTrue(TurnOffWait.setupHelp.contains("You can cancel any time during the wait."))
        XCTAssertTrue(TurnOffWait.setupHelp.contains("outlast a bad night"))
        XCTAssertEqual(TurnOffWait.firstHour, "For your first hour, you can change your mind instantly.")
        XCTAssertEqual(TurnOffWait.label, "Turn-off wait")
    }

    func testChoiceTitles() {
        XCTAssertEqual(TurnOffWait.choiceTitle(days: 1), "1 day")
        XCTAssertEqual(TurnOffWait.choiceTitle(days: 3), "3 days")
        XCTAssertEqual(TurnOffWait.choiceTitle(days: 7), "7 days")
        XCTAssertEqual(TurnOffWait.choiceTitle(days: 30), "30 days")
    }

    func testDurations() {
        XCTAssertEqual(TurnOffWait.duration(seconds: 86_400), "24 hours")
        XCTAssertEqual(TurnOffWait.duration(seconds: 36 * 3600), "36 hours")
        XCTAssertEqual(TurnOffWait.duration(seconds: 3 * 86_400), "3 days")
        XCTAssertEqual(TurnOffWait.duration(seconds: 7 * 86_400), "7 days")
        XCTAssertEqual(TurnOffWait.duration(seconds: 60 * 3600), "60 hours")
        XCTAssertEqual(TurnOffWait.duration(seconds: 3600), "1 hour")
        XCTAssertEqual(TurnOffWait.duration(seconds: 90), "1 minute")
        XCTAssertEqual(TurnOffWait.duration(days: 1), "24 hours")
        XCTAssertEqual(TurnOffWait.duration(days: 7), "7 days")
        XCTAssertEqual(TurnOffWait.row(seconds: 7 * 86_400), "Turn-off wait: 7 days")
    }

    func testCountdown() {
        XCTAssertEqual(TurnOffWait.countdown(seconds: 2 * 86_400 + 14 * 3600 + 59), "2 days 14 h")
        XCTAssertEqual(TurnOffWait.countdown(seconds: 86_400 + 3600), "1 day 1 h")
        XCTAssertEqual(TurnOffWait.countdown(seconds: 5 * 3600 + 3 * 60 + 7), "5 h 03 min")
        XCTAssertEqual(TurnOffWait.countdown(seconds: 12 * 60 + 9), "12 min 09 s")
        XCTAssertEqual(TurnOffWait.countdown(seconds: -4), "0 min 00 s")
        XCTAssertEqual(TurnOffWait.turnsOffIn(seconds: 2 * 86_400 + 14 * 3600), "Pax turns off in 2 days 14 h")
        XCTAssertEqual(TurnOffWait.turnsOffIn(seconds: 0), "Your turn-off wait is over.")
    }

    func testWordingIsCalm() {
        let all = [TurnOffWait.setupTitle, TurnOffWait.setupHelp, TurnOffWait.setupAlsoApplies, TurnOffWait.firstHour,
                   VerifiedSupportRelease.detail(allowed: false, pendingOnAt: 1_800_000_000),
                   VerifiedSupportRelease.detail(allowed: false, pendingOnAt: nil, tellingPartner: true)]
        for s in all { XCTAssertFalse(s.contains("!"), s) }
        XCTAssertTrue(VerifiedSupportRelease.detail(allowed: false, pendingOnAt: 1_800_000_000).contains("turn-off wait"))
    }

    func testDeviceStatusReadsTheWait() throws {
        let json = #"{"device_id": "d1", "name": "Mac", "platform": "mac", "installed_at": 1, "grace_until": 2,"#
            + #" "in_grace_period": false, "released_at": null, "removal_request": null, "wait_seconds": 604800}"#
        let s = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(json.utf8))
        XCTAssertEqual(s.wait_seconds, 604_800)
        let old = #"{"device_id": "d1", "name": "Mac", "platform": "mac", "installed_at": 1, "grace_until": 2,"#
            + #" "in_grace_period": false, "released_at": null, "removal_request": null}"#
        XCTAssertNil(try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(old.utf8)).wait_seconds)
    }
}
