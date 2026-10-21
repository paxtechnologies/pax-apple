// SPDX-License-Identifier: GPL-3.0-only
// 1.2 one-tap set-up: the "Make Pax stronger" list, changing the wait, releasing with a
// replaced escrow or a second (passcode) record. Fail closed throughout.
import XCTest

final class OneTapTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func testOneTapIsThreeScreens() {
        // Welcome, Apple's Screen Time sheet (while "Turning Pax on" shows), Done.
        XCTAssertEqual(SetupRules.path(child: false, privateAccounts: true).count, 3)
    }

    func testStrongerOrderIsFixed() {
        XCTAssertEqual(StrongerList.order, [.lockScreenTime, .trustedPerson, .encryptedDNS, .appsToClose,
                                            .turnOffWait, .computerSetup])
    }

    func testLockScreenTimeNudgeUntilDone() {
        var p = PaxPolicy()
        p.isActive = true
        XCTAssertTrue(StrongerList.nudge(p))
        XCTAssertFalse(StrongerCard.lockScreenTime.isDone(p, hasApps: false))
        p.passcodeEscrowed = true
        XCTAssertFalse(StrongerList.nudge(p))
        XCTAssertTrue(StrongerCard.lockScreenTime.isDone(p, hasApps: false))
        XCTAssertFalse(StrongerList.nudge(PaxPolicy()))        // not on: no nudge
    }

    func testStrongerProgress() {
        var p = PaxPolicy()
        p.isActive = true
        XCTAssertEqual(StrongerList.progress(p, hasApps: false).done, 0)
        XCTAssertEqual(StrongerList.progress(p, hasApps: false).total, 4)
        p.trustedEmail = "friend@example.com"
        p.dnsInstalled = true
        XCTAssertEqual(StrongerList.progress(p, hasApps: true).done, 3)
        XCTAssertFalse(StrongerCard.turnOffWait.isDone(p, hasApps: true))
        XCTAssertFalse(StrongerCard.computerSetup.isDone(p, hasApps: true))
    }

    func testWaitChange() {
        XCTAssertEqual(WaitChange.of(currentDays: 7, newDays: 7), .same)
        XCTAssertEqual(WaitChange.of(currentDays: 7, newDays: 30), .longerNow)
        XCTAssertEqual(WaitChange.of(currentDays: 7, newDays: 3), .shorterAfterWait)
        XCTAssertEqual(WaitChange.of(currentDays: 3, newDays: 1), .same)         // clamped to 3
        XCTAssertEqual(WaitChange.of(currentDays: 365, newDays: 1000), .same)    // clamped to 365
    }

    func testCombinedPhaseIsTheSlowerOne() {
        let a = TurnOffPhase.waiting(until: t0.addingTimeInterval(100))
        let b = TurnOffPhase.waiting(until: t0.addingTimeInterval(200))
        XCTAssertEqual(TurnOffRules.combine(.none, nil), .none)
        XCTAssertEqual(TurnOffRules.combine(.ready, nil), .ready)
        XCTAssertEqual(TurnOffRules.combine(a, b), b)
        XCTAssertEqual(TurnOffRules.combine(.ready, a), a)
        XCTAssertEqual(TurnOffRules.combine(a, .ready), a)
        XCTAssertEqual(TurnOffRules.combine(.ready, .ready), .ready)
        XCTAssertEqual(TurnOffRules.combine(.ready, .unknown), .unknown)
        XCTAssertEqual(TurnOffRules.combine(.unknown, .none), .unknown)
        // One asked for and one not: never "ready"; asking again covers the missing one.
        XCTAssertEqual(TurnOffRules.combine(.ready, TurnOffPhase.none), TurnOffPhase.none)
        XCTAssertEqual(TurnOffRules.combine(TurnOffPhase.none, a), TurnOffPhase.none)
    }

    func testReleaseAcceptsTheHashWrittenBeforeAReplace() {
        let old = EscrowSecret.make(passcode: nil)
        let new = EscrowSecret.make(passcode: "4831")
        var p = PaxPolicy()
        p.releaseKeyHash = old.releaseKeyHash
        p.pendingReleaseKeyHash = new.releaseKeyHash
        // The server may hold either while a replace is in flight: both release, nothing else does.
        XCTAssertEqual(EscrowSecret.decide(sealed: new.sealed, acceptedHashes: p.acceptedReleaseHashes),
                       .release(passcode: "4831"))
        XCTAssertEqual(EscrowSecret.decide(sealed: old.sealed, acceptedHashes: p.acceptedReleaseHashes),
                       .release(passcode: nil))
        let stranger = EscrowSecret.make(passcode: "4831")
        if case .release = EscrowSecret.decide(sealed: stranger.sealed, acceptedHashes: p.acceptedReleaseHashes) {
            XCTFail("a secret from elsewhere must not release this device")
        }
    }

    func testReleaseWithNoHashesStaysOn() {
        let s = EscrowSecret.make(passcode: nil)
        if case .release = EscrowSecret.decide(sealed: s.sealed, acceptedHashes: []) { XCTFail("released with no hash") }
        if case .release = EscrowSecret.decide(sealed: s.sealed, acceptedHashes: ["", ""]) { XCTFail("released with empty hashes") }
    }

    func testNewPolicyFieldsRoundTripAndOldPoliciesStayOn() throws {
        var p = PaxPolicy()
        p.isActive = true
        p.privateAccount = true
        p.pendingReleaseKeyHash = "pending"
        p.passcodeDeviceID = "dev2"
        p.passcodeKeyHash = "hash2"
        p.displayName = "Sam"
        XCTAssertEqual(PaxPolicy.decode(try JSONEncoder().encode(p)), p)
        // A 1.1 policy has none of these keys: still on, nothing invented.
        let old = PaxPolicy.decode(Data(#"{"isActive":true,"setUpFinished":true,"deviceID":"d","releaseKeyHash":"h"}"#.utf8))
        XCTAssertTrue(old.isActive)
        XCTAssertFalse(old.privateAccount)
        XCTAssertNil(old.passcodeDeviceID)
        XCTAssertEqual(old.acceptedReleaseHashes, ["h"])
    }

    func testAlertEmailsWithoutAnEmail() {
        let m = PaxAlertEmail.accessOff(device: "Sam's iPhone", email: "")
        XCTAssertFalse(m.trustedBody.contains("()"))
        XCTAssertTrue(PaxAlertEmail.accessOff(device: "Sam's iPhone", email: "Sam").trustedBody.contains("(Sam)"))
    }
}
