// SPDX-License-Identifier: GPL-3.0-only
// 1.2 one-tap set-up: email and code first (every account has a verified email), the waits,
// "Welcome back" for an existing account, the "Make Pax stronger" list, Lock Screen Time's
// refusals, releasing with a replaced escrow. Fail closed throughout.
import XCTest

final class OneTapTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func testSetUpIsFiveScreens() {
        // Welcome, email, code, Apple's Screen Time sheet (while "Turning Pax on" shows), Done.
        XCTAssertEqual(SetupRules.path(child: false, existing: false).count, 5)
        XCTAssertEqual(SetupRules.path(child: true, existing: false).count, 5)
        // An email that already has an account adds "Welcome back" (what's already set).
        XCTAssertEqual(SetupRules.path(child: false, existing: true).count, 6)
        XCTAssertFalse(SetupRules.path(child: false, existing: false).contains(.welcomeBack))
    }

    func testScreenshotStepNumbersStayPut() {
        // ios.yml opens these with -PaxShotStep.
        XCTAssertEqual(SetupStep(rawValue: 1), .childEmail)
        XCTAssertEqual(SetupStep(rawValue: 3), .email)
        XCTAssertEqual(SetupStep(rawValue: 7), .done)
    }

    func testDefaultWaits() {
        XCTAssertEqual(SetupRules.defaultWait(child: false), 7)
        XCTAssertEqual(SetupRules.defaultWait(child: true), 30)
        // A new account (the server's 72 hours) is raised to 7 days; a child's to 30.
        XCTAssertEqual(SetupRules.waitToSend(chosenDays: 7, currentSeconds: 72 * 3600), 7)
        XCTAssertEqual(SetupRules.waitToSend(chosenDays: 30, currentSeconds: 72 * 3600), 30)
    }

    func testAnExistingWaitIsNeverShortened() {
        XCTAssertNil(SetupRules.waitToSend(chosenDays: 7, currentSeconds: 30 * 86_400))
        XCTAssertNil(SetupRules.waitToSend(chosenDays: 7, currentSeconds: 7 * 86_400))       // same: nothing sent
        XCTAssertEqual(SetupRules.waitToSend(chosenDays: 30, currentSeconds: 14 * 86_400), 30)
    }

    func testWelcomeBackShowsWhatIsAlreadySet() {
        let a = ExistingAccount(waitSeconds: 14 * 86_400, pendingWaitSeconds: 3 * 86_400,
                                trustedEmail: "friend@example.com",
                                devices: [(name: "Sam's MacBook", platform: "mac", released: false),
                                          (name: "Old iPad", platform: "ipados", released: true),
                                          (name: nil, platform: "ios", released: nil)],
                                child: false)
        XCTAssertEqual(a.waitDays, 14)
        XCTAssertEqual(a.pendingWaitDays, 3)
        XCTAssertNil(a.lengthenTo)                           // 14 days already: left as it is
        XCTAssertEqual(a.devices, [.init(name: "Sam's MacBook", kind: "Mac"), .init(name: "A device", kind: "iPhone")])
        let lines = PaxCopy.welcomeBackLines(a).joined(separator: " ")
        XCTAssertTrue(lines.contains("Turn-off wait: 2 weeks"))
        XCTAssertTrue(lines.contains("friend@example.com"))
        XCTAssertTrue(lines.contains("Sam's MacBook (Mac)"))
        XCTAssertFalse(lines.contains("Old iPad"))
        XCTAssertFalse(lines.contains("lengthens"))

        let short = ExistingAccount(waitSeconds: 3 * 86_400, pendingWaitSeconds: nil, trustedEmail: "",
                                    devices: [], child: true)
        XCTAssertEqual(short.lengthenTo, 30)
        XCTAssertNil(short.trustedEmail)
        XCTAssertTrue(PaxCopy.welcomeBackLines(short).joined().contains("lengthens it to 30 days"))
    }

    func testSigningInAgainOnlyToTheSameAccount() {
        XCTAssertTrue(SetupRules.sameAccount(setUpID: "a1", setUpEmail: "sam@example.com", signedInID: "a1", signedInEmail: "x@example.com"))
        XCTAssertFalse(SetupRules.sameAccount(setUpID: "a1", setUpEmail: "sam@example.com", signedInID: "b2", signedInEmail: "sam@example.com"))
        XCTAssertTrue(SetupRules.sameAccount(setUpID: nil, setUpEmail: "Sam@Example.com", signedInID: "b2", signedInEmail: " sam@example.com"))
        XCTAssertFalse(SetupRules.sameAccount(setUpID: nil, setUpEmail: "sam@example.com", signedInID: "b2", signedInEmail: "kim@example.com"))
    }

    func testLockScreenTimeRefusalsAreCalm() {
        XCTAssertEqual(LockRefusal.of(status: 409, reason: "removal_request_open"), .turnOffOpen)
        XCTAssertEqual(LockRefusal.of(status: 409, reason: "emergency_open"), .supportTurnOffOpen)
        XCTAssertEqual(LockRefusal.of(status: 409, reason: "released"), .released)
        XCTAssertEqual(LockRefusal.of(status: 409, reason: "retired"), .removed)
        XCTAssertEqual(LockRefusal.of(status: 409, reason: "changed"), .changed)
        XCTAssertEqual(LockRefusal.of(status: 409, reason: nil), .changed)
        XCTAssertEqual(LockRefusal.of(status: 404, reason: nil), .notOnAccount)
        XCTAssertNil(LockRefusal.of(status: 0, reason: nil))         // offline: the general message
        XCTAssertNil(LockRefusal.of(status: 503, reason: nil))
        for r in [LockRefusal.turnOffOpen, .supportTurnOffOpen, .released, .removed, .changed, .notOnAccount] {
            XCTAssertFalse(r.message(isPad: false).contains("409"))
            XCTAssertFalse(r.message(isPad: true).contains("iPhone"))
            if r != .changed { XCTAssertTrue(r.message(isPad: true).contains("this iPad")) }
        }
    }

    func testFirstNameForTheTrustedPerson() {
        XCTAssertEqual(SetupRules.cleanName("  Sam \n"), "Sam")
        XCTAssertEqual(SetupRules.cleanName("Sam\tLee"), "Sam Lee")
        XCTAssertEqual(SetupRules.cleanName("Sa\u{202E}m"), "Sam")              // bidi override removed
        XCTAssertNil(SetupRules.cleanName(" \n "))
        XCTAssertEqual(SetupRules.cleanName(String(repeating: "a", count: 99))?.count, 40)
        XCTAssertNotNil(SetupRules.nameProblem("https://example.com"))
        XCTAssertNotNil(SetupRules.nameProblem("www.example.com"))
        XCTAssertNotNil(SetupRules.nameProblem(String(repeating: "a", count: 41)))
        XCTAssertNil(SetupRules.nameProblem("Sam"))
        XCTAssertNil(SetupRules.nameProblem(""))
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
        p.accountID = "a1"
        p.pendingReleaseKeyHash = "pending"
        p.displayName = "Sam"
        XCTAssertEqual(PaxPolicy.decode(try JSONEncoder().encode(p)), p)
        // A 1.1 policy has none of these keys: still on, nothing invented.
        let old = PaxPolicy.decode(Data(#"{"isActive":true,"setUpFinished":true,"deviceID":"d","releaseKeyHash":"h"}"#.utf8))
        XCTAssertTrue(old.isActive)
        XCTAssertNil(old.accountID)
        XCTAssertEqual(old.acceptedReleaseHashes, ["h"])
    }

    func testAlertEmailsWithoutAnEmail() {
        let m = PaxAlertEmail.accessOff(device: "Sam's iPhone", email: "")
        XCTAssertFalse(m.trustedBody.contains("()"))
        XCTAssertTrue(PaxAlertEmail.accessOff(device: "Sam's iPhone", email: "Sam").trustedBody.contains("(Sam)"))
    }
}
