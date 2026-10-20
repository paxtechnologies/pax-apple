// SPDX-License-Identifier: GPL-3.0-only
// Policy logic: fail closed everywhere.
import XCTest

final class PolicyTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    // MARK: saved policy

    func testPolicyRoundTrip() throws {
        var p = PaxPolicy()
        p.isActive = true
        p.setUpFinished = true
        p.audience = .child
        p.trustedEmail = "friend@example.com"
        p.blockedDomains = ["example.com"]
        p.deviceID = "dev1"
        p.releaseKeyHash = "abc"
        p.dnsInstalled = true
        p.dnsOffSince = t0
        let data = try JSONEncoder().encode(p)
        XCTAssertEqual(PaxPolicy.decode(data), p)
    }

    func testUnreadablePolicyCountsAsOn() {
        let p = PaxPolicy.decode(Data("not json".utf8))
        XCTAssertTrue(p.isActive)
        XCTAssertTrue(p.setUpFinished)
    }

    func testNoSavedPolicyIsNotSetUp() {
        XCTAssertFalse(PaxPolicy.decode(nil).isActive)
    }

    func testOlderPolicyWithMissingFieldsStaysOn() {
        // A policy saved before newer fields existed (only a few keys).
        let old = Data(#"{"isActive":true,"waitDays":30,"blockedDomains":["a.com"],"deviceID":"d"}"#.utf8)
        let p = PaxPolicy.decode(old)
        XCTAssertTrue(p.isActive)
        XCTAssertEqual(p.waitDays, 30)
        XCTAssertEqual(p.blockedDomains, ["a.com"])
        XCTAssertEqual(p.deviceID, "d")
        XCTAssertEqual(p.audience, .me)
    }

    func testWrongTypeInOneFieldDoesNotTurnPaxOff() {
        let odd = Data(#"{"isActive":true,"waitDays":"seven","audience":"robot"}"#.utf8)
        let p = PaxPolicy.decode(odd)
        XCTAssertTrue(p.isActive)
        XCTAssertEqual(p.waitDays, Pax.defaultWaitDays)
        XCTAssertEqual(p.audience, .me)
    }

    func testAddingSitesOnlyAdds() {
        var p = PaxPolicy()
        XCTAssertTrue(p.addDomain("https://www.Example.com/x"))
        XCTAssertFalse(p.addDomain("example.com"))
        XCTAssertFalse(p.addDomain("not a site"))
        XCTAssertEqual(p.blockedDomains, ["example.com"])
    }

    // MARK: releasing (the only path that removes anything)

    func testReleaseNeedsMatchingHash() {
        let s = EscrowSecret.make(passcode: "4831")
        XCTAssertEqual(EscrowSecret.decide(sealed: s.sealed, expectedHash: s.releaseKeyHash),
                       .release(passcode: "4831"))
        let other = EscrowSecret.make(passcode: "4831")
        if case .release = EscrowSecret.decide(sealed: other.sealed, expectedHash: s.releaseKeyHash) {
            XCTFail("a secret from another device must not release this one")
        }
    }

    func testReleaseFailsClosed() {
        let s = EscrowSecret.make(passcode: nil)
        for (sealed, hash) in [(nil, s.releaseKeyHash), ("garbage-garbage-garbage", s.releaseKeyHash),
                               (s.sealed, nil), (s.sealed, ""), ("paxios1.", s.releaseKeyHash)] as [(String?, String?)] {
            if case .release = EscrowSecret.decide(sealed: sealed, expectedHash: hash) {
                XCTFail("released with sealed=\(String(describing: sealed)) hash=\(String(describing: hash))")
            }
        }
        XCTAssertEqual(EscrowSecret.decide(sealed: s.sealed, expectedHash: s.releaseKeyHash), .release(passcode: nil))
    }

    func testSealedSecretFitsTheServerField() {
        for p in [nil, "4831"] as [String?] {
            let s = EscrowSecret.make(passcode: p).sealed
            XCTAssertTrue(s.hasPrefix("paxios1."))
            XCTAssertTrue((20...256).contains(s.count))
        }
    }

    // MARK: turn-off phase

    func testPhaseFromServer() {
        XCTAssertEqual(TurnOffRules.phase(requestStatus: nil, secondsRemaining: nil, canReveal: nil, now: t0), .none)
        XCTAssertEqual(TurnOffRules.phase(requestStatus: "cancelled", secondsRemaining: 0, canReveal: false, now: t0), .none)
        XCTAssertEqual(TurnOffRules.phase(requestStatus: "lapsed", secondsRemaining: 0, canReveal: false, now: t0), .none)
        XCTAssertEqual(TurnOffRules.phase(requestStatus: "pending", secondsRemaining: 3600, canReveal: false, now: t0),
                       .waiting(until: t0.addingTimeInterval(3600)))
        XCTAssertEqual(TurnOffRules.phase(requestStatus: "pending", secondsRemaining: 0, canReveal: true, now: t0), .ready)
        XCTAssertEqual(TurnOffRules.phase(requestStatus: "revealed", secondsRemaining: 0, canReveal: true, now: t0), .ready)
    }

    func testPhaseNeverReadyWhenServerSaysNo() {
        XCTAssertEqual(TurnOffRules.phase(requestStatus: "pending", secondsRemaining: 0, canReveal: false, now: t0), .unknown)
        XCTAssertEqual(TurnOffRules.phase(requestStatus: "pending", secondsRemaining: nil, canReveal: nil, now: t0), .unknown)
    }

    func testWaitLabelsAndDays() {
        XCTAssertEqual(Pax.waitChoices.first, 3)
        XCTAssertEqual(Pax.waitChoices.last, 365)
        XCTAssertEqual(Pax.waitChoices.map(TurnOffRules.waitLabel(days:)),
                       ["3 days", "1 week", "2 weeks", "30 days", "3 months", "6 months", "1 year"])
        XCTAssertEqual(TurnOffRules.days(fromSeconds: 72 * 3600), 3)
        XCTAssertEqual(TurnOffRules.days(fromSeconds: 72 * 3600 + 1), 4)   // rounded up, never shorter
    }

    // MARK: set-up

    func testSetupOrder() {
        var s = SetupStep.welcome
        var seen: [SetupStep] = [s]
        while s != .done { s = SetupRules.next(after: s, passcode: true); seen.append(s) }
        XCTAssertEqual(seen, SetupStep.allCases)
        XCTAssertEqual(SetupRules.next(after: .lockIn, passcode: false), .dns)
    }

    func testNoWayBackOnceSwitchedOn() {
        for s in [SetupStep.lockIn, .passcodeType, .dns, .done] { XCTAssertNil(SetupRules.back(from: s)) }
        XCTAssertEqual(SetupRules.resume(isActive: true), .dns)
        XCTAssertEqual(SetupRules.resume(isActive: false), .welcome)
    }

    func testEmailAndCode() {
        XCTAssertTrue(SetupRules.isEmail(" Sam@Example.com "))
        for bad in ["", "sam", "sam@", "@example.com", "sam@example", "sam@@example.com", "sa m@example.com"] {
            XCTAssertFalse(SetupRules.isEmail(bad), bad)
        }
        XCTAssertTrue(SetupRules.isCode("012345"))
        XCTAssertFalse(SetupRules.isCode("12345"))
        XCTAssertFalse(SetupRules.isCode("12345a"))
        XCTAssertFalse(SetupRules.isCode("١٢٣٤٥٦"))   // non-ASCII digits
    }

    func testTrustedPersonIsOptionalAndNotYou() {
        XCTAssertNil(SetupRules.trustedProblem("", account: "me@example.com"))
        XCTAssertNil(SetupRules.trustedProblem("friend@example.com", account: "me@example.com"))
        XCTAssertNotNil(SetupRules.trustedProblem("ME@example.com", account: "me@example.com"))
        XCTAssertNotNil(SetupRules.trustedProblem("friend", account: "me@example.com"))
    }

    func testSetUpOnlyLengthensTheWait() {
        XCTAssertEqual(SetupRules.waitToSend(chosenDays: 7, currentSeconds: nil), 7)
        XCTAssertEqual(SetupRules.waitToSend(chosenDays: 7, currentSeconds: 72 * 3600), 7)
        XCTAssertNil(SetupRules.waitToSend(chosenDays: 7, currentSeconds: 30 * 86_400))
        XCTAssertEqual(SetupRules.waitToSend(chosenDays: 1, currentSeconds: nil), 3)      // clamped
        XCTAssertEqual(SetupRules.defaultWait(for: .child), Pax.childDefaultWaitDays)
    }

    // MARK: DNS and Screen Time watch

    private func active() -> PaxPolicy {
        var p = PaxPolicy()
        p.isActive = true
        p.dnsInstalled = true
        p.setUpAt = t0
        return p
    }

    func testDNSOffAlertsOncePerOffPeriod() {
        var p = active()
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: true, now: t0), .none)
        XCTAssertTrue(p.dnsSeenOn)
        let a = DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(60))
        guard case .switchedOff = a else { return XCTFail("expected an alert") }
        // Not sent yet (email failed): it's due again.
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(120)), a)
        p.dnsAlertSent = DNSWatch.sentKey(for: a)
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(180)), .none)
        // Back on, then off again: a new alert.
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: true, now: t0.addingTimeInterval(240)), .none)
        let b = DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(300))
        guard case .switchedOff = b else { return XCTFail("expected a second alert") }
        XCTAssertNotEqual(a, b)
    }

    func testDNSNeverSwitchedOnAlertsAfterADay() {
        var p = active()
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(3600)), .none)
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(86_400)), .neverOn)
        p.dnsAlertSent = DNSWatch.sentKey(for: .neverOn)
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(90_000)), .none)
    }

    func testDNSWatchIgnoresInactiveOrNotAdded() {
        var p = PaxPolicy()
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: false, now: t0), .none)
        p.isActive = true
        XCTAssertEqual(DNSWatch.update(&p, isEnabled: false, now: t0.addingTimeInterval(200_000)), .none)
    }

    func testAccessLostNeedsTwoChecks() {
        XCTAssertFalse(AccessWatch.isLost(isActive: true, checks: [false]))
        XCTAssertTrue(AccessWatch.isLost(isActive: true, checks: [false, false]))
        XCTAssertFalse(AccessWatch.isLost(isActive: true, checks: [false, true]))
        XCTAssertFalse(AccessWatch.isLost(isActive: false, checks: [false, false]))
    }

    func testAlertEmailsFitTheRelay() {
        let all = [PaxAlertEmail.dnsOff(device: "Sam's iPhone", email: "sam@example.com"),
                   .dnsNeverOn(device: "Sam's iPhone", email: "sam@example.com"),
                   .accessOff(device: "Sam's iPhone", email: "sam@example.com")]
        for m in all {
            XCTAssertNotNil(m.kind.range(of: "^[a-z0-9_]+$", options: .regularExpression))
            XCTAssertLessThanOrEqual(m.subject.count, 200)
            XCTAssertLessThanOrEqual(m.body.count, 4000)
            XCTAssertLessThanOrEqual(m.trustedBody.count, 4000)
        }
    }
}
