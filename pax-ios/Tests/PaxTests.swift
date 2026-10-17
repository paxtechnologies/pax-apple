// SPDX-License-Identifier: GPL-3.0-only
import XCTest

final class PaxTests: XCTestCase {
    func testWaitIsClamped() {
        XCTAssertEqual(TurnOffRules.clampWait(days: 1), 3)
        XCTAssertEqual(TurnOffRules.clampWait(days: 30), 30)
        XCTAssertEqual(TurnOffRules.clampWait(days: 1000), 365)
    }

    func testGraceHourHasNoWait() {
        let setUp = Date(timeIntervalSince1970: 1_000_000)
        let early = setUp.addingTimeInterval(59 * 60)
        XCTAssertEqual(TurnOffRules.unlockDate(setUpAt: setUp, waitDays: 7, requestedAt: early), early)
        let late = setUp.addingTimeInterval(3600)
        XCTAssertEqual(TurnOffRules.unlockDate(setUpAt: setUp, waitDays: 7, requestedAt: late),
                       late.addingTimeInterval(7 * 86_400))
    }

    func testDescribe() {
        XCTAssertEqual(TurnOffRules.describe(remaining: 0), "ready now")
        XCTAssertEqual(TurnOffRules.describe(remaining: 3 * 86_400 + 4 * 3600), "3 days, 4 hours")
        XCTAssertEqual(TurnOffRules.describe(remaining: 3600), "1 hour")
        XCTAssertEqual(TurnOffRules.describe(remaining: 20), "less than a minute")
    }

    func testDomainNormalising() {
        XCTAssertEqual(PaxPolicy.normalise("https://WWW.Example.com/path?q=1"), "example.com")
        XCTAssertEqual(PaxPolicy.normalise("sub.example.co.uk."), "sub.example.co.uk")
        XCTAssertNil(PaxPolicy.normalise("not a domain"))
        XCTAssertNil(PaxPolicy.normalise("localhost"))
        XCTAssertNil(PaxPolicy.normalise("-bad.com"))
    }

    func testEscrowRoundTrip() {
        let s = EscrowSecret.make(passcode: "4831")
        XCTAssertGreaterThanOrEqual(s.sealed.count, 20)       // server minimum for removal_password
        XCTAssertLessThanOrEqual(s.sealed.count, 256)         // server maximum
        XCTAssertEqual(EscrowSecret.open(s.sealed), s)
        XCTAssertEqual(EscrowSecret.open(s.sealed)?.releaseKeyHash, s.releaseKeyHash)
        XCTAssertNil(EscrowSecret.open("garbage-garbage-garbage"))
    }

    func testPasscodesAreNotObvious() {
        for _ in 0..<500 {
            let c = EscrowSecret.makePasscode()
            XCTAssertEqual(c.count, 4)
            XCTAssertFalse(EscrowSecret.isObvious(c))
        }
        for bad in ["0000", "1234", "4321", "1212", "1999", "2026"] { XCTAssertTrue(EscrowSecret.isObvious(bad)) }
    }
}
