// SPDX-License-Identifier: GPL-3.0-only
// The words the app shows: family-friendly, calm, honest, and always pointing to
// setting up from a Mac for the strongest protection.
import XCTest

final class CopyTests: XCTestCase {
    private var every: [String] { PaxCopy.all(isPad: false) + PaxCopy.all(isPad: true) }

    func testSetUpFromAMacNote() {
        for pad in [false, true] {
            let d = pad ? "iPad" : "iPhone"
            XCTAssertEqual(PaxCopy.macNote(isPad: pad),
                           "For the strongest protection, set Pax up from a Mac. It locks this \(d) more firmly "
                           + "and can't be switched off in Settings.")
            XCTAssertTrue(PaxCopy.limits(isPad: pad, passcode: true).contains(PaxCopy.macSummaryLine(isPad: pad)))
            XCTAssertTrue(PaxCopy.limits(isPad: pad, passcode: false).contains(PaxCopy.macSummaryLine(isPad: pad)))
        }
        XCTAssertEqual(PaxCopy.macLink, "How to set up from a Mac")
        XCTAssertTrue(PaxCopy.macSummaryLine(isPad: false).contains("set Pax up from a Mac"))
    }

    func testMacStepsComeFromTheGuide() {
        let steps = GuideCopy.steps(isPad: false).filter { $0.id < 9 }
        XCTAssertEqual(steps.count, 8)
        XCTAssertTrue(steps.allSatisfy { !$0.title.contains("Strict") && !($0.detail ?? "").contains("Strict") })
        XCTAssertEqual(PaxLinks.macDownload.host, "github.com")
    }

    func testNoInternalNamesOrHarshWords() {
        let banned = ["Pax Strict", "porn", "accountability partner", "your partner", "restricted",
                      "addict", "craving", "urge", "shame"]
        for line in every {
            for b in banned {
                XCTAssertNil(line.range(of: b, options: .caseInsensitive), "“\(b)” in: \(line)")
            }
        }
    }

    func testFamilyAndTrustedPersonWording() {
        XCTAssertTrue(PaxCopy.welcomeBody(isPad: false).contains("adult and explicit content"))
        XCTAssertTrue(PaxCopy.welcomeBody(isPad: false).contains("your family"))
        XCTAssertEqual(PaxCopy.trustedTitle(.me), "Someone you trust")
        XCTAssertTrue(PaxCopy.trustedWitness.contains("never approve"))
        XCTAssertTrue(PaxCopy.waitTitle.contains("turn-off wait"))
        XCTAssertTrue(PaxCopy.emailBody(.child).contains("not your child's"))
    }

    func testHonestLimits() {
        let l = PaxCopy.limits(isPad: false, passcode: false).joined(separator: " ")
        XCTAssertTrue(l.contains("full erase"))
        XCTAssertTrue(l.contains("switch the encrypted DNS off in Settings"))
        XCTAssertTrue(l.contains("Face ID"))
        XCTAssertFalse(PaxCopy.limits(isPad: false, passcode: true).joined().contains("Face ID"))
        XCTAssertTrue(PaxCopy.dnsHonest(trusted: true).contains("switch this layer off"))
    }

    func testDeviceWordMatches() {
        XCTAssertTrue(PaxCopy.all(isPad: true).allSatisfy { !$0.contains("this iPhone") })
        XCTAssertTrue(PaxCopy.all(isPad: false).allSatisfy { !$0.contains("this iPad") })
    }

    func testLinks() {
        XCTAssertEqual(Pax.privacyURL.absoluteString, "https://paxpeace.com/privacy")
        XCTAssertEqual(Pax.apiBase.host, "api.paxpeace.com")
        XCTAssertEqual(Pax.dnsHost, "dns.paxpeace.com")
    }
}
