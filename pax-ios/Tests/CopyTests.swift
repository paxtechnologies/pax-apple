// SPDX-License-Identifier: GPL-3.0-only
// The words the app shows: family-friendly, calm, honest, and always pointing to
// setting up from a Mac for the strongest protection.
import XCTest

final class CopyTests: XCTestCase {
    private var every: [String] { PaxCopy.all(isPad: false) + PaxCopy.all(isPad: true) }

    func testOneTapWelcome() {
        XCTAssertEqual(PaxCopy.turnOn, "Turn Pax on")
        XCTAssertEqual(PaxCopy.childLink, "Setting up for a child?")
        XCTAssertTrue(PaxCopy.childBody(isPad: false).contains("not your child's"))
        XCTAssertTrue(PaxCopy.retryBody.contains("nothing has been switched on"))
    }

    func testMakePaxUnremovableCard() {
        XCTAssertEqual(PaxCopy.computerTitle, "Make Pax unremovable")
        XCTAssertEqual(PaxCopy.computerSubtitle, "Set up from a Mac or Windows PC")
        XCTAssertEqual(Pax.computerSetupURL.absoluteString, "https://paxpeace.com/setup")
        XCTAssertTrue(PaxCopy.lockBody.contains("Face ID alone can switch Pax off"))
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
        XCTAssertEqual(PaxCopy.trustedTitle, "Add someone you trust")
        XCTAssertTrue(PaxCopy.trustedWitness.contains("never approve"))
        XCTAssertTrue(PaxCopy.waitTitle.contains("turn-off wait"))
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
