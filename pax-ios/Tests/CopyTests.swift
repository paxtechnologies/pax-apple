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
        XCTAssertTrue(PaxCopy.lockBody.contains("until your turn-off wait ends"))
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
        for raw in every {
            // "YouTube Restricted Mode" is YouTube's own name for its setting (24 Oct 2026).
            let line = raw.replacingOccurrences(of: "YouTube Restricted Mode", with: "YouTube")
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

    /// 1.2 (Ruben, 23 Oct 2026): no "Good to know", and nothing in the app explains how to
    /// remove, get round or switch Pax off other than through the turn-off wait.
    func testNoWayRoundTheWaitInTheApp() {
        let banned = ["Good to know", "unlock", "full erase", "restore from a computer", "Face ID can",
                      "Face ID alone", "switch this layer off", "can switch the encrypted DNS off",
                      "switched off in Settings", "with no wait", "could be reset", "First hour"]
        for line in every {
            for b in banned {
                XCTAssertNil(line.range(of: b, options: .caseInsensitive), "“\(b)” in: \(line)")
            }
        }
        XCTAssertTrue(PaxCopy.dnsHonest(trusted: true).contains("Pax shows it here"))
        XCTAssertEqual(PaxCopy.homeNoPasscode, "Screen Time isn't locked yet")
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
