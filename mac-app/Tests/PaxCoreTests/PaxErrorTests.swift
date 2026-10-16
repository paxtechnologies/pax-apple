// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import XCTest
@testable import PaxCore

/// v0.7.0 support codes: unique, well-formed, documented, and the failure points
/// the maintainer listed map to the right code.
final class PaxErrorTests: XCTestCase {
    func testCodesAreUniqueAndWellFormed() {
        let codes = PaxErrorCatalog.all.map(\.code)
        XCTAssertEqual(codes.count, Set(codes).count)
        XCTAssertGreaterThan(codes.count, 30)
        for info in PaxErrorCatalog.all {
            XCTAssertTrue(PaxErrorCatalog.isWellFormed(info.code), info.code)
            XCTAssertFalse(info.message.isEmpty || info.action.isEmpty || info.cause.isEmpty, info.code)
        }
    }

    func testEveryCodeIsDocumented() throws {
        let docs = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("docs/ERROR_CODES.md")
        guard let text = try? String(contentsOf: docs, encoding: .utf8) else {
            throw XCTSkip("docs/ERROR_CODES.md not next to the sources")
        }
        for info in PaxErrorCatalog.all {
            XCTAssertTrue(text.contains("`\(info.code)`"), info.code)
        }
    }

    func testMacPreflightCodes() {
        func code(_ problem: String) -> String {
            PaxErrorClassifier.classify(MacLockdownError.preflightFailed([problem])).code
        }
        XCTAssertEqual(code("That isn't the password for alex. Pax needs it to set this up."), "PAX-MAC-001")
        XCTAssertEqual(code("alex isn't an administrator, so Pax can't set this up from here."), "PAX-MAC-002")
        XCTAssertEqual(code("There are other administrator accounts (rmsvc). Pax would not be…"), "PAX-MAC-003")
        XCTAssertEqual(code("A paxadmin account already exists. Remove Pax properly first."), "PAX-MAC-004")
        XCTAssertEqual(PaxErrorClassifier.classify(MacLockdownError.wrongPassword).code, "PAX-MAC-001")
    }

    func testGuardInstallCodes() {
        let coded = MacLockdownError.guardInstallFailed("pax-guard-install: PAX-GUARD-005: pax-guard is not loaded")
        XCTAssertEqual(PaxErrorClassifier.classify(coded).code, "PAX-GUARD-005")
        // Older installer output without a code: launchctl error 5 / quarantine.
        let legacy = MacLockdownError.rolledBack(.installGuard,
            "Bootstrap failed: 5: Input/output error")
        XCTAssertEqual(PaxErrorClassifier.classify(legacy).code, "PAX-GUARD-003")
        XCTAssertEqual(PaxErrorClassifier.guardCode("Refusing to execute/trust quarantined program"), "PAX-GUARD-003")
        XCTAssertEqual(PaxErrorClassifier.classify(MacLockdownError.rolledBack(.demoteUser, "x")).code, "PAX-MAC-010")
    }

    func testDeviceAndSetupCodes() {
        XCTAssertEqual(PaxErrorClassifier.classify(DeviceServiceError.toolMissing("/usr/local/bin/cfgutil")).code,
                       "PAX-IOS-001")
        XCTAssertEqual(PaxErrorClassifier.classify(
            DeviceServiceError.commandFailed(command: "prepare", message: "boom")).code, "PAX-IOS-002")
        XCTAssertEqual(PaxErrorClassifier.classify(
            DeviceServiceError.commandFailed(command: "make_profile.py", message: "error: PAX-PROFILE-001: bad")).code,
            "PAX-PROFILE-001")
        XCTAssertEqual(PaxErrorClassifier.classify(DeviceServiceError.noDevice).code, "PAX-IOS-004")
        XCTAssertEqual(PaxErrorClassifier.classify(SetupError.helperMissing).code, "PAX-IOS-005")
        XCTAssertEqual(PaxErrorClassifier.classify(SetupError.profileNotVerified).code, "PAX-PROFILE-003")
        XCTAssertEqual(PaxErrorClassifier.classify(HelperFailure(code: "backup_incomplete", message: "x")).code,
                       "PAX-IOS-009")
    }

    func testEscrowAndNetworkCodes() {
        XCTAssertEqual(PaxErrorClassifier.classify(
            EscrowClient.APIError(status: 401, code: "unauthorized", message: "bad token")).code, "PAX-ESCROW-001")
        XCTAssertEqual(PaxErrorClassifier.classify(
            EscrowClient.APIError(status: 400, code: "bad_request",
                                  message: "wait time must be between 3 days and 365 days")).code, "PAX-ESCROW-002")
        XCTAssertEqual(PaxErrorClassifier.classify(
            EscrowClient.APIError(status: 502, code: "http_502", message: "")).code, "PAX-ESCROW-004")
        XCTAssertEqual(PaxErrorClassifier.classify(URLError(.notConnectedToInternet)).code, "PAX-NET-002")
        XCTAssertEqual(PaxErrorClassifier.classify(URLError(.cannotConnectToHost)).code, "PAX-NET-001")
        XCTAssertEqual(PaxErrorClassifier.classify(MacLockdownError.escrowFailed("timed out")).code, "PAX-NET-001")
        XCTAssertEqual(PaxErrorClassifier.classify(MacLockdownError.escrowFailed("409")).code, "PAX-ESCROW-003")
    }

    func testUnknownErrorsGetTheGenericCode() {
        struct Odd: Error {}
        XCTAssertEqual(PaxErrorClassifier.classify(Odd()).code, "PAX-APP-000")
        XCTAssertEqual(PaxError("PAX-NOPE-123").code, "PAX-APP-000")
    }

    func testSupportDetailsRemovePersonalData() {
        let err = PaxError("PAX-GUARD-003", technical: "alex@example.com token=abcdefghijklmnopqrstuvwxyz123")
        let log = (1...80).map { "line \($0)" } + [
            "✓ Created Alex's MacBook for alex",
            "DNS https://dns.paxpeace.com/u/Abc_defGHIJKLmnopqrstuvwxyz0123/dns-query",
        ]
        let text = SupportDetails.text(error: err, appVersion: "0.7.0", macOSVersion: "15.1",
                                       deviceOSVersion: "18.0", log: log,
                                       redact: ["Alex's MacBook", "alex"])
        XCTAssertTrue(text.contains("Code: PAX-GUARD-003"))
        XCTAssertTrue(text.contains("Pax version: 0.7.0"))
        XCTAssertTrue(text.contains("macOS: 15.1"))
        XCTAssertTrue(text.contains("iOS 18.0"))
        XCTAssertFalse(text.contains("example.com"))
        XCTAssertFalse(text.lowercased().contains("alex"))
        XCTAssertFalse(text.contains("Abc_def"))
        XCTAssertFalse(text.contains("abcdefghijklmnopqrstuvwxyz123"))
        XCTAssertFalse(text.contains("line 30\n"))   // only the last 50 lines
        XCTAssertEqual(text.components(separatedBy: "\n").filter { $0.hasPrefix("  ") }.count, 50)
    }

    /// v0.8.1: an exception for a site Pax always blocks is refused at once (PAX-DNS-010),
    /// from the server (422 restricted_site) or from pax-guard (coded failure).
    func testRestrictedSiteRefusal() {
        let sentence = "This site is in a category Pax always blocks, so it can't be allowed."
        let server = EscrowClient.APIError(status: 422, code: "restricted_site", message: sentence)
        let e1 = PaxErrorClassifier.classify(server)
        XCTAssertEqual(e1.code, "PAX-DNS-010")
        XCTAssertTrue(e1.isRestrictedSite)
        XCTAssertEqual(e1.info.message, sentence)
        let guardFailure = GuardClient.Failure(code: "PAX-DNS-010", message: sentence)
        XCTAssertTrue(PaxErrorClassifier.classify(guardFailure).isRestrictedSite)
        // A full allow-list is still an ordinary failure.
        XCTAssertFalse(PaxErrorClassifier.classify(EscrowClient.APIError(status: 422, code: "limit_reached",
                                                              message: "full")).isRestrictedSite)
    }
}
