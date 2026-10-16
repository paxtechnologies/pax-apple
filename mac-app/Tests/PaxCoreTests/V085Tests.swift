// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.5: the production server by default (self-hosting still possible), the
/// /v1/notify relay for Mac partner emails, and the server's fail-closed partner error.
final class V085Tests: XCTestCase {
    private let prod = URL(string: "https://api.paxpeace.com/")!

    func testProductionServerIsTheDefaultAndSelfHostingStillWins() {
        XCTAssertEqual(ServerURLSetting.defaultURL, prod)
        XCTAssertEqual(ServerURLSetting.resolve(environment: [:], stored: nil), prod)
        XCTAssertEqual(ServerURLSetting.resolve(environment: [:], stored: "pax.example.org").absoluteString,
                       "https://pax.example.org/")
        XCTAssertEqual(ServerURLSetting.resolve(environment: [:], stored: "127.0.0.1:8080").absoluteString,
                       "http://127.0.0.1:8080/")
        XCTAssertEqual(ServerURLSetting.resolve(environment: ["PAX_SERVER_URL": "http://127.0.0.1:8080/"],
                                                stored: nil).absoluteString, "http://127.0.0.1:8080/")
    }

    func testRelayDefaultsToTheAppServerWithItsAccount() throws {
        for typed in ["", "  ", "https://", "http://"] {
            let relay = try PartnerRelay.url(typed: typed, appServer: prod).get()
            XCTAssertEqual(relay, prod, typed)
            XCTAssertTrue(PartnerRelay.usesAppAccount(relay: relay, typedToken: "", appServer: prod))
        }
        let same = try PartnerRelay.url(typed: "api.paxpeace.com", appServer: prod).get()
        XCTAssertTrue(PartnerRelay.usesAppAccount(relay: same, typedToken: " ", appServer: prod))
        XCTAssertFalse(PartnerRelay.usesAppAccount(relay: same, typedToken: "tok", appServer: prod))
    }

    func testRelayToASelfHostedServerNeedsItsOwnToken() throws {
        let own = try PartnerRelay.url(typed: "pax.example.org", appServer: prod).get()
        XCTAssertEqual(own.absoluteString, "https://pax.example.org/")
        XCTAssertFalse(PartnerRelay.usesAppAccount(relay: own, typedToken: "", appServer: prod))
        XCTAssertEqual(PartnerRelay.transport(relay: own, token: "t0k"),
                       ["kind": "relay", "url": "https://pax.example.org/", "token": "t0k"])
        if case .failure(let p) = PartnerRelay.url(typed: "http://pax.example.org", appServer: prod) {
            XCTAssertEqual(p, .insecureRemote)
        } else {
            XCTFail("plain http on the internet must be refused")
        }
    }

    func testServerPartnerUnreachableIsEscrow010() {
        let e = EscrowClient.APIError(status: 503, code: "partner_unreachable",
                                      message: "Pax couldn't email your partner just now, so nothing has started.")
        XCTAssertEqual(PaxErrorClassifier.classify(e).code, "PAX-ESCROW-010")
        let other = EscrowClient.APIError(status: 503, code: "unavailable", message: "down")
        XCTAssertEqual(PaxErrorClassifier.classify(other).code, "PAX-ESCROW-004")
        let signup = EscrowClient.APIError(status: 429, code: "rate_limited", message: "too many new accounts")
        XCTAssertEqual(PaxErrorClassifier.classify(signup).code, "PAX-ESCROW-006")
    }
}
