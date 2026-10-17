// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.15: verified support release. The app passes the set-up choice (on by default),
/// shows the Support ID and the switch, and hands a support code to pax-guard or the
/// server, which check it and tell the trusted person first.
final class V0815Tests: XCTestCase {
    func testSetUpDefaultsToOn() {
        XCTAssertTrue(SetupConfiguration().supportRelease)
        XCTAssertTrue(VerifiedSupportRelease.setUpDefault)
    }

    func testDepositPassesTheSetUpChoice() {
        let on = MacLockdownCommands.localEscrowDeposit(guardSource: "/R/guard", secretFile: "/tmp/s",
                                                        waitSeconds: 86_400, isExecutable: { _ in false })
        let i = on.1.firstIndex(of: "--support-release")!
        XCTAssertEqual(on.1[i + 1], "on")
        XCTAssertTrue(on.1.joined(separator: " ").contains("--wait-seconds 86400 --reset"))
        let off = MacLockdownCommands.localEscrowDeposit(guardSource: "/R/guard", secretFile: "/tmp/s",
                                                         waitSeconds: 86_400, supportRelease: false,
                                                         isExecutable: { _ in false })
        XCTAssertEqual(off.1[off.1.firstIndex(of: "--support-release")! + 1], "off")
    }

    func testDeviceStatusDecodesWithAndWithoutSupportFields() throws {
        let new = #"{"device_id":"d","name":"n","platform":"ios","installed_at":1,"grace_until":2,"in_grace_period":false,"released_at":null,"removal_request":null,"support_id":"ABCD-EFGH-IJKL-MNOP","support_release":{"allowed":false,"pending_on_at":1800000000}}"#
        let s = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(new.utf8))
        XCTAssertEqual(s.support_id, "ABCD-EFGH-IJKL-MNOP")
        XCTAssertEqual(s.support_release?.allowed, false)
        XCTAssertEqual(s.support_release?.pending_on_at, 1_800_000_000)
        let old = #"{"device_id":"d","name":"n","platform":"ios","installed_at":1,"grace_until":2,"in_grace_period":false,"released_at":null,"removal_request":null}"#
        let o = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(old.utf8))
        XCTAssertNil(o.support_id)
        XCTAssertNil(o.support_release)
    }

    func testRefusedCodesKeepTheirOwnCode() {
        for (name, code) in VerifiedSupportRelease.apiErrors {
            let e = EscrowClient.APIError(status: 403, code: name, message: "no")
            XCTAssertEqual(PaxErrorClassifier.classify(e).code, code)
            XCTAssertTrue(PaxErrorCatalog.contains(code), code)
        }
        XCTAssertEqual(Set(VerifiedSupportRelease.apiErrors.values).count, 8)
    }

    func testGuardRedeemAndSwitch() async throws {
        let device = #"{"device_id":"local","name":"This Mac","platform":"mac","installed_at":1,"grace_until":2,"in_grace_period":false,"released_at":null,"removal_request":null,"support_id":"ABCD-EFGH-IJKL-MNOP","support_release":{"allowed":false,"pending_on_at":null,"telling_partner":false}}"#
        let t = FakeGuardTransport([
            "escrow.support_release": #"{"ok": true, "device": \#(device)}"#,
            "escrow.redeem_support": #"{"ok": true, "released": {"device_id":"local","reason":"remove","removal_password":"pw"}}"#,
        ])
        let g = GuardClient(transport: t)
        let st = try await g.setSupportRelease(false)
        XCTAssertEqual(st.support_release?.allowed, false)
        XCTAssertEqual(t.sent[0]["allowed"] as? Bool, false)
        let r = try await g.redeemSupportCode("paxs-abcde fghij\n")
        XCTAssertEqual(r.removal_password, "pw")
        XCTAssertEqual(t.sent[1]["code"] as? String, "PAXS-ABCDEFGHIJ")
    }

    func testGuardRefusalCarriesItsCode() async {
        let t = FakeGuardTransport(["escrow.redeem_support": #"{"ok": false, "code": "PAX-ESCROW-018", "error": "partner not told"}"#])
        do {
            _ = try await GuardClient(transport: t).redeemSupportCode("PAXS-X")
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-ESCROW-018")
        }
    }

    func testWordingIsCalmAndNamesNoOne() {
        let all = [VerifiedSupportRelease.title, VerifiedSupportRelease.setUpDetail, VerifiedSupportRelease.codeExplainer,
                   VerifiedSupportRelease.detail(allowed: true, pendingOnAt: nil),
                   VerifiedSupportRelease.detail(allowed: false, pendingOnAt: nil),
                   VerifiedSupportRelease.detail(allowed: false, pendingOnAt: 1_800_000_000)].joined(separator: " ")
        XCTAssertFalse(all.contains("!"))
        XCTAssertTrue(VerifiedSupportRelease.setUpDetail.contains("this device only"))
        XCTAssertTrue(VerifiedSupportRelease.detail(allowed: false, pendingOnAt: nil).contains("full wait"))
    }

    func testCodeShapeCheck() {
        XCTAssertFalse(VerifiedSupportRelease.looksComplete("PAXS-ABCDE"))
        XCTAssertTrue(VerifiedSupportRelease.looksComplete("PAXS-" + String(repeating: "ABCDE-", count: 30)))
    }
}
