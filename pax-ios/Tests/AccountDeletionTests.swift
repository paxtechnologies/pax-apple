// SPDX-License-Identifier: GPL-3.0-only
// DELETE /v1/accounts/me answers (Pax server 0.8.30), and the fallback for servers without
// the route (0.8.29 answers 405, an older proxy 404).
import XCTest

final class AccountDeletionTests: XCTestCase {
    private func out(_ status: Int, _ json: String = "") -> AccountDeletion.Outcome {
        AccountDeletion.outcome(status: status, body: Data(json.utf8))
    }

    func testDeletedOn204() {
        XCTAssertEqual(out(204), .deleted)
        XCTAssertEqual(out(200, "{}"), .deleted)
    }

    func testRouteMissingMeansEmailInstead() {
        XCTAssertEqual(out(404, #"{"detail":"Not Found"}"#), .notAvailable)
        XCTAssertEqual(out(405, #"{"detail":"Method Not Allowed"}"#), .notAvailable)   // live 0.8.29
    }

    func testSignedOut() {
        XCTAssertEqual(out(401, #"{"error":"unauthorized","message":"invalid token","pax_code":"PAX-ESCROW-001"}"#),
                       .signedOut)
    }

    func testStillProtectedListsDevices() {
        let body = #"""
        {"error":"devices_still_protected","message":"Pax is still on 2 device(s) on this account. Turn Pax off on every device first, then delete your account.","count":2,
         "devices":[{"device_id":"d1","name":"Ruben's iPhone","platform":"ios","reason":"pax_on","removal_request":null,"checking_in":true},
                    {"device_id":"d2","name":"Study Mac","platform":"macos","reason":"turn_off_wait","removal_request":"normal","checking_in":false}],
         "pax_code":"PAX-ESCROW-005"}
        """#
        guard case let .stillProtected(message, count, devices) = out(409, body) else {
            return XCTFail("expected stillProtected")
        }
        XCTAssertEqual(count, 2)
        XCTAssertTrue(message.hasPrefix("Pax is still on 2"))
        XCTAssertEqual(devices.map(\.deviceID), ["d1", "d2"])
        XCTAssertEqual(devices[0].kind, "iPhone")
        XCTAssertEqual(devices[1].kind, "Mac")
        XCTAssertEqual(devices[1].reason, "turn_off_wait")
        XCTAssertEqual(devices[1].removalRequest, "normal")
        XCTAssertEqual(devices[1].checkingIn, false)
        XCTAssertNil(devices[0].removalRequest)
    }

    func testStillProtectedFailsClosed() {
        // A refusal with no readable list is still a refusal, never "deleted".
        guard case let .stillProtected(_, count, devices) = out(409, #"{"error":"devices_still_protected"}"#) else {
            return XCTFail("expected stillProtected")
        }
        XCTAssertEqual(count, 1)
        XCTAssertTrue(devices.isEmpty)
        let ipad = #"{"error":"devices_still_protected","count":1,"devices":[{"device_id":"x","name":"","platform":"ipados","reason":"emergency_release"}]}"#
        guard case let .stillProtected(_, _, d) = out(409, ipad) else { return XCTFail() }
        XCTAssertEqual(d.first?.kind, "iPad")
        XCTAssertEqual(d.first?.name, "A device")
        XCTAssertNil(d.first?.checkingIn)
    }

    func testOther409IsNotDeleted() {
        guard case .failed = out(409, #"{"error":"something_else","message":"busy"}"#) else { return XCTFail() }
    }

    func testRateLimited() {
        XCTAssertEqual(out(429, #"{"error":"rate_limited","pax_code":"PAX-ESCROW-006"}"#), .rateLimited)
    }

    func testServerErrorChangesNothing() {
        XCTAssertEqual(out(500, ""), .failed("Pax's server couldn't delete your account (500). Nothing has changed."))
        XCTAssertEqual(out(503, #"{"message":"try later"}"#), .failed("Try later."))
    }

    func testStillOnCopyIsCalm() {
        XCTAssertEqual(PaxCopy.deleteStillOnReason("pax_on", checkingIn: true), "Pax is on")
        XCTAssertEqual(PaxCopy.deleteStillOnReason("turn_off_wait", checkingIn: nil), "Turn-off wait in progress")
        XCTAssertTrue(PaxCopy.deleteStillOnReason("pax_on", checkingIn: false).contains("not seen online lately"))
        XCTAssertTrue(PaxCopy.deleteStillOnHowTo.contains("never skips"))
        XCTAssertTrue(PaxCopy.deleteBody(isActive: true).contains("never skips"))
        XCTAssertTrue(PaxCopy.deleteStillOnBody(count: 3).contains("3 of its devices"))
    }
}
