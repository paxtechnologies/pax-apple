// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.34: Pax.app and its preferences deleted, pax-guard still protecting -> the reinstalled
/// app reconnects instead of offering set-up (PAX-MAC-002 on a Standard account).
final class V0834ReconnectTests: XCTestCase {
    func testLocalKeyHeldByPaxGuardReconnects() {
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: nil, guardEscrowMode: "local", localEscrowHeld: true),
                       .reconnectLocal)
        XCTAssertEqual(GuardReconnect.localDeviceID, "local")
    }

    func testServerKeyNeverGuessesAnID() {
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: nil, guardEscrowMode: "server", localEscrowHeld: false),
                       .protectedByServer)
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: nil, guardEscrowMode: "server", localEscrowHeld: true),
                       .protectedByServer)
        XCTAssertFalse(GuardReconnect.offersSetUp(.protectedByServer))
        XCTAssertTrue(GuardReconnect.serverMessage.contains("Pax is still protecting this Mac"))
        XCTAssertTrue(GuardReconnect.serverMessage.contains("hello@paxpeace.com"))
        XCTAssertFalse(GuardReconnect.serverMessage.contains("PAX-"))
    }

    func testNoPaxGuardOrNothingHeldLeavesSetUpAlone() {
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: nil, guardEscrowMode: nil, localEscrowHeld: false), .none)
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: nil, guardEscrowMode: "local", localEscrowHeld: false), .none)
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: nil, guardEscrowMode: "other", localEscrowHeld: true), .none)
        XCTAssertTrue(GuardReconnect.offersSetUp(.none))
        XCTAssertFalse(GuardReconnect.offersSetUp(.reconnectLocal))
    }

    func testASavedDeviceIsKept() {
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: "abc123", guardEscrowMode: "server", localEscrowHeld: false), .none)
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: "local", guardEscrowMode: "local", localEscrowHeld: true), .none)
        XCTAssertEqual(GuardReconnect.decide(savedDeviceID: "", guardEscrowMode: "local", localEscrowHeld: true), .reconnectLocal)
    }
}
