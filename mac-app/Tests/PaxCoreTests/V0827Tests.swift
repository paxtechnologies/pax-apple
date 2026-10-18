// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.27: the Support ID sits with the turn-off controls, and only when a support code
/// could work there: verified support release switched on, device not turned off.
final class V0827Tests: XCTestCase {
    private let id = "ABCD-EFGH-IJKL-MNOP"

    private func status(supportRelease: String?, supportID: String? = "ABCD-EFGH-IJKL-MNOP",
                        releasedAt: String = "null", removal: String = "null",
                        extra: String = "") throws -> EscrowClient.DeviceStatus {
        var json = #"{"device_id":"d1","name":"Test iPhone","platform":"ios","installed_at":1,"grace_until":2,"#
            + #""in_grace_period":false,"removal_request":"# + removal + #","released_at":"# + releasedAt
        if let sid = supportID { json += ",\"support_id\":\"" + sid + "\"" }
        if let sr = supportRelease { json += #","support_release":"# + sr }
        json += extra + "}"
        return try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(json.utf8))
    }

    private let on = #"{"allowed":true,"pending_on_at":null,"telling_partner":false}"#
    private let off = #"{"allowed":false,"pending_on_at":null,"telling_partner":false}"#
    private let turningOn = #"{"allowed":false,"pending_on_at":1800000000,"telling_partner":false}"#

    func testShownWhenSwitchOn() throws {
        XCTAssertEqual(SupportIDPlacement.visibleID(try status(supportRelease: on)), id)
        // This Mac (pax-guard status has the same shape).
        let mac = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data((
            #"{"device_id":"local","name":"This Mac","platform":"mac","installed_at":1,"grace_until":2,"#
            + #""in_grace_period":false,"released_at":null,"removal_request":null,"support_id":"ABCD-EFGH-IJKL-MNOP","#
            + #""support_release":{"allowed":true,"pending_on_at":null}}"#).utf8))
        XCTAssertEqual(SupportIDPlacement.visibleID(mac), id)
    }

    func testHiddenWhenSwitchOffOrNotYetOn() throws {
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: off)))
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: turningOn)))   // still in its wait
        // Set up before 0.8.15 / an older server: no switch in the status at all.
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: nil)))
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: nil, supportID: nil)))
        // Switch on but no ID sent: nothing to show.
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: on, supportID: nil)))
        XCTAssertNil(SupportIDPlacement.visibleID(nil))
    }

    func testHiddenWhenTurnedOff() throws {
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: on, releasedAt: "5")))
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: on, extra: #","released":true"#)))
        // The caller knows it's off (this Mac's released phase, a phone's password showing).
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: on), turnedOff: true))
        XCTAssertNil(SupportIDPlacement.visibleID(supportID: id, supportRelease: nil, turnedOff: false))
        // A revealed removal request counts as turned off too (PhoneStatus.isReleased).
        let req = #"{"request_id":"r1","kind":"standard","status":"%@","unlock_at":1,"seconds_remaining":0,"can_reveal":true}"#
        XCTAssertNil(SupportIDPlacement.visibleID(try status(supportRelease: on,
                                                             removal: req.replacingOccurrences(of: "%@", with: "revealed"))))
        // A running turn-off wait isn't "off": the ID stays with the turn-off controls.
        XCTAssertEqual(SupportIDPlacement.visibleID(try status(supportRelease: on,
                                                               removal: req.replacingOccurrences(of: "%@", with: "pending"))), id)
    }

    func testWordingIsShortAndCalm() {
        XCTAssertEqual(SupportIDPlacement.label(id), "Support ID: ABCD-EFGH-IJKL-MNOP")
        XCTAssertEqual(VerifiedSupportRelease.supportIDLine,
                       "Share this with Pax support if you can't turn Pax off the usual way.")
        XCTAssertFalse(VerifiedSupportRelease.supportIDLine.lowercased().contains("unlock"))
    }

    func testSupportIDLeftAdvanced() {
        XCTAssertFalse(AppSettingsLayout.advancedItems.contains("Support ID"))
        XCTAssertFalse(AppSettingsLayout.advancedItems.contains(VerifiedSupportRelease.supportIDLabel))
    }

    // MARK: support code paste (v0.8.27: tidied once, no per-keystroke work)

    private var groups: String { (0..<30).map { i in String(repeating: ["A", "B", "C", "D", "E", "F"][i % 6], count: 5) }
        .joined(separator: " ") }

    func testPastedCodeToleratesWhitespaceNewlinesAndLowerCase() {
        let tidy = VerifiedSupportRelease.cleaned("PAXS-" + groups)
        XCTAssertEqual(tidy, "PAXS-" + groups.replacingOccurrences(of: " ", with: ""))
        // Lower case, line breaks, tabs, non-breaking and zero-width spaces, quotes and a full stop from an email.
        let messy = "  \u{201C}paxs-" + groups.lowercased().replacingOccurrences(of: " ", with: "\n")
            .replacingOccurrences(of: "aaaaa", with: "aa\u{200B}a\u{00A0}aa\t") + ".\u{201D}\r\n"
        XCTAssertEqual(VerifiedSupportRelease.cleaned(messy), tidy)
        XCTAssertTrue(VerifiedSupportRelease.looksComplete(messy))
        // Typographic dashes read as "-"; tidying twice changes nothing.
        XCTAssertEqual(VerifiedSupportRelease.cleaned("PAXS\u{2013}AB\u{2014}"), "PAXS-AB-")
        XCTAssertEqual(VerifiedSupportRelease.cleaned(tidy), tidy)
        XCTAssertFalse(VerifiedSupportRelease.looksComplete("PAXS-" + String(groups.prefix(60))))
        XCTAssertFalse(VerifiedSupportRelease.looksComplete(" \n\t "))
    }

    func testTidyingALongPasteIsCheap() {
        // What the field does per change is at most one of these; 5,000 runs should take well under a second.
        let code = "paxs-" + groups.lowercased()
        let start = Date()
        var n = 0
        for _ in 0..<5_000 where VerifiedSupportRelease.looksComplete(code) { n += 1 }
        XCTAssertEqual(n, 5_000)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2.0)
    }

    // MARK: Blocked Sites / Apps lists only devices Pax is still on (v0.8.27)

    private func phone(_ id: String, settingUp: Bool = false, _ state: PhoneStatus.State?,
                       missing: Bool = false) -> BlockedPage.PhoneEntry {
        BlockedPage.PhoneEntry(id: id, settingUp: settingUp, state: state, missing: missing)
    }

    func testPhonesShownOnlyWhileProtectedWaitingOrSettingUp() {
        XCTAssertTrue(BlockedPage.phoneShown(phone("a", .protected)))
        XCTAssertTrue(BlockedPage.phoneShown(phone("a", .trial(until: 1))))
        XCTAssertTrue(BlockedPage.phoneShown(phone("a", .turningOff(secondsLeft: 60, notifying: false))))
        XCTAssertTrue(BlockedPage.phoneShown(phone("a", settingUp: true, nil)))
        XCTAssertTrue(BlockedPage.phoneShown(phone("a", .notCheckingIn(lastSeen: nil))))   // Pax may still be on it
        XCTAssertTrue(BlockedPage.phoneShown(phone("a", nil)))          // no server answer yet: keep last known
        XCTAssertFalse(BlockedPage.phoneShown(phone("a", .turnedOff)))
        XCTAssertFalse(BlockedPage.phoneShown(phone("a", nil, missing: true)))   // retired / not on the account
    }

    func testSubjectSkipsTurnedOffAndFallsBack() {
        let off = phone("p1", .turnedOff)
        let on = phone("p2", .protected)
        // The picked phone while Pax is on it.
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: "p2", phones: [off, on], macShown: true), .phone(id: "p2"))
        // Picked phone turned off: this Mac, then the next phone still on, then nothing.
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: "p1", phones: [off, on], macShown: true), .mac)
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: "p1", phones: [off, on], macShown: false), .phone(id: "p2"))
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: "p1", phones: [off], macShown: false), .noDevice)
        // Removed from the list (no record) or retired (missing): gone.
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: "gone", phones: [], macShown: false), .noDevice)
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: "p3", phones: [phone("p3", nil, missing: true)],
                                           macShown: false), .noDevice)
        // This Mac picked: itself while Pax is on it.
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: nil, phones: [on], macShown: true), .mac)
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: nil, phones: [on], macShown: false), .phone(id: "p2"))
    }

    func testMacLeavesThePageWhenReleasedOrRemoved() {
        XCTAssertTrue(BlockedPage.macShown(hasDevice: true, released: false, removed: false))
        XCTAssertFalse(BlockedPage.macShown(hasDevice: true, released: true, removed: false))
        XCTAssertFalse(BlockedPage.macShown(hasDevice: false, released: false, removed: true))
        XCTAssertFalse(BlockedPage.macShown(hasDevice: false, released: false, removed: false))
        XCTAssertEqual(BlockedPage.subject(selectedPhoneID: nil, phones: [],
                                           macShown: BlockedPage.macShown(hasDevice: false, released: false,
                                                                          removed: true)), .noDevice)
        XCTAssertFalse(BlockedPage.emptyTitle.isEmpty)
        XCTAssertFalse(BlockedPage.emptyLine.lowercased().contains("unlock"))
    }
}
