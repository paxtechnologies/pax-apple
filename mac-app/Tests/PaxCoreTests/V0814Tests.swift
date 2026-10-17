// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.14: one Settings screen; a device's details live on its page.
final class V0814Tests: XCTestCase {
    func testSettingsSectionsInOrderWithAdvancedLast() {
        // v0.8.18: Blocking (this Mac's switches) and Turning Pax off joined from Home.
        XCTAssertEqual(AppSettingsLayout.sections,
                       ["Blocking", "Pax Max", "Turning Pax off", "Accountability partner email", "Updates", "About",
                        "Advanced"])
        XCTAssertEqual(AppSettingsLayout.sections.last, AppSettingsLayout.advanced)
        XCTAssertEqual(Array(AppSettingsLayout.advancedItems.suffix(3)),
                       ["Where this Mac keeps its key", "Pax server", "For testers"])
    }

    func testMediaIsOneAlwaysBlockedRow() {
        XCTAssertEqual(DeviceDetails.mediaLabel, "Images and video on X and Bluesky")
        XCTAssertEqual(DeviceDetails.mediaValue, "Always blocked")
    }

    func testBlockedAppsShowACountNotATruncatedList() {
        XCTAssertEqual(DeviceDetails.appCount([]), "None")
        XCTAssertEqual(DeviceDetails.appCount(["Notes"]), "1 app")
        XCTAssertEqual(DeviceDetails.appCount(["Subway - UK & Ireland", "b", "C"]), "3 apps")
        XCTAssertEqual(DeviceDetails.appList(["c", "Subway - UK & Ireland", "b"]), "b\nc\nSubway - UK & Ireland")
    }

    func testSetUpNoteIsPlain() {
        XCTAssertTrue(DeviceDetails.setUpChoicesNote.contains("set it up again"))
    }

    func testBrowserRulesNotice() {
        XCTAssertNil(BrowserRulesNotice.text(browser: "Chrome", missing: []))
        let one = BrowserRulesNotice.text(browser: "Chrome", missing: ["Momentum"]) ?? ""
        XCTAssertTrue(one.contains("Momentum shows as blocked"))
        XCTAssertTrue(one.contains("Your protection is unchanged"))
        let status = try? JSONDecoder().decode(GuardClient.Status.self, from: Data("""
        {"version":"0.8.14","escrow_mode":"local","browser_rules":{"browser":"Chrome","outdated":true,"missing":["Momentum"]}}
        """.utf8))
        XCTAssertEqual(status?.browser_rules?.missing, ["Momentum"])
        let old = try? JSONDecoder().decode(GuardClient.Status.self, from: Data("""
        {"version":"0.8.13","escrow_mode":"local"}
        """.utf8))
        XCTAssertNotNil(old)
        XCTAssertNil(old?.browser_rules)
    }
}
