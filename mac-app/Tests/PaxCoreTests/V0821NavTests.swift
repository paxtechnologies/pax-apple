// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.21: no Home row in the sidebar; "Blocked sites / apps" says which device it's about.
final class V0821NavTests: XCTestCase {
    func testSidebarHasNoHomeRow() {
        XCTAssertFalse(AppNav.sidebarRows.contains("Home"))
        XCTAssertEqual(AppNav.sidebarRows, ["Blocked sites / apps", "Settings"])
        XCTAssertEqual(AppNav.blockedMenuTitle, "Blocked Sites / Apps")
        XCTAssertEqual(AppNav.backToHome, "Home")
    }

    func testDeviceLine() {
        XCTAssertEqual(BlockedPage.deviceLine(name: "Ruben's MacBook Air"), "Blocking on Ruben's MacBook Air")
        XCTAssertEqual(BlockedPage.deviceLine(name: "Kitchen iPad"), "Blocking on Kitchen iPad")
        XCTAssertEqual(BlockedPage.deviceLine(name: nil), "Blocking on this device")
        XCTAssertEqual(BlockedPage.deviceLine(name: "  "), "Blocking on this device")
    }

    func testSitesReach() {
        XCTAssertEqual(BlockedPage.sitesReach(phoneSelected: false, macLocalList: true, macSyncOn: true), .allDevices)
        XCTAssertEqual(BlockedPage.sitesReach(phoneSelected: false, macLocalList: true, macSyncOn: false), .thisMacOnly)
        XCTAssertEqual(BlockedPage.sitesReach(phoneSelected: false, macLocalList: false, macSyncOn: nil), .allDevices)
        XCTAssertEqual(BlockedPage.sitesReach(phoneSelected: true, macLocalList: true, macSyncOn: false), .phonesNotThisMac)
        XCTAssertEqual(BlockedPage.sitesReach(phoneSelected: true, macLocalList: false, macSyncOn: nil), .allDevices)
        XCTAssertEqual(BlockedPage.sitesLine(.allDevices), "Sites: applies to all your devices.")
        XCTAssertTrue(BlockedPage.sitesLine(.thisMacOnly).hasPrefix("Sites: applies to this Mac only."))
    }

    func testAppsAreAlwaysPerDevice() {
        XCTAssertEqual(BlockedPage.appsLine(phone: false), "Apps: this Mac only.")
        XCTAssertEqual(BlockedPage.appsLine(phone: true), "Apps: this iPhone only, chosen at set-up.")
        XCTAssertEqual(BlockedPage.appsLine(phone: true, isIPad: true), "Apps: this iPad only, chosen at set-up.")
        for s in [BlockedPage.sitesLine(.allDevices), BlockedPage.sitesLine(.phonesNotThisMac),
                  BlockedPage.sitesLine(.thisMacOnly), BlockedPage.appsLine(phone: false)] {
            XCTAssertFalse(s.contains("!"), s)
        }
    }
}
