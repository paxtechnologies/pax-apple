// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.20: macOS 12 Monterey. The settings app and its profiles pane follow the Mac's version.
final class V0820Tests: XCTestCase {
    func testMontereyNamesSystemPreferencesAndItsProfilesPane() {
        let p = SystemSettingsPlace(macOSMajor: 12)
        XCTAssertEqual(p.appName, "System Preferences")
        XCTAssertEqual(p.profilesPath, "Profiles")
        XCTAssertEqual(p.profilesPaneURL, "x-apple.systempreferences:com.apple.preferences.configurationprofiles")
        XCTAssertEqual(p.usersPath, "System Preferences › Users & Groups")
        XCTAssertEqual(MacLockdownCommands.openDeviceManagementSettings(p).1, [p.profilesPaneURL])
    }

    func testVenturaAndLaterKeepSystemSettings() {
        for (major, path) in [(13, "Privacy & Security › Profiles"), (14, "Privacy & Security › Profiles"),
                              (15, "General › Device Management"), (26, "General › Device Management")] {
            let p = SystemSettingsPlace(macOSMajor: major)
            XCTAssertEqual(p.appName, "System Settings")
            XCTAssertEqual(p.profilesPath, path)
            XCTAssertEqual(p.profilesPaneURL, "x-apple.systempreferences:com.apple.Profiles-Settings.extension")
            XCTAssertEqual(MacLockdownCommands.openDeviceManagementSettings(p).0, "/usr/bin/open")
        }
    }

    func testProfileErrorExplainsBothPlaces() {
        let info = PaxErrorCatalog.info("PAX-PROFILE-002")
        XCTAssertTrue(info.action.contains("System Preferences > Profiles"))
        XCTAssertTrue(info.action.contains("System Settings > Device Management"))
    }
}
