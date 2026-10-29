// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.36: the calm note beside System Settings' "Privacy & Security is trying to modify your system
/// settings" administrator dialog (PaxCore/PrivacyPrompts.swift). The install panel's rules (V0834/V0835)
/// stay as they were.
final class V0836Tests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 4_000_000)
    private let dialog = AdminPromptHelper.WindowInfo(number: 11, ownerName: "SecurityAgent", ownerBundleID: nil,
                                                      ownerPath: nil,
                                                      bounds: HelperRect(x: 500, y: 300, width: 420, height: 260),
                                                      alpha: 1, layer: 1000)
    private func win(_ n: Int, owner: String?, bundle: String? = nil, layer: Int = 0, alpha: Double = 1,
                     w: Double = 700, h: Double = 500) -> AdminPromptHelper.WindowInfo {
        .init(number: n, ownerName: owner, ownerBundleID: bundle, ownerPath: nil,
              bounds: HelperRect(x: 100, y: 100, width: w, height: h), alpha: alpha, layer: layer, ownerPID: 42)
    }

    func testWording() {
        XCTAssertEqual(PrivacyPromptHelper.title, "Changing a privacy setting needs an administrator.")
        XCTAssertEqual(PrivacyPromptHelper.body, "On this Mac, ask someone you trust to type their password.")
        XCTAssertEqual(PrivacyPromptHelper.okButton, "OK")
        XCTAssertEqual(PrivacyPromptHelper.requesterLine("Swoop"), "Swoop wants a privacy permission.")
        // Calm and honest: no offer to grant, change or switch anything off.
        let all = [PrivacyPromptHelper.title, PrivacyPromptHelper.body, PrivacyPromptHelper.okButton,
                   PrivacyPromptHelper.requesterLine("Swoop")].joined(separator: " ").lowercased()
        for word in ["allow", "grant", "turn off", "switch off", "remove pax", "disable", "tcc", "bypass"] {
            XCTAssertFalse(all.contains(word), word)
        }
    }

    func testSystemSettingsIsRecognised() {
        XCTAssertTrue(PrivacyPromptHelper.isSystemSettings(bundleID: "com.apple.systempreferences"))
        XCTAssertTrue(PrivacyPromptHelper.isSystemSettings(bundleID: "com.apple.SystemPreferences"))
        XCTAssertTrue(PrivacyPromptHelper.isSystemSettings(bundleID: "com.apple.settings.PrivacySecurity.extension"))
        XCTAssertTrue(PrivacyPromptHelper.isSystemSettings(ownerName: "System Settings", bundleID: nil))
        XCTAssertTrue(PrivacyPromptHelper.isSystemSettings(ownerName: "System Preferences", bundleID: nil))
        XCTAssertFalse(PrivacyPromptHelper.isSystemSettings(bundleID: "com.apple.finder"))
        XCTAssertFalse(PrivacyPromptHelper.isSystemSettings(bundleID: "com.apple.installer"))
        XCTAssertFalse(PrivacyPromptHelper.isSystemSettings(bundleID: "com.swoopkey.swoop"))
        XCTAssertFalse(PrivacyPromptHelper.isSystemSettings(bundleID: nil))
        XCTAssertFalse(PrivacyPromptHelper.isSystemSettings(ownerName: "Finder", bundleID: nil))
    }

    func testSettingsContextFromTheAppInFrontOrTheWindowBehindTheDialog() {
        let settingsWin = win(2, owner: "System Settings")
        let finderWin = win(3, owner: "Finder")
        // Pax saw the app in front: that decides.
        XCTAssertTrue(PrivacyPromptHelper.isSettingsContext(previousApp: "com.apple.systempreferences", behindDialog: nil))
        XCTAssertFalse(PrivacyPromptHelper.isSettingsContext(previousApp: "com.apple.finder", behindDialog: settingsWin))
        // Pax was just started for the dialog: the window it sits on decides.
        XCTAssertTrue(PrivacyPromptHelper.isSettingsContext(previousApp: nil, behindDialog: settingsWin))
        XCTAssertTrue(PrivacyPromptHelper.isSettingsContext(previousApp: "", behindDialog: settingsWin))
        XCTAssertFalse(PrivacyPromptHelper.isSettingsContext(previousApp: nil, behindDialog: finderWin))
        XCTAssertFalse(PrivacyPromptHelper.isSettingsContext(previousApp: nil, behindDialog: nil))
    }

    func testAppBehindDialogSkipsTheDialogMenuBarPaxAndTinyWindows() {
        let windows = [
            win(1, owner: "Window Server", layer: 25, w: 1440, h: 24),       // menu bar
            dialog,
            win(4, owner: "Pax", bundle: "org.paxmobile.pax"),
            win(5, owner: "Swoop", w: 40, h: 20),                             // a tiny status item
            win(6, owner: nil, bundle: "com.apple.systempreferences"),        // macOS 26: no owner name
            win(7, owner: "Finder"),
        ]
        let behind = PrivacyPromptHelper.appBehindDialog(windows, paxBundleID: "org.paxmobile.pax")
        XCTAssertEqual(behind?.number, 6)
        XCTAssertTrue(PrivacyPromptHelper.isSettingsContext(previousApp: nil, behindDialog: behind))
        XCTAssertNil(PrivacyPromptHelper.appBehindDialog([dialog], paxBundleID: nil))
    }

    func testShowsOnlyForStandardUsersOnProtectedMacsOncePerDialogAndRateLimited() {
        func show(protected: Bool = true, admin: Bool = false, settings: Bool = true, shown: Set<Int> = [],
                  last: Date? = nil) -> Bool {
            PrivacyPromptHelper.shouldShow(dialog: dialog, now: t0, lastShown: last, shownWindows: shown,
                                           protected: protected, isAdmin: admin, settingsContext: settings)
        }
        XCTAssertTrue(show())
        XCTAssertFalse(show(admin: true))                     // administrators see nothing
        XCTAssertFalse(show(protected: false))                // only Macs Pax protects
        XCTAssertFalse(show(settings: false))                 // not System Settings: the install rules apply
        XCTAssertFalse(show(shown: [11]))                     // once per dialog
        XCTAssertFalse(show(last: t0.addingTimeInterval(-30)))
        XCTAssertFalse(show(last: t0.addingTimeInterval(-119)))
        XCTAssertTrue(show(last: t0.addingTimeInterval(-121)))
        XCTAssertEqual(PrivacyPromptHelper.rateLimit, AdminPromptHelper.rateLimit)
    }

    func testTheInstallPanelIsUnchangedForInstallersAndStillQuietForSystemSettings() {
        func install(prev: String?, assume: Bool = false) -> Bool {
            AdminPromptHelper.shouldShow(dialog: dialog, now: t0, lastShown: nil, shownWindows: [], protected: true,
                                         isAdmin: false, previousApp: prev, assumeInstallWhenUnknown: assume)
        }
        XCTAssertTrue(install(prev: "com.apple.finder"))
        XCTAssertTrue(install(prev: "com.swoopkey.swoop"))
        XCTAssertTrue(install(prev: "org.mozilla.firefox"))
        XCTAssertTrue(install(prev: nil, assume: true))
        XCTAssertFalse(install(prev: "com.apple.systempreferences"))
        XCTAssertFalse(install(prev: "com.apple.systempreferences", assume: true))
        // A third-party installer in front is never a privacy context.
        XCTAssertFalse(PrivacyPromptHelper.isSettingsContext(previousApp: "com.swoopkey.swoop", behindDialog: nil))
        // WindowInfo's new fields default so older call sites are unchanged.
        let old = AdminPromptHelper.WindowInfo(number: 1, ownerName: "SecurityAgent", ownerBundleID: nil, ownerPath: nil,
                                               bounds: HelperRect(x: 0, y: 0, width: 400, height: 200), alpha: 1)
        XCTAssertEqual(old.layer, 0)
        XCTAssertNil(old.ownerPID)
    }

    func testRequesterIsTheNewestRunningThirdPartyApp() {
        typealias R = PrivacyPromptHelper.RecentApp
        let pax = "org.paxmobile.pax"
        let recent = [
            R(bundleID: "com.apple.systempreferences", name: "System Settings", at: t0.addingTimeInterval(-5), running: true),
            R(bundleID: "com.swoopkey.swoop", name: "Swoop", at: t0.addingTimeInterval(-20), running: true),
            R(bundleID: "org.mozilla.firefox", name: "Firefox", at: t0.addingTimeInterval(-200), running: true),
            R(bundleID: pax, name: "Pax", at: t0.addingTimeInterval(-1), running: true),
        ]
        XCTAssertEqual(PrivacyPromptHelper.requesterName(recent, now: t0, paxBundleID: pax), "Swoop")
        // Quit since: not named; the next one still counts.
        let quit = recent.map { $0.bundleID == "com.swoopkey.swoop"
            ? R(bundleID: $0.bundleID, name: $0.name, at: $0.at, running: false) : $0 }
        XCTAssertEqual(PrivacyPromptHelper.requesterName(quit, now: t0, paxBundleID: pax), "Firefox")
        // Too long ago: Pax can't tell, so no name.
        let old = [R(bundleID: "com.swoopkey.swoop", name: "Swoop", at: t0.addingTimeInterval(-301), running: true)]
        XCTAssertNil(PrivacyPromptHelper.requesterName(old, now: t0, paxBundleID: pax))
        // Only Apple's apps and Pax: no name.
        XCTAssertNil(PrivacyPromptHelper.requesterName(Array(recent.prefix(1)) + [recent[3]], now: t0, paxBundleID: pax))
        XCTAssertNil(PrivacyPromptHelper.requesterName([], now: t0, paxBundleID: pax))
        // Pax's other bundle IDs never count.
        let paxOther = [R(bundleID: "org.paxpeace.pax", name: "Pax", at: t0, running: true)]
        XCTAssertNil(PrivacyPromptHelper.requesterName(paxOther, now: t0, paxBundleID: pax))
    }

    func testDisplayNameIsOneShortPlainLine() {
        XCTAssertEqual(PrivacyPromptHelper.displayName("Swoop"), "Swoop")
        XCTAssertEqual(PrivacyPromptHelper.displayName("  Swoop  "), "Swoop")
        XCTAssertEqual(PrivacyPromptHelper.displayName("Swoop.app"), "Swoop")
        XCTAssertEqual(PrivacyPromptHelper.displayName("Visual\nStudio   Code"), "Visual Studio Code")
        XCTAssertEqual(PrivacyPromptHelper.displayName("Bad\u{0007}Name"), "BadName")
        XCTAssertNil(PrivacyPromptHelper.displayName(String(repeating: "x", count: 33)))
        XCTAssertNotNil(PrivacyPromptHelper.displayName(String(repeating: "x", count: 32)))
        XCTAssertNil(PrivacyPromptHelper.displayName(""))
        XCTAssertNil(PrivacyPromptHelper.displayName("   "))
        XCTAssertNil(PrivacyPromptHelper.displayName(nil))
        XCTAssertNil(PrivacyPromptHelper.displayName("Pax"))
    }
}
