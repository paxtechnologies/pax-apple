// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.35: Pax opens itself for installs even when it isn't running (pax-guard and its StartOnMount
/// agent pass --pax-install-check), the admin-dialog panel after such a launch, the self-heal and
/// same-team wording (guard/tests/test_v0835_*.py cover pax-guard's side).
final class V0835Tests: XCTestCase {
    private let exe = "/Applications/Pax.app/Contents/MacOS/Pax"

    func testInstallCheckFlagAndReason() {
        XCTAssertTrue(InstallCheckLaunch.isInstallCheck([exe, "--pax-install-check"]))
        XCTAssertFalse(InstallCheckLaunch.isInstallCheck([exe]))
        XCTAssertFalse(InstallCheckLaunch.isInstallCheck(["--pax-install-check"]))   // the executable itself
        XCTAssertFalse(InstallCheckLaunch.isInstallCheck([exe, "--pax-login"]))
        XCTAssertNil(InstallCheckLaunch.reason([exe]))
        XCTAssertEqual(InstallCheckLaunch.reason([exe, "--pax-install-check"]), .mount)    // the mount agent
        XCTAssertEqual(InstallCheckLaunch.reason([exe, "--pax-install-check", "--pax-install-reason=auth"]), .auth)
        XCTAssertEqual(InstallCheckLaunch.reason([exe, "--pax-install-check", "--pax-install-reason=update"]), .update)
        XCTAssertEqual(InstallCheckLaunch.reason([exe, "--pax-install-check", "--pax-install-reason=zzz"]), .mount)
        // a reason without the flag is not an install check
        XCTAssertNil(InstallCheckLaunch.reason([exe, "--pax-install-reason=auth"]))
    }

    func testInstallChecksStartQuietWithoutADockIconUnlessAFileWasOpened() {
        let check = [exe, "--pax-install-check"]
        XCTAssertTrue(InstallCheckLaunch.startHidden(arguments: check, openedFiles: false))
        XCTAssertTrue(InstallCheckLaunch.startAsAccessory(arguments: check, openedFiles: false))
        XCTAssertFalse(InstallCheckLaunch.startHidden(arguments: check, openedFiles: true))
        XCTAssertFalse(InstallCheckLaunch.startAsAccessory(arguments: check, openedFiles: true))
        // 0.8.34's login launch still starts hidden, and keeps its Dock icon
        XCTAssertTrue(InstallCheckLaunch.startHidden(arguments: [exe, "--pax-login"], openedFiles: false))
        XCTAssertFalse(InstallCheckLaunch.startAsAccessory(arguments: [exe, "--pax-login"], openedFiles: false))
        // opened normally: shown normally
        XCTAssertFalse(InstallCheckLaunch.startHidden(arguments: [exe], openedFiles: false))
        XCTAssertFalse(InstallCheckLaunch.startAsAccessory(arguments: [exe], openedFiles: false))
    }

    func testAgentNamesMatchPaxGuard() {
        XCTAssertEqual(InstallCheckLaunch.argument, "--pax-install-check")
        XCTAssertEqual(InstallCheckLaunch.reasonPrefix, "--pax-install-reason=")
        XCTAssertEqual(InstallCheckLaunch.agentLabel, "org.paxpeace.pax-installs")
        XCTAssertEqual(InstallCheckLaunch.agentPath, "/Library/LaunchAgents/org.paxpeace.pax-installs.plist")
    }

    func testAnAuthLaunchTreatsAnUnknownFrontAppAsAnInstallForAMinute() {
        let t0 = Date(timeIntervalSince1970: 2_000_000)
        XCTAssertTrue(InstallCheckLaunch.assumeInstallContext(reason: .auth, launchedAt: t0, now: t0.addingTimeInterval(3)))
        XCTAssertFalse(InstallCheckLaunch.assumeInstallContext(reason: .auth, launchedAt: t0, now: t0.addingTimeInterval(61)))
        XCTAssertFalse(InstallCheckLaunch.assumeInstallContext(reason: .auth, launchedAt: t0, now: t0.addingTimeInterval(-1)))
        XCTAssertFalse(InstallCheckLaunch.assumeInstallContext(reason: .mount, launchedAt: t0, now: t0))
        XCTAssertFalse(InstallCheckLaunch.assumeInstallContext(reason: .update, launchedAt: t0, now: t0))
        XCTAssertFalse(InstallCheckLaunch.assumeInstallContext(reason: nil, launchedAt: t0, now: t0))
    }

    func testThePanelAfterAnAuthLaunch() {
        let d = AdminPromptHelper.WindowInfo(number: 9, ownerName: "SecurityAgent", ownerBundleID: nil, ownerPath: nil,
                                             bounds: HelperRect(x: 500, y: 300, width: 420, height: 260), alpha: 1)
        let t0 = Date(timeIntervalSince1970: 3_000_000)
        func show(prev: String?, assume: Bool, admin: Bool = false, shown: Set<Int> = [], last: Date? = nil) -> Bool {
            AdminPromptHelper.shouldShow(dialog: d, now: t0, lastShown: last, shownWindows: shown, protected: true,
                                         isAdmin: admin, previousApp: prev, assumeInstallWhenUnknown: assume)
        }
        XCTAssertTrue(show(prev: nil, assume: true))               // Pax just started for this dialog
        XCTAssertFalse(show(prev: nil, assume: false))             // 0.8.34 rule unchanged
        XCTAssertTrue(show(prev: "com.apple.finder", assume: false))   // Finder drag to Applications
        XCTAssertFalse(show(prev: "com.apple.systempreferences", assume: true))   // a known non-install app
        XCTAssertFalse(show(prev: nil, assume: true, admin: true))
        XCTAssertFalse(show(prev: nil, assume: true, shown: [9]))
        XCTAssertFalse(show(prev: nil, assume: true, last: t0.addingTimeInterval(-10)))   // rate limit holds
    }

    func testFinderDragWithADiskImageOpensOnItsSheet() {
        // Finder drag from a mounted disk image: "Open Pax" on the panel goes to that disk's sheet.
        let r = AppInstallRequest(path: "/Volumes/Writer/Writer.app", name: "Writer", isUpdate: false)
        XCTAssertEqual(AdminPromptHelper.openTarget(pending: nil, mounted: r, cards: []), .sheet(r))
        XCTAssertEqual(AdminPromptHelper.openTarget(pending: nil, mounted: nil, cards: []), .installer)
    }

    func testSecurityNoticesForTheNewTamperKinds() {
        XCTAssertEqual(SecurityNotices.sentence("changed:installs_agent"),
                       "Pax's install helper was removed or switched off, and Pax put it back")
        XCTAssertEqual(SecurityNotices.sentence("changed:pax_app"),
                       "Pax was removed from Applications, and Pax put it back")
    }

    func testErrorCodeWording() {
        let c023 = PaxErrorCatalog.info("PAX-MAC-023")
        XCTAssertEqual(c023.message, "Pax doesn't change this app.")
        XCTAssertTrue(c023.action.contains("If this is Pax itself, Pax puts it back in Applications for you."))
        XCTAssertTrue(c023.cause.contains("Pax's Team ID alone no longer counts"))
        XCTAssertTrue(PaxErrorCatalog.contains("PAX-GUARD-017"))
        XCTAssertTrue(PaxErrorCatalog.contains("PAX-GUARD-018"))
        XCTAssertEqual(PaxErrorCatalog.info("PAX-GUARD-018").message,
                       "Pax was removed from Applications, and Pax put it back.")
    }
}
