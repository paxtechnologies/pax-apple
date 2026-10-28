// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.34 (Ruben, 28 Oct 2026): Pax opens at login, hidden, on a Mac it protects
/// (pax-guard's LaunchAgent passes --pax-login; guard/tests/test_v0834_login_agent.py).
final class V0834LoginTests: XCTestCase {
    func testOnlyTheLoginAgentsFlagMakesALoginLaunch() {
        XCTAssertTrue(LoginLaunch.isLoginLaunch(["/Applications/Pax.app/Contents/MacOS/Pax", "--pax-login"]))
        XCTAssertFalse(LoginLaunch.isLoginLaunch(["/Applications/Pax.app/Contents/MacOS/Pax"]))
        XCTAssertFalse(LoginLaunch.isLoginLaunch(["/Applications/Pax.app/Contents/MacOS/Pax", "-NSDocumentRevisionsDebugMode", "YES"]))
        // the executable's own path is never read as the flag
        XCTAssertFalse(LoginLaunch.isLoginLaunch(["--pax-login"]))
        XCTAssertFalse(LoginLaunch.isLoginLaunch([]))
    }

    func testALoginLaunchStaysHiddenUnlessAFileWasOpenedWithPax() {
        let login = ["Pax", "--pax-login"]
        XCTAssertTrue(LoginLaunch.startHidden(arguments: login, openedFiles: false))
        XCTAssertFalse(LoginLaunch.startHidden(arguments: login, openedFiles: true))
        XCTAssertFalse(LoginLaunch.startHidden(arguments: ["Pax"], openedFiles: false))
    }

    func testTheAgentNamesMatchPaxGuard() {
        XCTAssertEqual(LoginLaunch.argument, "--pax-login")
        XCTAssertEqual(LoginLaunch.agentLabel, "org.paxpeace.pax-login")
        XCTAssertEqual(LoginLaunch.agentPath, "/Library/LaunchAgents/org.paxpeace.pax-login.plist")
    }

    func testARepairedLoginItemReadsPlainly() {
        let s = SecurityNotices.sentence("changed:login_agent")
        XCTAssertEqual(s, "Pax's open-at-login item was removed or switched off, and Pax put it back")
        XCTAssertFalse(s.contains("PAX-"))
        XCTAssertFalse(s.contains("LaunchAgent"))
    }
}
