// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.34: Pax points the Standard user at Pax-approved installs: a mounted disk image with an
/// app brings up "Install <App>?", and macOS's administrator dialog gets a small "Pax can do it
/// for you" panel beside it. Dedupe, rate limit and routing rules.
final class V0834Tests: XCTestCase {
    private func vol(_ apps: [MountedAppPrompts.AppOnDisk], mount: String = "/Volumes/Writer",
                     image: String? = "/Users/alex/Downloads/Writer-3.2.dmg", local: Bool = true,
                     tm: Bool = false, id: String = "UUID-1") -> MountedAppPrompts.Volume {
        MountedAppPrompts.Volume(mountPoint: mount, imagePath: image, identity: id, isLocal: local,
                                 hasTimeMachineMarkers: tm, apps: apps)
    }

    private let writer = MountedAppPrompts.AppOnDisk(path: "/Volumes/Writer/Writer.app", name: "Writer",
                                                     bundleID: "com.example.Writer", version: "3.2")

    private func decide(_ v: MountedAppPrompts.Volume, installed: [String: String] = [:],
                        remembered: Set<String> = [], protected: Bool = true, admin: Bool = false)
        -> MountedAppPrompts.Decision {
        MountedAppPrompts.decide(v, protected: protected, isAdmin: admin, home: "/Users/alex",
                                 installedVersion: { installed[$0] }, remembered: remembered)
    }

    func testANewAppOnADiskImageAsksToInstallItOncePerDiskAppAndVersion() {
        guard case .prompt(let r, let key) = decide(vol([writer])) else { return XCTFail("no prompt") }
        XCTAssertEqual(r.title, "Install Writer?")
        XCTAssertEqual(r.path, "/Volumes/Writer/Writer.app")
        XCTAssertFalse(r.updateOnly)
        XCTAssertEqual(key, "UUID-1|com.example.writer|3.2")
        // dismissed (or installed): the same disk, app and version never asks again
        XCTAssertEqual(decide(vol([writer]), remembered: [key]), .skip("already offered"))
        // a new version on the same disk image name is a new offer
        let newer = MountedAppPrompts.AppOnDisk(path: writer.path, name: "Writer", bundleID: writer.bundleID,
                                                version: "3.3")
        if case .skip = decide(vol([newer]), remembered: [key]) { XCTFail("a new version should ask") }
        var list: [String] = []
        for i in 0..<250 { list = MountedAppPrompts.remember("k\(i)", in: list) }
        XCTAssertEqual(list.count, MountedAppPrompts.rememberLimit)
        XCTAssertEqual(list.last, "k249")
        XCTAssertEqual(MountedAppPrompts.remember("k249", in: list).count, MountedAppPrompts.rememberLimit)
    }

    func testAnInstalledAppIsAnUpdateOnlyWhenTheDiskHasANewerVersion() {
        guard case .prompt(let r, _) = decide(vol([writer]), installed: ["com.example.Writer": "3.1.9"]) else {
            return XCTFail("no prompt")
        }
        XCTAssertEqual(r.title, "Update Writer?")
        XCTAssertEqual(decide(vol([writer]), installed: ["com.example.Writer": "3.2"]), .skip("nothing new to install"))
        XCTAssertEqual(decide(vol([writer]), installed: ["com.example.Writer": "10.0"]), .skip("nothing new to install"))
        XCTAssertTrue(HelperVersion.isNewer("1.10", than: "1.9"))
        XCTAssertFalse(HelperVersion.isNewer("1.9", than: "1.10"))
        XCTAssertFalse(HelperVersion.isNewer("beta", than: "1.0"))
        XCTAssertFalse(HelperVersion.isNewer("2.0", than: "2.0.0"))
    }

    func testOnlyProtectedStandardMacsAndOnlyRealDiskImages() {
        XCTAssertEqual(decide(vol([writer]), protected: false), .skip("this Mac isn't protected"))
        XCTAssertEqual(decide(vol([writer]), admin: true), .skip("an administrator can install it themselves"))
        XCTAssertEqual(decide(vol([writer], local: false)), .skip("a network disk"))
        XCTAssertEqual(decide(vol([writer], tm: true)), .skip("a Time Machine disk"))
        XCTAssertEqual(decide(vol([writer], image: nil)), .skip("not a disk image"))                // a USB disk
        XCTAssertEqual(decide(vol([writer], image: "/Volumes/NAS/Mac.sparsebundle")), .skip("not a disk image"))
        XCTAssertEqual(decide(vol([writer], mount: "/")), .skip("not a mounted disk"))
        XCTAssertEqual(decide(vol([writer], mount: "/System/Volumes/Data")), .skip("not a mounted disk"))
        XCTAssertEqual(decide(vol([writer], mount: "/Volumes/.timemachine")), .skip("not a mounted disk"))
        XCTAssertEqual(decide(vol([])), .skip("nothing new to install"))
        XCTAssertTrue(MountedAppPrompts.isTimeMachine(topLevel: ["Backups.backupdb"]))
        XCTAssertTrue(MountedAppPrompts.isTimeMachine(topLevel: ["2026-10-28-101010.previous"]))
        XCTAssertFalse(MountedAppPrompts.isTimeMachine(topLevel: ["Writer.app", "Applications"]))
    }

    func testPaxsOwnDiskImageAndApplesAppsAreIgnored() {
        let pax = MountedAppPrompts.AppOnDisk(path: "/Volumes/Pax/Pax.app", name: "Pax",
                                              bundleID: "org.paxmobile.pax", version: "0.8.34")
        XCTAssertEqual(decide(vol([pax], mount: "/Volumes/Pax")), .skip("Pax's own disk image"))
        let renamed = MountedAppPrompts.AppOnDisk(path: "/Volumes/X/Calm.app", name: "Calm",
                                                  bundleID: "org.paxpeace.pax", version: "1")
        XCTAssertEqual(decide(vol([renamed, writer])), .skip("Pax's own disk image"))
        let apple = MountedAppPrompts.AppOnDisk(path: "/Volumes/X/Xcode.app", name: "Xcode",
                                                bundleID: "com.apple.dt.Xcode", version: "26")
        XCTAssertEqual(decide(vol([apple])), .skip("nothing new to install"))
    }

    func testSeveralAppsHandPaxGuardTheImageSoItAsksWhichOne() {
        let beta = MountedAppPrompts.AppOnDisk(path: "/Volumes/Writer/Writer Beta.app", name: "Writer Beta",
                                               bundleID: "com.example.writer.beta", version: "4.0")
        guard case .prompt(let r, let key) = decide(vol([writer, beta])) else { return XCTFail("no prompt") }
        XCTAssertEqual(r.path, "/Users/alex/Downloads/Writer-3.2.dmg")
        XCTAssertEqual(r.title, "Install Writer?")          // the disk's name
        XCTAssertEqual(decide(vol([writer, beta]), remembered: [key]), .skip("already offered"))
        // an image pax-guard wouldn't accept (outside home and /Volumes): the first app instead
        guard case .prompt(let r2, _) = decide(vol([writer, beta], image: "/private/tmp/w.dmg")) else {
            return XCTFail("no prompt")
        }
        XCTAssertEqual(r2.path, writer.path)
    }

    func testHdiutilInfoMapsMountPointsToImages() throws {
        let plist: [String: Any] = ["images": [
            ["image-path": "/Users/alex/Downloads/Writer.dmg",
             "system-entities": [["dev-entry": "/dev/disk4"], ["dev-entry": "/dev/disk4s1", "mount-point": "/Volumes/Writer"]]],
            ["image-path": "/Volumes/NAS/Backups.sparsebundle", "system-entities": [["mount-point": "/Volumes/.timemachine/x"]]],
            ["system-entities": [["mount-point": "/Volumes/Odd"]]],
        ]]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        let map = MountedAppPrompts.imagesByMountPoint(data)
        XCTAssertEqual(map["/Volumes/Writer"], "/Users/alex/Downloads/Writer.dmg")
        XCTAssertEqual(map["/Volumes/.timemachine/x"], "/Volumes/NAS/Backups.sparsebundle")
        XCTAssertNil(map["/Volumes/Odd"])
        XCTAssertEqual(MountedAppPrompts.imagesByMountPoint(Data("junk".utf8)), [:])
    }

    // MARK: the panel beside the administrator dialog

    private func win(_ n: Int, owner: String?, bundle: String? = nil, path: String? = nil,
                     w: Double = 420, h: Double = 260, alpha: Double = 1) -> AdminPromptHelper.WindowInfo {
        AdminPromptHelper.WindowInfo(number: n, ownerName: owner, ownerBundleID: bundle, ownerPath: path,
                                     bounds: HelperRect(x: 500, y: 300, width: w, height: h), alpha: alpha)
    }

    func testOnlyASecurityAgentDialogCountsEvenWithoutOwnerNames() {
        XCTAssertEqual(AdminPromptHelper.authDialog(in: [win(1, owner: "Finder"), win(2, owner: "SecurityAgent")])?.number, 2)
        // macOS 26 may hide owner names without Screen Recording: the pid's bundle or path still say it
        XCTAssertEqual(AdminPromptHelper.authDialog(in: [win(3, owner: nil, bundle: "com.apple.SecurityAgent")])?.number, 3)
        XCTAssertEqual(AdminPromptHelper.authDialog(in: [win(4, owner: nil, path:
            "/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent")])?.number, 4)
        XCTAssertNil(AdminPromptHelper.authDialog(in: [win(5, owner: "SecurityAgent", w: 40, h: 20)]))   // not a dialog
        XCTAssertNil(AdminPromptHelper.authDialog(in: [win(6, owner: "SecurityAgent", alpha: 0)]))
        XCTAssertNil(AdminPromptHelper.authDialog(in: [win(7, owner: nil)]))
        XCTAssertNil(AdminPromptHelper.authDialog(in: [win(8, owner: "universalAccessAuthWarn")]))
    }

    func testThePanelIsRateLimitedOncePerDialogAndOnlyInAnInstallContext() {
        let d = win(10, owner: "SecurityAgent")
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        func show(_ now: Date, last: Date?, shown: Set<Int> = [], prev: String? = "com.apple.finder",
                  protected: Bool = true, admin: Bool = false) -> Bool {
            AdminPromptHelper.shouldShow(dialog: d, now: now, lastShown: last, shownWindows: shown,
                                         protected: protected, isAdmin: admin, previousApp: prev)
        }
        XCTAssertTrue(show(t0, last: nil))
        XCTAssertFalse(show(t0.addingTimeInterval(119), last: t0))
        XCTAssertTrue(show(t0.addingTimeInterval(120), last: t0))
        XCTAssertTrue(show(t0.addingTimeInterval(-5), last: t0))           // clock moved back
        XCTAssertFalse(show(t0.addingTimeInterval(500), last: t0, shown: [10]))   // the same dialog
        XCTAssertFalse(show(t0, last: nil, protected: false))
        XCTAssertFalse(show(t0, last: nil, admin: true))
        XCTAssertTrue(show(t0, last: nil, prev: "com.example.Writer"))      // a third-party updater
        for apple in ["com.apple.systempreferences", "com.apple.installer", "com.apple.Safari", "com.apple.keychainaccess"] {
            XCTAssertFalse(show(t0, last: nil, prev: apple), apple)
        }
        XCTAssertFalse(show(t0, last: nil, prev: "org.paxmobile.pax"))
        XCTAssertFalse(show(t0, last: nil, prev: nil))
        XCTAssertEqual(AdminPromptHelper.title, "Installing or updating an app?")
        XCTAssertEqual(AdminPromptHelper.body, "Pax can do it for you.")
        let words = (AdminPromptHelper.title + AdminPromptHelper.body + AdminPromptHelper.openButton
                     + AdminPromptHelper.notNowButton).lowercased()
        XCTAssertFalse(words.contains("password"))
        XCTAssertFalse(words.contains("administrator"))
    }

    func testThePanelSitsBesideTheDialogOnScreen() {
        let screen = HelperRect(x: 0, y: 25, width: 1440, height: 875)
        let mid = HelperRect(x: 500, y: 300, width: 420, height: 260)
        var p = AdminPromptHelper.panelOrigin(dialog: mid, screen: screen, panelWidth: 300, panelHeight: 120)
        XCTAssertEqual(p.x, 936); XCTAssertEqual(p.y, 300)                                  // right
        let rightEdge = HelperRect(x: 1100, y: 300, width: 320, height: 260)
        p = AdminPromptHelper.panelOrigin(dialog: rightEdge, screen: screen, panelWidth: 300, panelHeight: 120)
        XCTAssertEqual(p.x, 784)                                                            // left
        let wide = HelperRect(x: 20, y: 100, width: 1400, height: 260)
        p = AdminPromptHelper.panelOrigin(dialog: wide, screen: screen, panelWidth: 300, panelHeight: 120)
        XCTAssertEqual(p.y, 376); XCTAssertEqual(p.x, 570)                                  // below
        let tall = HelperRect(x: 20, y: 30, width: 1400, height: 860)
        p = AdminPromptHelper.panelOrigin(dialog: tall, screen: screen, panelWidth: 300, panelHeight: 120)
        XCTAssertGreaterThanOrEqual(p.y, screen.y); XCTAssertLessThanOrEqual(p.y + 120, screen.maxY)
    }

    func testOpenPaxGoesToTheWaitingSheetThenTheDiskThenAnUpdateThenSettings() {
        let waiting = AppInstallRequest(path: "/a.dmg", name: "A", isUpdate: false)
        let disk = AppInstallRequest(path: "/Volumes/B/B.app", name: "B", isUpdate: true)
        let card = GuardClient.DownloadedUpdate(path: "/Users/a/Library/Caches/x/C.app", name: "C",
                                                bundle_id: "com.c", version: "2", installed_version: "1")
        XCTAssertEqual(AdminPromptHelper.openTarget(pending: waiting, mounted: disk, cards: [card]), .sheet(waiting))
        XCTAssertEqual(AdminPromptHelper.openTarget(pending: nil, mounted: disk, cards: [card]), .sheet(disk))
        XCTAssertEqual(AdminPromptHelper.openTarget(pending: nil, mounted: nil, cards: [card]),
                       .sheet(AppUpdatePrompts.request(for: card)))
        XCTAssertEqual(AdminPromptHelper.openTarget(pending: nil, mounted: nil, cards: []), .installer)
    }
}
