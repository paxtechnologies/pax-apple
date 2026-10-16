// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.7: the "Ads and trackers" switch on Home works live on local escrow
/// (pax-guard's state/settings.json), stays on the server for server escrow, and is
/// shown as a set-up choice (not a dead switch) with a pax-guard older than 0.8.7.
final class V087Tests: XCTestCase {

    func testAdsSwitchGoesStraightToPaxGuard() async throws {
        let t = FakeGuardTransport([
            "settings.set": #"{"ok": true, "settings": {"youtube_restricted": true, "youtube_available": true, "adblock": false, "adblock_local": true, "changed_at": 1800000000}}"#,
        ])
        let s = try await GuardClient(transport: t).setAdblock(false)
        XCTAssertEqual(s.adblock, false)
        XCTAssertEqual(s.adblock_local, true)
        XCTAssertEqual(t.sent.last?["cmd"] as? String, "settings.set")
        XCTAssertEqual(t.sent.last?["adblock"] as? Bool, false)
        XCTAssertNil(t.sent.last?["youtube_restricted"])          // only the ads switch is sent
    }

    func testServerEscrowRefusalKeepsItsCode() async {
        let t = FakeGuardTransport(["settings.set": #"{"ok": false, "code": "PAX-ESCROW-009", "error": "this Mac's ad setting is on the Pax server"}"#])
        do {
            _ = try await GuardClient(transport: t).setAdblock(true)
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-ESCROW-009")
        }
    }

    func testStatusCarriesTheAdsSetting() async throws {
        let t = FakeGuardTransport(["status": #"{"ok": true, "version": "0.8.7", "escrow_mode": "local", "settings": {"youtube_restricted": true, "youtube_available": true, "adblock": false, "adblock_local": true}}"#])
        let s = try await GuardClient(transport: t).status()
        XCTAssertEqual(s.settings?.adblock, false)
        XCTAssertEqual(AdblockSwitch.mode(localEscrow: true, settings: s.settings), .guardLive)
    }

    func testWhereTheSwitchGoes() {
        let new = GuardClient.Settings(youtube_restricted: true, adblock: true, adblock_local: true)
        let old = GuardClient.Settings(youtube_restricted: true)               // 0.8.6 pax-guard
        XCTAssertEqual(AdblockSwitch.mode(localEscrow: true, settings: new), .guardLive)
        XCTAssertEqual(AdblockSwitch.mode(localEscrow: true, settings: old), .setUpOnly)
        XCTAssertEqual(AdblockSwitch.mode(localEscrow: true, settings: nil), .setUpOnly)
        XCTAssertEqual(AdblockSwitch.mode(localEscrow: false, settings: new), .server)
        XCTAssertEqual(AdblockSwitch.mode(localEscrow: false, settings: nil), .server)
    }

    func testOlderPaxGuardSettingsStillDecode() async throws {
        let t = FakeGuardTransport(["settings.get": #"{"ok": true, "settings": {"youtube_restricted": false, "youtube_available": true, "changed_at": null}}"#])
        let s = try await GuardClient(transport: t).settings()
        XCTAssertEqual(s, GuardClient.Settings(youtube_restricted: false))
        XCTAssertNil(s.adblock)
    }

    func testGuardConfigStillCarriesTheSetUpChoice() throws {
        let off = GuardConfigFile(server_url: "s", guard_token: "", profile_identifier: "p", user: "u",
                                  resolver_host: "r", adblock_default: false)
        XCTAssertTrue(String(decoding: try off.json(), as: UTF8.self).contains(#""adblock_default":false"#))
    }

    // MARK: Blocked apps (v0.8.7)

    func testNeverBlockedApps() {
        XCTAssertEqual(AppBlockRules.protectedReason(bundleID: "com.apple.Preferences"), "one of Apple's own apps")
        XCTAssertEqual(AppBlockRules.protectedReason(bundleID: "org.paxmobile.pax"), "Pax itself")
        XCTAssertEqual(AppBlockRules.protectedReason(bundleID: "com.8bit.bitwarden"), "a password manager")
        XCTAssertEqual(AppBlockRules.protectedReason(bundleID: "com.example.vault", name: "1Password Beta"),
                       "a password manager")
        XCTAssertNil(AppBlockRules.protectedReason(bundleID: "com.example.game", name: "Game"))
    }

    func testTypedBundleIDs() {
        XCTAssertEqual(AppBlockRules.checkTyped(" com.example.app "), .success("com.example.app"))
        XCTAssertEqual(AppBlockRules.checkTyped("not an id"), .failure(.notAnAppID))
        XCTAssertEqual(AppBlockRules.checkTyped("example"), .failure(.notAnAppID))
        XCTAssertEqual(AppBlockRules.checkTyped("com..app"), .failure(.notAnAppID))
        XCTAssertEqual(AppBlockRules.checkTyped("com.apple.MobileSMS"), .failure(.neverBlocked("one of Apple's own apps")))
        XCTAssertEqual(AppBlockRules.customCount(["a.b", "A.B", "com.nordvpn.NordVPN"], paxBlocked: ["com.nordvpn.nordvpn"]), 1)
    }

    func testIPhoneAppListFromTheHelper() async throws {
        let runner = FakeHelperRunner()
        runner.replies["apps"] = #"{"ok":true,"apps":[{"bundle_id":"com.example.game","name":"Game","version":"2.1","pax_blocks":false,"can_block":true,"why_not":"","icon":"/tmp/i/com.example.game.png"},{"bundle_id":"com.nordvpn.NordVPN","name":"NordVPN","version":"","pax_blocks":true,"can_block":true,"why_not":""},{"bundle_id":"com.8bit.bitwarden","name":"Bitwarden","version":"","pax_blocks":false,"can_block":false,"why_not":"a password manager"}],"pax_blocked":["com.nordvpn.NordVPN"],"max_custom":200,"icons":1}"#
        let sup = KeepDataSupervisor(helper: PaxDeviceHelper(script: URL(fileURLWithPath: "/x/pax_device.py"),
                                                             python: URL(fileURLWithPath: "/usr/bin/python3"),
                                                             runner: runner, assumeAvailable: true))
        let list = try await sup.installedApps(udid: "U1", iconsDirectory: URL(fileURLWithPath: "/tmp/i"))
        XCTAssertEqual(list.apps.count, 3)
        XCTAssertEqual(list.apps[0].iconPath, "/tmp/i/com.example.game.png")
        XCTAssertTrue(list.apps[1].paxBlocks)
        XCTAssertFalse(list.apps[2].canBlock)
        XCTAssertEqual(list.filtered("nord").map(\.bundleID), ["com.nordvpn.NordVPN"])
        XCTAssertEqual(list.maxCustom, 200)
        let args = runner.calls.last?.args ?? []
        XCTAssertEqual(Array(args.dropFirst()), ["apps", "--udid", "U1", "--icons-dir", "/tmp/i"])
    }

    func testAppListFailureKeepsItsCode() async {
        let runner = FakeHelperRunner()
        runner.replies["apps"] = #"{"ok":false,"code":"apps_failed","error":"PAX-IOS-012: couldn't read the iPhone's apps (ConnectionError)"}"#
        let sup = KeepDataSupervisor(helper: PaxDeviceHelper(script: URL(fileURLWithPath: "/x/pax_device.py"),
                                                             python: URL(fileURLWithPath: "/usr/bin/python3"),
                                                             runner: runner, assumeAvailable: true))
        do {
            _ = try await sup.installedApps(udid: "U1")
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-IOS-012")
        }
    }

    func testChosenAppsReachTheProfileGenerator() {
        let script = URL(fileURLWithPath: "/R/profile/make_profile.py")
        let args = ProfileGenerator.arguments(script: script, platform: "ios", out: URL(fileURLWithPath: "/tmp/p"),
                                              escrow: URL(fileURLWithPath: "/tmp/e"), filter: .family, resolverURL: nil,
                                              blockApps: ["com.example.game", "com.example.chat"], blockURLs: [])
        XCTAssertEqual(args.filter { $0 == "--block-app" }.count, 2)
        XCTAssertTrue(args.contains("com.example.chat"))
        XCTAssertEqual(SetupConfiguration(customBlockedApps: ["com.example.game"]).customBlockedApps, ["com.example.game"])
    }

    func testMacBlockedAppsGoToPaxGuard() async throws {
        let view = #"{"now": 1, "apps": [{"bundle_id": "com.example.game", "name": "Game", "team_id": "ABCDE12345", "added_at": 1, "pending_removal": null}], "pending": [], "limits": {"max_apps": 200, "delay_seconds": 259200}}"#
        let t = FakeGuardTransport([
            "apps.add": #"{"ok": true, "bundle_id": "com.example.game", "created": true, "apps": \#(view)}"#,
            "apps.unblock": #"{"ok": true, "request": {"request_id": "r1", "action": "unblock_app", "domain": "com.example.game", "display_domain": "Game", "status": "pending", "created_at": 1, "effective_at": 2, "seconds_remaining": 1}, "apps": \#(view)}"#,
        ])
        let g = GuardClient(transport: t)
        let v = try await g.addBlockedApp(path: "/Applications/Game.app")
        XCTAssertEqual(v.apps.first?.name, "Game")
        XCTAssertEqual(t.sent.last?["path"] as? String, "/Applications/Game.app")
        _ = try await g.unblockApp(bundleID: "com.example.game")
        XCTAssertEqual(t.sent.last?["cmd"] as? String, "apps.unblock")
        XCTAssertEqual(t.sent.last?["bundle_id"] as? String, "com.example.game")
    }

    func testRefusedMacAppKeepsItsCode() async {
        let t = FakeGuardTransport(["apps.add": #"{"ok": false, "code": "PAX-MAC-016", "error": "Bitwarden can't be blocked: it's a password manager"}"#])
        do {
            _ = try await GuardClient(transport: t).addBlockedApp(path: "/Applications/Bitwarden.app")
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-MAC-016")
        }
    }

    func testMacAppScannerReadsInfoPlists() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pax-apps-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        func make(_ folder: String, _ plist: [String: Any]) throws {
            let c = dir.appendingPathComponent("\(folder).app/Contents")
            try FileManager.default.createDirectory(at: c, withIntermediateDirectories: true)
            let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            try data.write(to: c.appendingPathComponent("Info.plist"))
        }
        try make("Zed Game", ["CFBundleIdentifier": "com.example.zed", "CFBundleName": "Zed Game"])
        try make("Bitwarden", ["CFBundleIdentifier": "com.bitwarden.desktop", "CFBundleName": "Bitwarden"])
        try make("Notes", ["CFBundleIdentifier": "com.apple.Notes"])
        try make("Broken", [:])
        let apps = MacAppScanner.installedApps(directories: [dir])
        XCTAssertEqual(apps.map(\.name), ["Bitwarden", "Notes", "Zed Game"])
        XCTAssertEqual(apps.first { $0.bundleID == "com.example.zed" }?.whyNot, nil)
        XCTAssertEqual(apps.first { $0.bundleID == "com.bitwarden.desktop" }?.whyNot, "a password manager")
        XCTAssertEqual(apps.first { $0.bundleID == "com.apple.Notes" }?.whyNot, "one of Apple's own apps")
    }
}
