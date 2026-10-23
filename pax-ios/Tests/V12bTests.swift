// SPDX-License-Identifier: GPL-3.0-only
// 1.2 (24 Oct 2026): YouTube Restricted Mode as a wait-gated switch (server capability), the
// simplified Home and Settings, and blocked apps by bundle ID (installed or not). Fail closed.
import XCTest

final class YouTubeRestrictedTests: XCTestCase {
    private func cats(_ list: [CategoryInfo], now: Int = 1_000) -> CategoriesView { CategoriesView(now: now, categories: list) }
    private let rd = CategoryInfo(id: "remote_desktop", enabled: true, can_turn_off: true)

    func testTodaysServersShowNoSwitchAndStayOn() {
        // 0.8.31 / 0.8.32: /v1/categories has no youtube_restricted entry.
        let r = YouTubeRestricted.row(categories: cats([rd]), dnsSetting: true, child: false, macSetUp: false)
        XCTAssertEqual(r, YouTubeRow(value: .on, canSwitch: false, turningOff: nil))
        XCTAssertFalse(YouTubeRestricted.serverHasWait(cats([rd])))
        // Nothing read: on, no switch.
        XCTAssertEqual(YouTubeRestricted.row(categories: nil, dnsSetting: nil, child: false, macSetUp: false), .fallback)
        XCTAssertEqual(YouTubeRestricted.flip(.fallback, to: false), .nothing)
    }

    func testListedButNotTurnOffAbleIsNoSwitch() {
        let c = CategoryInfo(id: "youtube_restricted", enabled: true, can_turn_off: false)
        XCTAssertFalse(YouTubeRestricted.row(categories: cats([c]), dnsSetting: nil, child: false, macSetUp: false).canSwitch)
    }

    func testChildAlwaysOnMacReadOnly() {
        let c = CategoryInfo(id: "youtube_restricted", enabled: true, can_turn_off: true)
        let child = YouTubeRestricted.row(categories: cats([c]), dnsSetting: false, child: true, macSetUp: false)
        XCTAssertEqual(child.value, .alwaysOn)
        XCTAssertFalse(child.canSwitch)
        let mac = YouTubeRestricted.row(categories: cats([c]), dnsSetting: true, child: false, macSetUp: true)
        XCTAssertFalse(mac.canSwitch)
        XCTAssertEqual(mac.value, .on)
    }

    func testOffOnlyStartsTheWaitAndOnIsInstant() {
        let c = CategoryInfo(id: "youtube_restricted", enabled: true, can_turn_off: true)
        let on = YouTubeRestricted.row(categories: cats([c]), dnsSetting: nil, child: false, macSetUp: false)
        XCTAssertTrue(on.canSwitch)
        XCTAssertEqual(YouTubeRestricted.flip(on, to: false), .confirmTurnOff)
        XCTAssertEqual(YouTubeRestricted.flip(on, to: true), .nothing)
        let offCat = CategoryInfo(id: "youtube_restricted", enabled: false, can_turn_off: true)
        let off = YouTubeRestricted.row(categories: cats([offCat]), dnsSetting: nil, child: false, macSetUp: false)
        XCTAssertFalse(off.isOn)
        XCTAssertEqual(YouTubeRestricted.flip(off, to: true), .turnOnNow)
    }

    func testWaitingTurnOffIsStillOnUntilTheServerSaysOff() {
        let req = BlocklistRequestInfo(request_id: "r9", action: "youtube_restricted_off", domain: nil,
                                       status: "pending", effective_at: 5_000, seconds_remaining: 4_000)
        let c = CategoryInfo(id: "youtube_restricted", enabled: true, can_turn_off: true, pending: req)
        let r = YouTubeRestricted.row(categories: cats([c]), dnsSetting: nil, child: false, macSetUp: false)
        XCTAssertTrue(r.isOn)
        XCTAssertEqual(r.turningOff, YouTubeTurnOff(requestID: "r9", effectiveAt: 5_000))
        XCTAssertEqual(YouTubeRestricted.flip(r, to: false), .nothing)        // one request at a time
        // Remaining by the SERVER's clock: device 100 s behind the server.
        let left = YouTubeRestricted.remaining(r.turningOff!, serverOffset: 100, now: Date(timeIntervalSince1970: 1_000))
        XCTAssertEqual(left, 3_900, accuracy: 0.001)
    }

    func testDecodesTheServersAnswers() throws {
        let json = #"{"now": 10, "categories": [{"id": "bypass", "title": "x", "can_turn_off": false, "enabled": true, "pending": null},
          {"id": "youtube_restricted", "title": "YouTube Restricted Mode", "can_turn_off": true, "enabled": true,
           "pending": {"request_id": "a", "action": "youtube_restricted_off", "domain": null, "display_domain": null,
                       "status": "pending", "created_at": 1, "effective_at": 99, "seconds_remaining": 89}}], "delay_seconds": 604800}"#
        let v = try JSONDecoder().decode(CategoriesView.self, from: Data(json.utf8))
        XCTAssertTrue(YouTubeRestricted.serverHasWait(v))
        let s = try JSONDecoder().decode(DNSSettingsView.self,
                                         from: Data(#"{"now": 1, "settings": {"x_media": true, "youtube_restricted": true}}"#.utf8))
        XCTAssertEqual(s.settings.youtube_restricted, true)
    }

    func testWords() {
        XCTAssertEqual(PaxCopy.youtubeTurningOff("3 days"), "Turning off, available in 3 days")
        XCTAssertTrue(PaxCopy.youtubeOffBody(waitDays: 7, trusted: true).contains("emailed first"))
        XCTAssertTrue(PaxCopy.youtubeOffBody(waitDays: 7, trusted: true).contains("turn-off wait"))
        XCTAssertFalse(PaxCopy.youtubeOffBody(waitDays: 7, trusted: false).contains("emailed"))
    }
}

final class HomeLayoutTests: XCTestCase {
    func testHomeHasTwoActions() {
        XCTAssertEqual(HomeLayout.actions, [.blockedSites, .settings])
    }

    func testNudgeOnlyWhileNotLocked() {
        var p = PaxPolicy()
        p.isActive = true
        XCTAssertTrue(HomeLayout.showsNudge(p, macSetUp: false))
        p.passcodeEscrowed = true
        XCTAssertFalse(HomeLayout.showsNudge(p, macSetUp: false))
        var m = PaxPolicy()
        m.macSetUp = true
        XCTAssertFalse(HomeLayout.showsNudge(m, macSetUp: true))
    }

    func testEverythingIsInSettingsAndTurnOffIsLast() {
        let app = HomeLayout.all(macSetUp: false)
        XCTAssertEqual(Set(app), Set(SettingsItem.allCases))
        XCTAssertEqual(app.last, .turnOff)
        XCTAssertEqual(app.filter { $0 == .turnOff }.count, 1)
    }

    func testMacSetUpOnlyAddsToIt() {
        let mac = HomeLayout.all(macSetUp: true)
        for item in [SettingsItem.lockScreenTime, .encryptedDNS, .appsToClose, .blockedApps, .computerSetup] {
            XCTAssertFalse(mac.contains(item), "\(item)")
        }
        XCTAssertTrue(mac.contains(.youtube))
        XCTAssertEqual(mac.last, .turnOff)
    }
}

final class BlockedAppsTests: XCTestCase {
    func testBaiduIsInTheSearch() {
        let r = AppCatalog.search("bai")
        XCTAssertEqual(r.first?.bundleID, "com.baidu.BaiduMobile")
        XCTAssertTrue(r.first?.domains.contains("baidu.com") ?? false)
        XCTAssertEqual(AppCatalog.search("").count, AppCatalog.apps.count)
        XCTAssertTrue(AppCatalog.search("xiaohongshu").contains { $0.bundleID == "com.xingin.discover" })
        XCTAssertTrue(AppCatalog.apps.allSatisfy { AppBlockRules.isBundleID($0.bundleID) })
        XCTAssertTrue(AppCatalog.apps.allSatisfy { $0.domains.allSatisfy { PaxPolicy.normalise($0) == $0 } })
        XCTAssertEqual(Set(AppCatalog.apps.map { $0.bundleID }).count, AppCatalog.apps.count)
    }

    func testNeverPaxAppleOrPasswordManagers() {
        let p = PaxPolicy()
        XCTAssertEqual(AppBlockRules.problem("org.paxpeace.pax", policy: p), .pax)
        XCTAssertEqual(AppBlockRules.problem("com.apple.Preferences", policy: p), .apple)
        XCTAssertEqual(AppBlockRules.problem("com.apple.mobilephone", policy: p), .apple)
        XCTAssertEqual(AppBlockRules.problem("com.8bit.bitwarden", policy: p), .passwordManager)
        XCTAssertEqual(AppBlockRules.problem("not an app", policy: p), .notAnApp)
        XCTAssertNil(AppBlockRules.problem("com.baidu.BaiduMobile", policy: p))
        XCTAssertEqual(AppBlockRules.problem(Pax.bypassAppBundleIDs[0], policy: p), .alreadyBlocked)
    }

    func testSavedProtectedIDsAreNeverApplied() {
        var p = PaxPolicy()
        p.blockedApps = [BlockedApp(bundleID: "com.apple.Preferences", name: "Settings"),
                         BlockedApp(bundleID: "org.paxpeace.pax", name: "Pax"),
                         BlockedApp(bundleID: "com.baidu.BaiduMobile", name: "Baidu")]
        let ids = AppBlockRules.bundleIDs(p)
        XCTAssertTrue(ids.contains("com.baidu.BaiduMobile"))
        XCTAssertFalse(ids.contains("com.apple.Preferences"))
        XCTAssertFalse(ids.contains("org.paxpeace.pax"))
        XCTAssertTrue(Pax.bypassAppBundleIDs.allSatisfy { ids.contains($0) })
        XCTAssertLessThanOrEqual(ids.count, 50)
    }

    func testFullAtTheLimit() {
        var p = PaxPolicy()
        p.blockedApps = (0..<AppBlockRules.maxCustomApps).map { BlockedApp(bundleID: "com.example.app\($0)", name: "\($0)") }
        XCTAssertEqual(AppBlockRules.problem("com.example.more", policy: p), .full)
        XCTAssertLessThanOrEqual(AppBlockRules.bundleIDs(p).count, 50)
    }

    func testAppStoreLinksAndBundleIDs() {
        XCTAssertEqual(AppEntry.parse("https://apps.apple.com/gb/app/%E7%99%BE%E5%BA%A6/id382201985"), .appStoreID(382201985))
        XCTAssertEqual(AppEntry.parse("apps.apple.com/us/app/tiktok/id835599320?l=en"), .appStoreID(835599320))
        XCTAssertEqual(AppEntry.parse("id382201985"), .appStoreID(382201985))
        XCTAssertEqual(AppEntry.parse(" com.baidu.BaiduMobile "), .bundleID("com.baidu.BaiduMobile"))
        XCTAssertNil(AppEntry.parse("https://apps.apple.com/gb/app/nothing"))
        XCTAssertNil(AppEntry.parse("baidu"))
        XCTAssertNil(AppEntry.parse(""))
    }

    private func waiting(_ b: String, until: Int) -> BlockedAppInfo {
        BlockedAppInfo(bundle_id: b, name: nil,
                       pending_removal: BlocklistRequestInfo(request_id: "r1", action: "unblock_app", domain: nil,
                                                             status: "pending", effective_at: until, seconds_remaining: nil))
    }

    func testRemovalOnlyWithTheServersListAndAfterItsWait() {
        var p = PaxPolicy()
        p.blockedApps = [BlockedApp(bundleID: "com.baidu.BaiduMobile", name: "Baidu")]
        XCTAssertFalse(AppRemoval.canRemove("com.baidu.BaiduMobile", policy: p, serverHasList: false))   // no local-only removal
        XCTAssertTrue(AppRemoval.canRemove("com.baidu.BaiduMobile", policy: p, serverHasList: true))
        let local = [PendingAppRemoval(bundleID: "com.baidu.BaiduMobile", requestID: "r1", effectiveAt: 1_000)]
        let still = AppRemoval.reconcile(local: local, blocked: p.blockedApps,
                                         server: AppsViewInfo(now: 500, apps: [waiting("com.baidu.BaiduMobile", until: 1_000)]))
        XCTAssertEqual(still.removeNow, [])
        XCTAssertEqual(still.pending, local)
        let early = AppRemoval.reconcile(local: local, blocked: p.blockedApps, server: AppsViewInfo(now: 999, apps: []))
        XCTAssertEqual(early.removeNow, [])
        let done = AppRemoval.reconcile(local: local, blocked: p.blockedApps, server: AppsViewInfo(now: 1_000, apps: []))
        XCTAssertEqual(done.removeNow, ["com.baidu.BaiduMobile"])
        p.pendingAppRemovals = local
        XCTAssertTrue(AppRemoval.apply(done, to: &p))
        XCTAssertTrue(p.blockedApps.isEmpty)
        // Never removed without a request from this device.
        var q = PaxPolicy()
        q.blockedApps = [BlockedApp(bundleID: "com.kik.chat", name: "Kik")]
        XCTAssertEqual(AppRemoval.reconcile(local: [], blocked: q.blockedApps, server: AppsViewInfo(now: 9_999_999, apps: [])).removeNow, [])
        // Cancelled elsewhere: stays blocked, record goes.
        let cancelled = AppRemoval.reconcile(local: local, blocked: [BlockedApp(bundleID: "com.baidu.BaiduMobile", name: "Baidu")],
                                             server: AppsViewInfo(now: 2_000, apps: [BlockedAppInfo(bundle_id: "com.baidu.BaiduMobile")]))
        XCTAssertEqual(cancelled.removeNow, [])
        XCTAssertEqual(cancelled.pending, [])
    }

    func testPickerOnlyAdds() {
        XCTAssertEqual(SelectionRules.merged(Set([1, 2]), adding: Set<Int>()), [1, 2])     // un-choosing removes nothing
        XCTAssertEqual(SelectionRules.merged(Set([1, 2]), adding: [3]), [1, 2, 3])
    }

    func testPolicyKeepsBlockedAppsAndOldDataReadsAsNone() throws {
        var p = PaxPolicy()
        p.isActive = true
        p.blockedApps = [BlockedApp(bundleID: "com.baidu.BaiduMobile", name: "Baidu")]
        p.pendingAppRemovals = [PendingAppRemoval(bundleID: "com.baidu.BaiduMobile", requestID: "r", effectiveAt: 5)]
        let back = PaxPolicy.decode(try JSONEncoder().encode(p))
        XCTAssertEqual(back, p)
        let old = PaxPolicy.decode(Data(#"{"isActive": true, "setUpFinished": true}"#.utf8))
        XCTAssertTrue(old.isActive)
        XCTAssertTrue(old.blockedApps.isEmpty)
    }

    func testWords() {
        XCTAssertTrue(PaxCopy.blockedAppsIntro(isPad: false).contains("isn't on this iPhone yet"))
        XCTAssertTrue(PaxCopy.blockedAppsFooter(serverHasList: true).contains("turn-off wait"))
        XCTAssertTrue(PaxCopy.blockedAppsFooter(serverHasList: false).contains("stay blocked"))
        XCTAssertTrue(PaxCopy.blockedAppsProblem(.apple, isPad: true).contains("this iPad"))
    }
}
