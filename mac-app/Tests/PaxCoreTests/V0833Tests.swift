// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.33: Pax-approved installs and updates (guard/app_installs.py does the checking).
final class V0833Tests: XCTestCase {
    func testStartInstallSendsOnlyThePathAndDecodesTheJob() async throws {
        let t = FakeGuardTransport([
            "installs.start": #"{"ok": true, "job": {"id": 1, "state": "working", "step": "copying", "kind": "dmg", "source": "Writer.dmg", "started_at": 5}}"#,
            "installs.status": #"{"ok": true, "job": {"id": 1, "state": "installed", "kind": "dmg", "source": "Writer.dmg", "name": "Writer", "version": "3.0", "dest": "/Applications/Writer.app"}, "history": []}"#,
        ])
        let g = GuardClient(transport: t)
        let job = try await g.startInstall(path: "/Users/alex/Downloads/Writer.dmg")
        XCTAssertTrue(job.isWorking)
        XCTAssertEqual(t.sent[0]["path"] as? String, "/Users/alex/Downloads/Writer.dmg")
        XCTAssertNil(t.sent[0]["choice"])
        XCTAssertNil(t.sent[0]["update_only"])
        let done = try await g.installStatus()
        XCTAssertEqual(done?.succeeded, true)
        XCTAssertEqual(AppInstallText.done(done!), "Writer 3.0 is installed in Applications.")
        _ = try await g.startInstall(path: "/p.dmg", choice: "Beta.app", updateOnly: true)
        XCTAssertEqual(t.sent.last?["choice"] as? String, "Beta.app")
        XCTAssertEqual(t.sent.last?["update_only"] as? Bool, true)
    }

    func testNoJobYetIsNil() async throws {
        let t = FakeGuardTransport(["installs.status": #"{"ok": true, "job": null, "history": []}"#])
        let job = try await GuardClient(transport: t).installStatus()
        XCTAssertNil(job)
    }

    func testRefusalsUseTheCatalogAndNameTheKindOfApp() {
        let blocked = GuardClient.InstallJob(id: 2, state: "refused", step: nil, kind: "app", source: "AnyDesk.app",
                                             name: "AnyDesk", version: "9", code: "PAX-MAC-021",
                                             error: "Pax doesn't install remote-desktop tools",
                                             options: nil, category: "remote-desktop tools: they reach a computer outside Pax",
                                             dest: nil)
        let p = AppInstallText.problem(blocked)
        XCTAssertEqual(p.message, "Pax doesn't install remote-desktop tools: they reach a computer outside Pax.")
        XCTAssertEqual(p.code, "PAX-MAC-021")
        let other = GuardClient.InstallJob(id: 3, state: "refused", step: nil, kind: "pkg", source: "x.pkg", name: nil,
                                           version: nil, code: "PAX-MAC-024", error: nil, options: nil, category: nil,
                                           dest: nil)
        XCTAssertEqual(AppInstallText.problem(other).message, PaxErrorCatalog.info("PAX-MAC-024").message)
        for code in (18...31).map({ String(format: "PAX-MAC-%03d", $0) }) + ["PAX-UPDATE-009", "PAX-UPDATE-010",
                                                                              "PAX-UPDATE-011"] {
            XCTAssertTrue(PaxErrorCatalog.contains(code), code)
        }
    }

    func testOnlyAppsImagesAndPackagesAreOffered() {
        XCTAssertTrue(AppInstallRules.isInstallable(URL(fileURLWithPath: "/Users/a/Downloads/Writer.dmg")))
        XCTAssertTrue(AppInstallRules.isInstallable(URL(fileURLWithPath: "/Users/a/Downloads/Writer.APP")))
        XCTAssertTrue(AppInstallRules.isInstallable(URL(fileURLWithPath: "/Users/a/Downloads/Tool.pkg")))
        XCTAssertFalse(AppInstallRules.isInstallable(URL(fileURLWithPath: "/Users/a/Downloads/Writer.zip")))
        XCTAssertFalse(AppInstallRules.isInstallable(URL(string: "https://example.com/Writer.dmg")!))
    }

    func testSystemUpdatesDecodeAndNeverRestart() async throws {
        let t = FakeGuardTransport([
            "system_updates.install": #"{"ok": true, "system_updates": {"state": "installing", "installing": "Safari18.1", "updates": [{"label": "Safari18.1", "title": "Safari", "version": "18.1", "restart": false, "recommended": true, "size": "1KiB"}], "checked_at": 1, "code": null, "error": null}}"#,
        ])
        let s = try await GuardClient(transport: t).installSystemUpdate(label: "Safari18.1")
        XCTAssertTrue(s.isBusy)
        XCTAssertEqual(t.sent[0]["label"] as? String, "Safari18.1")
        XCTAssertEqual(t.sent[0].keys.sorted(), ["cmd", "label"])
        let u = GuardClient.SystemUpdate(label: "m", title: "macOS Ventura 13.7.1", version: "13.7.1", restart: true,
                                         recommended: true, size: nil)
        XCTAssertEqual(AppInstallText.systemRow(u), "restart needed")
    }

    func testCopyIsCalmAndOnBrand() {
        let all = [AppInstallText.rowTitle, AppInstallText.rowLine, AppInstallText.sheetTitle, AppInstallText.dropHint,
                   AppInstallText.downloadedLine, AppInstallText.systemLine, AppInstallText.systemRestart,
                   AppInstallText.systemNone] + AppInstallText.rules
        for s in all {
            let l = s.lowercased()
            XCTAssertFalse(l.contains("unlock"), s)
            XCTAssertFalse(l.contains("pax strict"), s)
            XCTAssertFalse(l.contains("porn"), s)
            XCTAssertFalse(l.contains("!"), s)
        }
        XCTAssertTrue(AppInstallText.rules.joined().contains("turning Pax off"))
        XCTAssertEqual(AppInstallText.rowTitle, "Install or update an app")
    }

    // MARK: v0.8.33 simple doors (Ruben, 28 Oct 2026): Home card, one notification, Open With / drop

    private func upd(_ name: String, _ id: String, _ v: String, path: String? = nil) -> GuardClient.DownloadedUpdate {
        GuardClient.DownloadedUpdate(path: path ?? "/Users/a/Library/Caches/\(id)/\(name).app", name: name,
                                     bundle_id: id, version: v, installed_version: "1.0")
    }

    func testScanBecomesCardsAndNotifiesOncePerAppAndVersion() {
        let a = upd("Writer", "com.example.Writer", "3.2")
        let b = upd("Notes Plus", "com.example.notes", "5.0")
        let first = AppUpdatePrompts.process([a, b], remembered: [])
        XCTAssertEqual(first.cards, [a, b])
        XCTAssertEqual(first.notify, [a, b])
        XCTAssertEqual(first.remembered, ["com.example.writer|3.2", "com.example.notes|5.0"])
        // Same scan again (launch, every 30 min): cards stay, no new notification.
        let again = AppUpdatePrompts.process([a, b], remembered: first.remembered)
        XCTAssertEqual(again.cards, [a, b])
        XCTAssertTrue(again.notify.isEmpty)
        XCTAssertEqual(again.remembered, first.remembered)
        // Installed: gone from the scan, so gone from Home; it comes back only as a newer version.
        let later = AppUpdatePrompts.process([upd("Writer", "COM.EXAMPLE.WRITER", "3.3")], remembered: again.remembered)
        XCTAssertEqual(later.cards.map(\.version), ["3.3"])
        XCTAssertEqual(later.notify.map(\.version), ["3.3"])
        let back = AppUpdatePrompts.process([a], remembered: later.remembered)
        XCTAssertTrue(back.notify.isEmpty, "3.2 was already notified once")
        // One card per app, at most three, and nothing nameless.
        let many = (1...6).map { upd("App\($0)", "com.x.app\($0)", "2.0") } + [upd("Dup", "com.x.app1", "9.0"),
                                                                           upd("", "com.x.blank", "1.0")]
        let out = AppUpdatePrompts.process(many, remembered: [])
        XCTAssertEqual(out.cards.count, AppUpdatePrompts.maxCards)
        XCTAssertEqual(out.notify.count, 6)
        XCTAssertFalse(out.notify.contains { $0.name == "Dup" || $0.name.isEmpty })
        // Remembered pairs are bounded.
        let old = (0..<AppUpdatePrompts.rememberLimit).map { "com.old.\($0)|1" }
        let trimmed = AppUpdatePrompts.process([a], remembered: old)
        XCTAssertEqual(trimmed.remembered.count, AppUpdatePrompts.rememberLimit)
        XCTAssertEqual(trimmed.remembered.last, "com.example.writer|3.2")
        XCTAssertEqual(trimmed.notify, [a])
    }

    func testCardNotificationAndSheetWording() {
        let a = upd("Writer", "com.example.Writer", "3.2")
        XCTAssertEqual(AppUpdatePrompts.cardTitle(a), "App update ready: Writer 3.2")
        XCTAssertEqual(AppUpdatePrompts.cardButton, "Update")
        XCTAssertEqual(AppUpdatePrompts.notificationBody(a), "Writer has an update ready. Pax can install it for you.")
        let r = AppUpdatePrompts.request(for: a)
        XCTAssertEqual(r.title, "Update Writer?")
        XCTAssertEqual(r.button, "Update")
        XCTAssertTrue(r.updateOnly)
        let n = AppInstallRequest(path: "/Users/a/Downloads/Tool.dmg", name: "Tool", isUpdate: false)
        XCTAssertEqual(n.title, "Install Tool?")
        XCTAssertEqual(n.button, "Install")
        XCTAssertFalse(n.updateOnly)
        for s in [AppUpdatePrompts.cardTitle(a), AppUpdatePrompts.notificationBody(a), r.title, n.title] {
            XCTAssertFalse(s.lowercased().contains("password"), s)
            XCTAssertFalse(s.lowercased().contains("admin"), s)
        }
    }

    func testScanTiming() {
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        XCTAssertTrue(AppUpdatePrompts.shouldScan(last: nil, now: t0, reason: .launch))
        XCTAssertFalse(AppUpdatePrompts.shouldScan(last: t0, now: t0.addingTimeInterval(10), reason: .appear))
        XCTAssertTrue(AppUpdatePrompts.shouldScan(last: t0, now: t0.addingTimeInterval(61), reason: .appear))
        XCTAssertFalse(AppUpdatePrompts.shouldScan(last: t0, now: t0.addingTimeInterval(600), reason: .periodic))
        XCTAssertTrue(AppUpdatePrompts.shouldScan(last: t0, now: t0.addingTimeInterval(30 * 60), reason: .periodic))
        XCTAssertTrue(AppUpdatePrompts.shouldScan(last: t0, now: t0.addingTimeInterval(-5), reason: .periodic))
    }

    func testNotificationClickOnlyOpensAnUpdateStillInTheScan() {
        let a = upd("Writer", "com.example.Writer", "3.2")
        XCTAssertEqual(AppUpdatePrompts.requestForClick(path: a.path, current: [a]), AppUpdatePrompts.request(for: a))
        XCTAssertNil(AppUpdatePrompts.requestForClick(path: "/etc/evil.app", current: [a]))
        XCTAssertNil(AppUpdatePrompts.requestForClick(path: nil, current: [a]))
        XCTAssertNil(AppUpdatePrompts.requestForClick(path: a.path, current: []))
    }

    func testOpenWithAndDropsGoStraightToTheConfirmation() {
        let dmg = URL(fileURLWithPath: "/Users/a/Downloads/Writer-3.2.1-universal.dmg")
        let app = URL(fileURLWithPath: "/Volumes/Writer/Writer.app")
        let zip = URL(fileURLWithPath: "/Users/a/Downloads/Writer.zip")
        XCTAssertEqual(AppOpenRouting.route([dmg], protected: true),
                       .confirm(AppInstallRequest(path: dmg.path, name: "Writer", isUpdate: false)))
        XCTAssertEqual(AppOpenRouting.route([zip, app], protected: true, isInstalled: { $0 == "Writer" }),
                       .confirm(AppInstallRequest(path: app.path, name: "Writer", isUpdate: true)))
        if case .confirm(let r) = AppOpenRouting.route([app], protected: true, isInstalled: { _ in true }) {
            XCTAssertEqual(r.title, "Update Writer?")
            XCTAssertFalse(r.updateOnly)
        } else { XCTFail("expected the confirmation") }
        XCTAssertEqual(AppOpenRouting.route([zip], protected: true), .ignore)
        XCTAssertEqual(AppOpenRouting.route([], protected: true), .ignore)
        XCTAssertEqual(AppOpenRouting.route([URL(string: "https://example.com/Writer.dmg")!], protected: true), .ignore)
        XCTAssertEqual(AppOpenRouting.route([dmg], protected: false), .reveal(dmg))
        XCTAssertEqual(AppOpenRouting.displayName(URL(fileURLWithPath: "/d/Big App 2 v4.1.dmg")), "Big App 2")
        XCTAssertEqual(AppOpenRouting.displayName(URL(fileURLWithPath: "/d/Notes_Plus_5.0_macOS.dmg")), "Notes Plus")
        XCTAssertEqual(AppOpenRouting.displayName(URL(fileURLWithPath: "/d/3.2.dmg")), "3.2")
        XCTAssertEqual(AppOpenRouting.displayName(URL(fileURLWithPath: "/d/My-App 2.app")), "My-App 2")
    }
}

