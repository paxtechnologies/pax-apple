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
}
