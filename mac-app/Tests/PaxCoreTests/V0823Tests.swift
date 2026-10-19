// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.23: calmer Settings, honest Pax Max scope, plain security notices.
final class V0823Tests: XCTestCase {
    func testSettingsFoldsPaxMaxAndAboutWithoutLosingAnything() {
        XCTAssertEqual(AppSettingsLayout.foldedSections, ["Pax Max", "Advanced"])
        XCTAssertEqual(Array(AppSettingsLayout.sections.suffix(2)), AppSettingsLayout.foldedSections)
        XCTAssertEqual(AppSettingsLayout.foldedInUpdates, AppSettingsLayout.about)
        XCTAssertEqual(AppSettingsLayout.details, "Details")
        // v0.8.27: the Support ID moved to Turning Pax off (V0827Tests).
        // v0.8.28: "For testers" removed; nothing else left Advanced.
        XCTAssertEqual(AppSettingsLayout.advancedItems.count, 5)
    }

    func testPaxMaxCopyIsHonestAboutBrowsers() {
        XCTAssertEqual(PaxMax.summary, "Blurs pictures and video in Firefox. Other browsers aren't covered yet.")
        XCTAssertFalse(PaxMax.title.lowercased().contains("everywhere"))
        XCTAssertTrue(PaxMax.title.contains("Firefox"))
        XCTAssertTrue(PaxMax.explanation.contains("aren't covered yet"))
        XCTAssertEqual(PaxMax.stateLabel(on: nil, pending: false), "Off")
        XCTAssertEqual(PaxMax.stateLabel(on: false, pending: false), "Off")
        XCTAssertEqual(PaxMax.stateLabel(on: true, pending: false), "On")
        XCTAssertEqual(PaxMax.stateLabel(on: true, pending: true), "Turning off")
        let all = [PaxMax.title, PaxMax.summary, PaxMax.explanation].joined(separator: " ").lowercased()
        for word in ["porn", "explicit", "nsfw", "adult", "sexual", "unlock", "wait time"] {
            XCTAssertFalse(all.contains(word), word)
        }
    }

    func testPartnerSummaryIsOneLine() {
        XCTAssertEqual(PartnerSummary.value(partner: nil), "Not set")
        XCTAssertEqual(PartnerSummary.value(partner: "sam@example.com"), "sam@example.com")
        XCTAssertEqual(PartnerSummary.button(partner: nil), "Add…")
        XCTAssertEqual(PartnerSummary.button(partner: "sam@example.com"), "Change…")
        XCTAssertEqual(PartnerSummary.state(partner: "sam@example.com", available: true),
                       "Told before any turn-off wait starts.")
        XCTAssertEqual(PartnerSummary.state(partner: "sam@example.com", available: true, pending: true,
                                            pendingEmail: "alex@example.com", pendingWhen: "20 Oct 2026"),
                       "Changing to alex@example.com on 20 Oct 2026.")
        XCTAssertEqual(PartnerSummary.state(partner: "sam@example.com", available: true, pending: true),
                       "Being removed.")
        XCTAssertTrue(PartnerSummary.state(partner: "sam@example.com", available: true, queued: 2)
            .hasPrefix("2 emails waiting to send"))
        XCTAssertEqual(PartnerSummary.state(partner: nil, available: false), PartnerSummary.unavailable)
        XCTAssertTrue(PartnerSummary.rule.contains("Changing or removing them takes your turn-off wait"))
        XCTAssertTrue(PartnerSummary.rule.contains("the wait doesn't start yet"))
    }

    func testPartnerViewDecodesQueuedCount() throws {
        let json = #"{"partner": "sam@example.com", "owner_email": null, "pending_partner": null, "transport": null, "queued": [{"id": "m1", "kind": "removal_requested", "attempts": 2, "gate": null, "last_error": ""}]}"#
        let v = try JSONDecoder().decode(GuardClient.PartnerView.self, from: Data(json.utf8))
        XCTAssertEqual(v.queued?.count, 1)
        let old = #"{"partner": null, "owner_email": null, "pending_partner": null, "transport": null}"#
        XCTAssertNil(try JSONDecoder().decode(GuardClient.PartnerView.self, from: Data(old.utf8)).queued)
    }

    private func e(_ ts: Int, _ kind: String) -> GuardClient.TamperEvent { GuardClient.TamperEvent(ts: ts, kind: kind) }

    func testBriefBackupEpisodesAreNotShown() {
        let base = 1_800_000_000
        let events = [e(base, "dns:fallback_on"), e(base + 40, "dns:fallback_off"),
                      e(base + 3600, "dns:fallback_on"), e(base + 3620, "dns:fallback_off"),
                      e(base + 7200, "changed:admins")]
        let shown = SecurityNotices.visible(events, now: Date(timeIntervalSince1970: TimeInterval(base + 9000)))
        XCTAssertEqual(shown.count, 1)
        XCTAssertTrue(shown[0].text.hasPrefix("The list of administrators on this Mac changed ("))
    }

    func testLongBackupEpisodeIsOnePlainLine() {
        let base = 1_800_000_000
        let shown = SecurityNotices.visible([e(base, "dns:fallback_on"), e(base + 1500, "dns:fallback_off")])
        XCTAssertEqual(shown.count, 1)
        XCTAssertTrue(shown[0].text.hasPrefix("Pax used its backup family filter for 25 minutes on "))
        XCTAssertTrue(shown[0].text.hasSuffix("You stayed protected."))
        XCTAssertFalse(shown[0].text.contains("dns:"))
        // Still running: shown once it has lasted 10 minutes.
        XCTAssertTrue(SecurityNotices.visible([e(base, "dns:fallback_on")],
                                              now: Date(timeIntervalSince1970: TimeInterval(base + 300))).isEmpty)
        XCTAssertTrue(SecurityNotices.visible([e(base, "dns:fallback_on")],
                                              now: Date(timeIntervalSince1970: TimeInterval(base + 900)))[0]
            .text.contains("You're still protected"))
        XCTAssertEqual(SecurityNotices.duration(3900), "1 hour 5 minutes")
    }

    func testNoRawCodesInNotices() {
        let kinds = ["changed:admins", "changed:paxadmin", "changed:volume_owners", "changed:secure_token",
                     "changed:filevault", "changed:recovery_key", "changed:mdm", "changed:startup_security",
                     "changed:firmware", "changed:guard_files", "changed:runtime", "changed:something_new",
                     "accounts:made_standard", "admin:made_standard_again", "clock_backwards", "clock_forward",
                     "trial_ended_early", "support_release_setting", "support_release_used", "support_code_refused",
                     "setting:adblock", "setting:pax_max", "setting:family_layer_off_requested", "setting:new_one",
                     "filters:pack_refused", "filters:pack_rolled_back", "totally_unknown"]
        for k in kinds {
            let t = HomeLayout.tamperNotice(kind: k, at: 1_800_000_000)
            XCTAssertFalse(t.contains(k), k)
            XCTAssertFalse(t.contains("_"), k)
            XCTAssertFalse(t.contains(":") && t.firstIndex(of: ":")! < t.firstIndex(of: "(")!, k)
        }
    }
}
