// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.18: Pax's own filter, its backup, and the Advanced "Extra family filter layer".
final class V0818FilterTests: XCTestCase {
    func testFilterModesInPlainWords() async throws {
        let t = FakeGuardTransport(["status": #"{"ok": true, "version": "0.8.18", "escrow_mode": "local", "dns": {"active": "Quad9", "ready": true, "all_down": false, "filter_mode": "fallback", "fallback_reason": "canary: example check", "fallback_since": 1800000000, "canary": {}}}"#])
        let s = try await GuardClient(transport: t).status()
        XCTAssertEqual(s.dns?.filter_mode, "fallback")
        XCTAssertTrue(FilterStatusText.line(s.dns).contains("family filter is answering"))
        XCTAssertTrue(FilterModeText.fallbackLine(s.dns)?.hasSuffix("canary: example check.") == true)
        XCTAssertEqual(FilterModeText.label("fallback"), "Backup (family filter)")

        let pax = GuardClient.Status.DNS(active: "Quad9", ready: true, all_down: false, filter_mode: "pax")
        XCTAssertEqual(FilterStatusText.line(pax), "Filtering with Pax's own filter. It checks itself regularly.")
        XCTAssertNil(FilterModeText.fallbackLine(pax))
        XCTAssertEqual(FilterModeText.label("pax"), "Pax filter")
        let layer = GuardClient.Status.DNS(active: "Quad9", ready: true, all_down: false, filter_mode: "family-layer")
        XCTAssertTrue(FilterStatusText.line(layer).contains("extra family filter layer"))
        // Home: Pax's filter is the normal state; the backup gets a line.
        XCTAssertFalse(HomeLayout.filterNeedsNotice(pax))
        XCTAssertFalse(HomeLayout.filterNeedsNotice(layer))
        XCTAssertTrue(HomeLayout.filterNeedsNotice(s.dns))
        let starting = GuardClient.Status.DNS(active: "Quad9", ready: false, all_down: false, filter_mode: "fallback")
        XCTAssertEqual(FilterStatusText.line(starting), "Starting the filter…")
        let down = GuardClient.Status.DNS(active: nil, ready: true, all_down: true, filter_mode: "fallback")
        XCTAssertTrue(FilterStatusText.line(down).contains("won't open"))
    }

    func testFamilyLayerOffWaitsAndCarriesItsRequest() async throws {
        let req = #"{"request_id": "f1", "action": "family_layer_off", "domain": "family-layer", "display_domain": "the extra family filter", "status": "pending", "created_at": 1, "effective_at": 86401, "seconds_remaining": 86400}"#
        let t = FakeGuardTransport(["settings.set": #"{"ok": true, "settings": {"youtube_restricted": true, "youtube_available": true, "family_layer": true, "family_layer_local": true, "family_layer_pending": \#(req)}, "request": \#(req)}"#])
        let g = GuardClient(transport: t)
        let r = try await g.setFamilyLayer(false)
        XCTAssertEqual(t.sent[0]["family_layer"] as? Bool, false)
        XCTAssertEqual(r.settings.family_layer, true)            // still on until the wait ends
        XCTAssertEqual(r.request?.request_id, "f1")
        XCTAssertEqual(r.settings.family_layer_pending?.seconds_remaining, 86400)
    }

    func testFamilyLayerOnIsImmediateAndOlderGuardsDecode() async throws {
        let t = FakeGuardTransport([
            "settings.set": #"{"ok": true, "settings": {"youtube_restricted": true, "family_layer": true, "family_layer_local": true, "family_layer_pending": null}}"#,
            "settings.get": #"{"ok": true, "settings": {"youtube_restricted": false}}"#,
        ])
        let g = GuardClient(transport: t)
        let r = try await g.setFamilyLayer(true)
        XCTAssertEqual(r.settings.family_layer, true)
        XCTAssertNil(r.request)
        let old = try await g.settings()
        XCTAssertNil(old.family_layer)
        XCTAssertEqual(AppSettingsLayout.familyLayerTitle, "Extra family filter layer")
        XCTAssertTrue(AppSettingsLayout.advancedItems.contains(AppSettingsLayout.familyLayerTitle))
    }
}
