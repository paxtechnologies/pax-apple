// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.19: the filter pack in use (signed list updates) in Settings › Advanced, and
/// plain notices for a refused or rolled-back pack.
final class V0819FilterPackTests: XCTestCase {
    func testFilterPackStatusDecodesAndReadsPlainly() async throws {
        let t = FakeGuardTransport(["status": #"{"ok": true, "version": "0.8.19", "escrow_mode": "local", "dns": {"active": "Quad9", "ready": true, "all_down": false, "filter_mode": "pax"}, "filter_pack": {"version": "2026.1018.300", "origin": "pack", "bundled_version": "2026.1017.1", "last_check_at": 1800000000, "last_ok": true, "last_error": null, "refused": []}}"#])
        let s = try await GuardClient(transport: t).status()
        XCTAssertEqual(s.filter_pack?.version, "2026.1018.300")
        XCTAssertEqual(FilterPackText.value(s.filter_pack), "2026.1018.300 (updated automatically)")
        XCTAssertTrue(FilterPackText.lastCheck(s.filter_pack)?.contains("every 6 hours") == true)

        let bundled = GuardClient.Status.FilterPack(version: "2026.1017.1", origin: "bundled")
        XCTAssertEqual(FilterPackText.value(bundled), "2026.1017.1 (built into Pax)")
        XCTAssertNil(FilterPackText.lastCheck(bundled))
        let failed = GuardClient.Status.FilterPack(version: "2026.1017.1", origin: "bundled", last_check_at: 1800000000,
                                                   last_ok: false, last_error: "canary failed on the new lists")
        XCTAssertTrue(FilterPackText.lastCheck(failed)?.contains("Kept the lists in use") == true)
        XCTAssertNil(FilterPackText.value(nil))
    }

    func testOlderGuardWithoutFilterPackStillDecodes() async throws {
        let t = FakeGuardTransport(["status": #"{"ok": true, "version": "0.8.18", "escrow_mode": "local"}"#])
        let s = try await GuardClient(transport: t).status()
        XCTAssertNil(s.filter_pack)
    }

    func testPackNoticesArePlain() {
        XCTAssertTrue(HomeLayout.tamperNotice(kind: "filters:pack_refused", at: 1800000000)
            .hasPrefix("A filter list update didn't pass Pax's checks"))
        XCTAssertTrue(HomeLayout.tamperNotice(kind: "filters:pack_rolled_back", at: 1800000000)
            .contains("went back to the previous lists"))
        // v0.8.23: plain words, no raw log code.
        XCTAssertTrue(HomeLayout.tamperNotice(kind: "changed:sip", at: 1800000000)
            .hasPrefix("System Integrity Protection on this Mac changed ("))
    }
}
