// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.12: Pax Max after set-up. (The v0.8.12 "Safer social media" tests went in
/// 0.8.13 with the switch: see V0813Tests.)
final class V0812Tests: XCTestCase {

    // MARK: Pax Max after set-up (on instantly; off after 1 hour, partner first)

    func testPaxMaxWordingExplainsAndWarns() {
        XCTAssertTrue(PaxMax.explanation.contains("blurs pictures and video"))
        XCTAssertTrue(PaxMax.warning.contains("isn't perfect"))
        XCTAssertTrue(PaxMax.warning.contains("ordinary pictures and video"))
        XCTAssertTrue(PaxMax.warning.contains("1 hour"))
        XCTAssertTrue(PaxMax.confirmOffMessage.contains("Turning this off takes effect after 1 hour"))
        XCTAssertTrue(PaxMax.setUpDetail.contains(PaxMax.warning))
        XCTAssertTrue(PaxMax.confirmOnMessage.contains(PaxMax.warning))
        XCTAssertEqual(PaxMax.offDelaySeconds, 3600)
        let all = [PaxMax.title, PaxMax.explanation, PaxMax.warning, PaxMax.rule, PaxMax.turnedOn,
                   PaxMax.offRequested, PaxMax.turnedOff, PaxMax.confirmOffMessage].joined(separator: " ").lowercased()
        for word in ["porn", "explicit", "nsfw", "adult", "sexual"] { XCTAssertFalse(all.contains(word), word) }
    }

    func testPaxMaxStatusLines() {
        XCTAssertTrue(PaxMax.status(on: true, pendingSeconds: nil).hasPrefix("Pax Max is on."))
        XCTAssertEqual(PaxMax.status(on: false, pendingSeconds: nil), "Pax Max is off.")
        XCTAssertTrue(PaxMax.status(on: true, pendingSeconds: 3600).contains("turns off in 60 minutes"))
        XCTAssertTrue(PaxMax.status(on: true, pendingSeconds: 30).contains("turns off in 1 minute."))
        XCTAssertTrue(PaxMax.status(on: nil, pendingSeconds: nil).contains("Set Pax up again"))
    }

    func testPaxMaxCommandsGoToPaxGuard() async throws {
        let view = #"{"switchable": true, "on": true, "pending": {"request_id": "r1", "action": "pax_max_off", "domain": "pax-max", "display_domain": "Pax Max", "status": "pending", "created_at": 1800000000, "effective_at": 1800003600, "seconds_remaining": 3600}, "off_delay_seconds": 3600}"#
        let t = FakeGuardTransport([
            "paxmax.get": #"{"ok": true, "pax_max": {"switchable": true, "on": true, "pending": null, "off_delay_seconds": 3600}}"#,
            "paxmax.on": #"{"ok": true, "pax_max": {"switchable": true, "on": true, "pending": null, "off_delay_seconds": 3600}}"#,
            "paxmax.off": #"{"ok": true, "request": {}, "pax_max": "# + view + #"}"#,
            "paxmax.cancel": #"{"ok": true, "pax_max": {"switchable": true, "on": true, "pending": null, "off_delay_seconds": 3600}}"#,
        ])
        let g = GuardClient(transport: t)
        let first = try await g.paxMax()
        XCTAssertEqual(first, GuardClient.PaxMaxView(switchable: true, on: true))
        let off = try await g.requestPaxMaxOff()
        XCTAssertEqual(off.on, true)                                  // still on during the hour
        XCTAssertEqual(off.pending?.seconds_remaining, 3600)
        XCTAssertEqual(off.pending?.action, "pax_max_off")
        _ = try await g.cancelPaxMaxOff(requestID: "r1")
        XCTAssertEqual(t.sent.last?["cmd"] as? String, "paxmax.cancel")
        XCTAssertEqual(t.sent.last?["request_id"] as? String, "r1")
        _ = try await g.turnPaxMaxOn()
        XCTAssertEqual(t.sent.last?["cmd"] as? String, "paxmax.on")
    }

    func testPaxMaxRefusalsKeepTheirCodes() async {
        for (code, cmd) in [("PAX-GUARD-014", "paxmax.off"), ("PAX-ESCROW-010", "paxmax.off"), ("PAX-GUARD-015", "paxmax.on")] {
            let t = FakeGuardTransport([cmd: #"{"ok": false, "code": ""# + code + #"", "error": "no"}"#])
            do {
                if cmd == "paxmax.off" { _ = try await GuardClient(transport: t).requestPaxMaxOff() }
                else { _ = try await GuardClient(transport: t).turnPaxMaxOn() }
                XCTFail("should throw")
            } catch {
                XCTAssertEqual(PaxErrorClassifier.classify(error).code, code)
            }
        }
    }

    func testSettingsCarryPaxMaxAndOldGuardHasNone() async throws {
        let t = FakeGuardTransport(["settings.get": #"{"ok": true, "settings": {"youtube_restricted": true, "pax_max": {"switchable": false, "on": null, "pending": null, "off_delay_seconds": 3600}}}"#])
        let s = try await GuardClient(transport: t).settings()
        XCTAssertEqual(s.pax_max?.switchable, false)
        XCTAssertNil(s.pax_max?.on)
        let old = FakeGuardTransport(["settings.get": #"{"ok": true, "settings": {"youtube_restricted": true}}"#])
        let olderSettings = try await GuardClient(transport: old).settings()
        XCTAssertNil(olderSettings.pax_max)
    }

    func testSetUpAsksForASwitchableBlurOnlyWhenAsked() {
        let script = URL(fileURLWithPath: "/R/profile/make_profile.py"), out = URL(fileURLWithPath: "/tmp/p.mobileconfig")
        XCTAssertFalse(ProfileGenerator.selfLockArguments(script: script, out: out, filter: .family)
            .contains("--image-blur-switchable"))
        let a = ProfileGenerator.selfLockArguments(script: script, out: out, filter: .family, imageBlurSwitchable: true)
        XCTAssertTrue(a.contains("--image-blur-switchable"))
        XCTAssertFalse(a.contains("--image-blur"))                     // Pax Max itself still off
        let cfg = GuardConfigFile(server_url: "s", guard_token: "", profile_identifier: "p", user: "u",
                                  resolver_host: "r", pax_max_switchable: true, pax_max_default: false)
        let json = String(decoding: try! cfg.json(), as: UTF8.self)
        XCTAssertTrue(json.contains(#""pax_max_switchable":true"#) && json.contains(#""pax_max_default":false"#))
        let old = String(decoding: try! GuardConfigFile(server_url: "s", guard_token: "", profile_identifier: "p",
                                                        user: "u", resolver_host: "r").json(), as: UTF8.self)
        XCTAssertFalse(old.contains("pax_max"))                        // left out unless set
    }
}
