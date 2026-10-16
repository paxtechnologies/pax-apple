// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.13 (project decision): pictures and video on X and Bluesky are always
/// blocked, with no switch anywhere. The v0.8.12 "Safer social media" switch is
/// gone: YouTube Restricted Mode is a plain switch again and set-up and Home show a
/// calm notice. The server refuses turning them off (PAX-DNS-016).
final class V0813Tests: XCTestCase {

    func testNoticeIsShortCalmAndNeutral() {
        XCTAssertEqual(AlwaysBlockedMedia.notice,
                       "Pictures and video on X and Bluesky are always off. Posts stay readable.")
        let all = [AlwaysBlockedMedia.notice, AlwaysBlockedMedia.title, AlwaysBlockedMedia.planLine,
                   AlwaysBlockedMedia.legacyNote(xMediaWasOn: false, blueskyMediaWasOn: true, usesPaxFilter: nil) ?? "",
                   AlwaysBlockedMedia.legacyNote(xMediaWasOn: false, blueskyMediaWasOn: true, usesPaxFilter: true) ?? "",
                   AlwaysBlockedMedia.legacyNote(xMediaWasOn: true, blueskyMediaWasOn: false, usesPaxFilter: false) ?? ""]
            .joined(separator: " ").lowercased()
        for word in ["porn", "explicit", "nsfw", "adult", "sexual", "covenant", "hardstop", "canopy"] {
            XCTAssertFalse(all.contains(word), word)
        }
    }

    func testHostsMatchPaxGuardAndTheProfile() {
        // Same lists as guard_config.ALWAYS_BLOCKED_MEDIA_NAMES / make_profile.IOS_ALWAYS_BLOCKED_MEDIA_HOSTS.
        XCTAssertEqual(AlwaysBlockedMedia.hosts, ["pbs.twimg.com", "video.twimg.com", "ton.twimg.com",
                                                  "cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app",
                                                  "gifs.bsky.app"])
        XCTAssertFalse(AlwaysBlockedMedia.hosts.contains("x.com"))
        XCTAssertFalse(AlwaysBlockedMedia.hosts.contains("bsky.app"))
        // Built into every iPhone profile, so they never take a custom slot.
        for h in AlwaysBlockedMedia.hosts { XCTAssertTrue(BulkSiteImport.iosBuiltInHosts.contains(h), h) }
    }

    func testFilterSettingsOnlyCarryYouTube() {
        XCTAssertEqual(PaxFilterSettings(), PaxFilterSettings(youtubeRestricted: true))
        XCTAssertFalse(PaxFilterSettings(youtubeRestricted: false).youtubeRestricted)
    }

    func testGuardConfigHasNoMediaSwitches() throws {
        let c = GuardConfigFile(server_url: "s", guard_token: "", profile_identifier: "p", user: "u", resolver_host: "r")
        let json = String(decoding: try c.json(), as: UTF8.self)
        XCTAssertFalse(json.contains("x_media"))
        XCTAssertFalse(json.contains("bluesky_media"))
    }

    func testOlderPaxGuardSettingsStillDecode() async throws {
        // A 0.8.12 pax-guard still reports x_media / bluesky_media; they're ignored.
        let t = FakeGuardTransport([
            "settings.get": #"{"ok": true, "settings": {"youtube_restricted": true, "youtube_available": true, "x_media": false, "bluesky_media": true, "changed_at": null}}"#,
        ])
        let s = try await GuardClient(transport: t).settings()
        XCTAssertEqual(s, GuardClient.Settings(youtube_restricted: true))
    }

    func testServerRefusalHasItsOwnCode() {
        let e = PaxErrorClassifier.classify(EscrowClient.APIError(
            status: 422, code: "media_always_blocked",
            message: "pictures and video on X and Bluesky are always off; posts stay readable"))
        XCTAssertEqual(e.code, "PAX-DNS-016")
        XCTAssertTrue(e.info.message.contains("always off"))
        XCTAssertFalse(e.isRestrictedSite)
        // pax-guard's coded refusal maps the same way.
        XCTAssertEqual(PaxErrorClassifier.classify(GuardClient.Failure(code: "PAX-DNS-016", message: "x")).code,
                       "PAX-DNS-016")
    }

    func testLegacyDeviceNote() {
        XCTAssertNil(AlwaysBlockedMedia.legacyNote(xMediaWasOn: true, blueskyMediaWasOn: true, usesPaxFilter: false))
        XCTAssertNil(AlwaysBlockedMedia.legacyNote(xMediaWasOn: nil, blueskyMediaWasOn: nil, usesPaxFilter: nil))
        XCTAssertTrue(AlwaysBlockedMedia.legacyNote(xMediaWasOn: false, blueskyMediaWasOn: true,
                                                    usesPaxFilter: true)!.contains("Pax's filter now keeps them off"))
        XCTAssertTrue(AlwaysBlockedMedia.legacyNote(xMediaWasOn: true, blueskyMediaWasOn: false,
                                                    usesPaxFilter: false)!.contains("Set this device up again"))
    }
}
