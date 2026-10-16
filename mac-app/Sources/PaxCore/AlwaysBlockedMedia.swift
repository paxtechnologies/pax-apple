// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.13 (project decision): pictures and video on X and Bluesky are always
/// blocked, on every device, with no switch anywhere. Their media servers are
/// blocked while the posts themselves stay readable. Replaces the v0.8.12 "Safer
/// social media" switch: YouTube Restricted Mode is its own plain switch again,
/// and set-up and Home show this notice instead.
///
/// Enforced outside the app too, so an older app can't undo it: pax-guard always
/// blocks the hosts and refuses settings.set (PAX-DNS-016), the iPhone profile
/// always carries them (make_profile.py IOS_ALWAYS_BLOCKED_MEDIA_HOSTS), and the
/// Pax server refuses to turn them off (HTTP 422 media_always_blocked) and forced
/// older accounts back on.
public enum AlwaysBlockedMedia {
    /// The short line shown in set-up (before anything is locked) and on Home.
    public static let notice = "Pictures and video on X and Bluesky are always off. Posts stay readable."
    /// Heading for the notice row.
    public static let title = "X and Bluesky"
    /// One line for "Here's what Pax will do".
    public static let planLine = "Hide pictures and video on X and Bluesky. Posts stay readable."

    /// X's image and video servers (guard_config.X_MEDIA_NAMES).
    public static let xHosts = ["pbs.twimg.com", "video.twimg.com", "ton.twimg.com"]
    /// Bluesky's image, video and GIF servers (guard_config.BLUESKY_MEDIA_NAMES).
    public static let blueskyHosts = ["cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app", "gifs.bsky.app"]
    /// Both, in the same order as guard_config.ALWAYS_BLOCKED_MEDIA_NAMES.
    public static let hosts = xHosts + blueskyHosts

    /// An iPhone/iPad set up before 0.8.13 with either switch off: on Pax's own
    /// filter the server now blocks them; on CleanBrowsing directly the locked
    /// profile can't change, so the phone needs setting up again. nil when the
    /// device had both on (or was set up with 0.8.13 or later).
    public static func legacyNote(xMediaWasOn: Bool?, blueskyMediaWasOn: Bool?, usesPaxFilter: Bool?) -> String? {
        guard xMediaWasOn == false || blueskyMediaWasOn == false else { return nil }
        let start = "Set up earlier with pictures and video on X or Bluesky showing. "
        switch usesPaxFilter {
        case true?: return start + "Pax's filter now keeps them off."
        case false?: return start + "Set this device up again to turn them off."
        case nil: return start + "If they still load, set this device up again."
        }
    }
}
