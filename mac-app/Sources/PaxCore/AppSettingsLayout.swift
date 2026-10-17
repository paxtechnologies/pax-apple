// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.14 (project decision): one place for settings. The sidebar's "Settings"
/// (and Pax › Settings… ⌘,) opens this screen in the main window; there is no
/// separate Settings window and no per-device "Settings" screen. A device's own
/// details and switches are on its page (click it in the sidebar).
///
/// v0.8.18 (Ruben: "simplify, simplify, simplify"): Home keeps only three things
/// (Status, What's blocked, Turn off). This Mac's switches and its details moved here,
/// grouped simply, each with one plain line; rare things sit under Advanced.
public enum AppSettingsLayout {
    /// v0.8.18 Advanced switch title.
    public static let familyLayerTitle = "Extra family filter layer"
    /// This Mac's switches: ads and trackers, sync, YouTube Restricted Mode, the X/Bluesky line.
    public static let blocking = "Blocking"
    public static let paxMax = "Pax Max"
    /// Turn-off wait, the trial day, verified support release.
    public static let turningOff = "Turning Pax off"
    public static let partnerEmail = "Accountability partner email"
    public static let updates = "Updates"
    public static let about = "About"
    /// Closed by default.
    public static let advanced = "Advanced"
    public static let advancedItems = ["Support ID", "Security notices", "Filter", "Extra family filter layer", "Where this Mac keeps its key",
                                       "Pax server", "For testers"]

    /// The sections, top to bottom.
    public static let sections = [blocking, paxMax, turningOff, partnerEmail, updates, about, advanced]

    /// The one plain line under each switch or row (Settings).
    public enum Line {
        public static let adsLive = "Hides ads and trackers in every app and browser. Switches straight away."
        public static let adsServer = "Hides ads and trackers in every app and browser. Switches within a minute."
        public static let sync = "Keeps one list of blocked sites on all your devices."
        public static let youtube = "Hides videos YouTube marks as mature. Switches straight away."
        public static let turnOffWait = "How long turning Pax off takes after you ask. The same wait applies "
            + "before a site or app is unblocked."
        public static let supportRelease = "In a genuine emergency, Pax support can check it and give you a "
            + "one-time code for this device. Your trusted person is told first."
        public static let supportReleaseRule = "Turning it off is instant. Turning it on takes your turn-off wait "
            + "(instant during your trial day), and your trusted person is told."
        public static let supportID = "Quote this if you ever contact Pax support."
        /// v0.8.18 Advanced: the extra family filter layer (off by default).
        public static let familyLayer = "Also send every lookup Pax allows through a family filter. "
            + "Stricter, and it can block a few ordinary sites."
        public static let familyLayerRule = "Turning it on is instant. Turning it off takes your turn-off wait, "
            + "and your trusted person is told first."
        public static let securityNotices = "Changes Pax noticed to this Mac's security settings."
    }
}

/// v0.8.14: the details card on an iPhone's or iPad's page.
public enum DeviceDetails {
    /// One row since 0.8.13 made both always blocked (was two rows, X and Bluesky).
    public static let mediaLabel = "Images and video on X and Bluesky"
    public static let mediaValue = "Always blocked"
    public static let appsLabel = "Your blocked apps"
    /// Under the card. The choices are kept in the device's locked profile.
    public static let setUpChoicesNote = "These were chosen when the device was set up. "
        + "To change them, set it up again."

    /// "None", "1 app", "3 apps": short, so it never gets cut off.
    public static func appCount(_ names: [String]) -> String {
        switch names.count {
        case 0: return "None"
        case 1: return "1 app"
        default: return "\(names.count) apps"
        }
    }

    /// The names, sorted, one per line (shown wrapped under the count).
    public static func appList(_ names: [String]) -> String {
        names.sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }.joined(separator: "\n")
    }
}

/// v0.8.14: a Mac set up with an older version keeps that version's Chrome extension
/// list in its locked profile, so an extension allowed since (e.g. Momentum) shows as
/// blocked by the administrator. macOS only lets an administrator replace that profile,
/// and the administrator password is kept behind the wait, so Pax can't refresh it on
/// its own; nothing is weaker meanwhile (fewer extensions are allowed, not more).
public enum BrowserRulesNotice {
    public static func text(browser: String?, missing: [String]) -> String? {
        guard !missing.isEmpty else { return nil }
        let names = ListFormatter.localizedString(byJoining: missing)
        let b = browser ?? "Chrome"
        return "\(b) is using the extension list from when Pax was set up, so \(names) "
            + (missing.count == 1 ? "shows" : "show") + " as blocked by your administrator. Your protection is "
            + "unchanged. macOS lets only an administrator update this list, so it updates when Pax is next set up."
    }
}
