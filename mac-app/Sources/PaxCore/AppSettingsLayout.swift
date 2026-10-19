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
    /// Turn-off wait, the trial day, verified support release, and (v0.8.27) the Support ID.
    public static let turningOff = "Turning Pax off"
    public static let partnerEmail = "Accountability partner email"
    /// v0.8.23: Updates and About are one card; About's text is folded inside it.
    public static let updates = "Updates"
    public static let about = "About Pax"
    /// Closed by default.
    public static let advanced = "Advanced"
    /// v0.8.27: the Support ID moved to Turning Pax off (shown only with verified support release on).
    /// v0.8.28: "For testers" removed (Ruben); "Copy details" on error cards is unchanged.
    public static let advancedItems = ["Security notices", "Filter", "Extra family filter layer", "Where this Mac keeps its key",
                                       "Pax server"]

    /// v0.8.23 (Ruben: "only keep what is necessary"): each card shows a title and its
    /// current state; explanations and rare actions sit behind a "Details" disclosure.
    /// Pax Max is folded like Advanced, just above it (off by default; most people
    /// won't use it). Nothing was removed: everything is at most one click deeper.
    public static let sections = [blocking, turningOff, partnerEmail, updates, paxMax, advanced]
    /// Cards closed until clicked (a row with an arrow).
    public static let foldedSections = [paxMax, advanced]
    /// Inside the Updates card, folded.
    public static let foldedInUpdates = about
    /// The disclosure inside a card that holds its explanations and rare actions.
    public static let details = "Details"
    /// Settings' one-line subtitle.
    public static let subtitle = "This Mac and the app. An iPhone's or iPad's own details are on its page."

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
        /// v0.8.18 Advanced: the extra family filter layer (off by default).
        public static let familyLayer = "Also send every lookup Pax allows through a family filter. "
            + "Stricter, and it can block a few ordinary sites."
        public static let familyLayerRule = "Turning it on is instant. Turning it off takes your turn-off wait, "
            + "and your trusted person is told first."
        public static let securityNotices = "Changes Pax noticed to this Mac's security settings."
    }
}

/// v0.8.23 Settings › Accountability partner email: one line for who it is and its state,
/// plus one button. How Pax sends the email lives in the Change sheet. The rules are
/// unchanged (told before any turn-off wait starts; changing or removing them waits).
public enum PartnerSummary {
    public static let notSet = "Not set"
    /// The one rule, shown in the Change sheet.
    public static let rule = "Optional: someone you trust. Pax tells them before any turn-off wait starts; "
        + "if it can't reach them, the wait doesn't start yet. Changing or removing them takes your turn-off wait."
    public static let unavailable = "Available once this Mac is protected with its key on this Mac. On the "
        + "server path, the server emails them."

    /// The value on the right: their email, or "Not set".
    public static func value(partner: String?) -> String {
        let p = (partner ?? "").trimmingCharacters(in: .whitespaces)
        return p.isEmpty ? notSet : p
    }

    /// The button: "Add…" with no one set, else "Change…".
    public static func button(partner: String?) -> String {
        value(partner: partner) == notSet ? "Add…" : "Change…"
    }

    /// The one state line under it. `pendingWhen` is the formatted date of a waiting change.
    public static func state(partner: String?, available: Bool, pending: Bool = false, pendingEmail: String? = nil,
                             pendingWhen: String? = nil, queued: Int = 0) -> String {
        guard available else { return unavailable }
        if pending {
            let when = pendingWhen.map { " on \($0)" } ?? ""
            if let e = pendingEmail, !e.isEmpty { return "Changing to \(e)\(when)." }
            return "Being removed\(when)."
        }
        let set = value(partner: partner) != notSet
        if set && queued > 0 {
            return queued == 1 ? "1 email waiting to send. Pax keeps trying." : "\(queued) emails waiting to send. Pax keeps trying."
        }
        return set ? "Told before any turn-off wait starts." : "Optional. Someone you trust, told before any turn-off wait starts."
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
