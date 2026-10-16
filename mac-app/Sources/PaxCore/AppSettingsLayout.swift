// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.14 (project decision): one place for settings. The sidebar's "Settings"
/// (and Pax › Settings… ⌘,) opens this screen in the main window; there is no
/// separate Settings window and no per-device "Settings" screen. A device's own
/// details and switches are on its page (click it in the sidebar).
public enum AppSettingsLayout {
    public static let paxMax = "Pax Max"
    public static let partnerEmail = "Accountability partner email"
    public static let updates = "Updates"
    public static let about = "About"
    /// Closed by default: where this Mac keeps its key, the server address, testers' note.
    public static let advanced = "Advanced"
    public static let advancedItems = ["Where this Mac keeps its key", "Pax server", "For testers"]

    /// The sections, top to bottom.
    public static let sections = [paxMax, partnerEmail, updates, about, advanced]
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
