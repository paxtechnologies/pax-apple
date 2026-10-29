// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.36 (Ruben, 29 Oct 2026): a calm note beside macOS's "Privacy & Security is trying to modify your
/// system settings" administrator dialog. On a Mac Pax protects, a Standard user who switches on a privacy
/// permission (Accessibility, Full Disk Access, Input Monitoring, Screen Recording...) in System Settings is
/// asked for an administrator's name and password. Pax shows a small floating panel beside that dialog:
///
///     [<App> wants a privacy permission.]          (only when Pax can tell which app)
///     Changing a privacy setting needs an administrator.
///     On this Mac, ask someone you trust to type their password.
///                                                         [OK]
///
/// It only explains. Pax never grants, requests or changes a permission, never reads or edits the privacy
/// database (TCC), never touches the dialog, and offers nothing that would help switch Pax off. Standard
/// accounts on a protected Mac only; administrators see nothing. Same window-list rules, rate limit and
/// once-per-dialog rule as the install panel (AdminPromptHelper), which is unchanged for installers.
public enum PrivacyPromptHelper {
    public static let title = "Changing a privacy setting needs an administrator."
    public static let body = "On this Mac, ask someone you trust to type their password."
    public static let okButton = "OK"

    /// At most one privacy panel this often (same as the install panel).
    public static let rateLimit: TimeInterval = AdminPromptHelper.rateLimit
    /// An app counts as "the app that wants the permission" if it was opened or brought forward this
    /// recently before the dialog and is still running.
    public static let requesterWindow: TimeInterval = 300
    /// Longer names aren't shown (the panel stays one calm line).
    public static let maxNameLength = 32

    /// System Settings (macOS 13+) and System Preferences (12) share this bundle ID; its panes run as
    /// `com.apple.settings.*` extensions.
    public static let systemSettingsBundleID = "com.apple.systempreferences"
    public static let systemSettingsExtensionPrefix = "com.apple.settings."
    public static let systemSettingsOwnerNames: Set<String> = ["System Settings", "System Preferences"]

    public static func isSystemSettings(bundleID: String?) -> Bool {
        guard let b = bundleID?.lowercased(), !b.isEmpty else { return false }
        return b == systemSettingsBundleID || b.hasPrefix(systemSettingsExtensionPrefix)
    }

    public static func isSystemSettings(ownerName: String?, bundleID: String?) -> Bool {
        if let n = ownerName, systemSettingsOwnerNames.contains(n) { return true }
        return isSystemSettings(bundleID: bundleID)
    }

    /// The topmost ordinary (layer 0) window under the dialog that isn't the dialog or Pax: which app the
    /// dialog is in front of. Used when Pax didn't see which app was in front (it was just started by
    /// pax-guard for this dialog).
    public static func appBehindDialog(_ windows: [AdminPromptHelper.WindowInfo], paxBundleID: String?)
        -> AdminPromptHelper.WindowInfo? {
        let pax = paxBundleID?.lowercased()
        return windows.first { w in
            w.layer == 0 && w.alpha > 0.05 && w.bounds.width >= 100 && w.bounds.height >= 60
                && !AdminPromptHelper.isAgent(ownerName: w.ownerName, bundleID: w.ownerBundleID, path: w.ownerPath)
                && !(pax != nil && w.ownerBundleID?.lowercased() == pax)
                && w.ownerName != "Pax"
        }
    }

    /// Is this administrator dialog System Settings asking? The app Pax saw in front just before it, or,
    /// when Pax doesn't know (just started), the app whose window the dialog sits on.
    public static func isSettingsContext(previousApp: String?, behindDialog: AdminPromptHelper.WindowInfo?) -> Bool {
        if let p = previousApp, !p.isEmpty { return isSystemSettings(bundleID: p) }
        guard let w = behindDialog else { return false }
        return isSystemSettings(ownerName: w.ownerName, bundleID: w.ownerBundleID)
    }

    public static func shouldShow(dialog: AdminPromptHelper.WindowInfo, now: Date, lastShown: Date?,
                                  shownWindows: Set<Int>, protected: Bool, isAdmin: Bool,
                                  settingsContext: Bool) -> Bool {
        guard protected, !isAdmin, settingsContext else { return false }
        guard !shownWindows.contains(dialog.number) else { return false }
        if let last = lastShown {
            let gap = now.timeIntervalSince(last)
            if gap >= 0 && gap < rateLimit { return false }
        }
        return true
    }

    /// An app the person recently opened or used (from NSWorkspace launch/activate notifications).
    public struct RecentApp: Equatable, Sendable {
        public let bundleID: String
        public let name: String?
        public let at: Date
        public let running: Bool
        public init(bundleID: String, name: String?, at: Date, running: Bool) {
            self.bundleID = bundleID; self.name = name; self.at = at; self.running = running
        }
    }

    /// The most recent non-Apple, non-Pax app opened or used within `requesterWindow` before `now` and
    /// still running, if it has a short, plain name. nil: Pax can't tell, and the panel names no app.
    public static func requesterName(_ recent: [RecentApp], now: Date, paxBundleID: String?) -> String? {
        let pax = paxBundleID?.lowercased()
        let candidates = recent.filter { r in
            let b = r.bundleID.lowercased()
            let age = now.timeIntervalSince(r.at)
            return r.running && !b.isEmpty && !b.hasPrefix("com.apple.")
                && !b.hasPrefix("org.paxpeace.") && !b.hasPrefix("org.paxmobile.") && b != pax
                && age >= 0 && age <= requesterWindow
        }
        guard let newest = candidates.max(by: { $0.at < $1.at }) else { return nil }
        return displayName(newest.name)
    }

    /// A name safe to put in the panel: one line, no control characters, no ".app", not too long.
    public static func displayName(_ raw: String?) -> String? {
        guard var n = raw else { return nil }
        // Line breaks and tabs become spaces; any other control character is dropped.
        n = String(n.unicodeScalars.compactMap { u -> Character? in
            if CharacterSet.whitespacesAndNewlines.contains(u) { return " " }
            return CharacterSet.controlCharacters.contains(u) ? nil : Character(u)
        })
        n = n.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
        if n.lowercased().hasSuffix(".app") { n = String(n.dropLast(4)).trimmingCharacters(in: .whitespaces) }
        guard !n.isEmpty, n.count <= maxNameLength else { return nil }
        if n == "Pax" { return nil }
        return n
    }

    public static func requesterLine(_ name: String) -> String { "\(name) wants a privacy permission." }
}
