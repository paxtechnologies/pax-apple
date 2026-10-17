// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.21 (Ruben): the sidebar no longer has a "Home" row. The app opens on Home, and
/// a device row (or the Pax logo, the page's "Home" back link, Pax › Home ⇧⌘H) goes
/// back to it. "Blocked sites" is now "Blocked sites / apps", and that page says at the
/// top which device it is about and how far its blocks reach.
public enum AppNav {
    /// Sidebar row, compact header link and page title (sentence case like the sidebar).
    public static let blockedTitle = "Blocked sites / apps"
    /// The Pax menu item (menus use title case).
    public static let blockedMenuTitle = "Blocked Sites / Apps"
    /// The rows under the device list, top to bottom. No "Home": the devices are Home.
    public static let sidebarRows = [blockedTitle, "Settings"]
    /// The back link on Settings and on Blocked sites / apps.
    public static let backToHome = "Home"
}

public enum BlockedPage {
    /// Where the user's own blocked sites take effect.
    public enum SitesReach: Equatable, Sendable {
        /// The account's list: every device that uses it (phones, and Macs that sync).
        case allDevices
        /// The account's list while this Mac keeps its own list unsynced.
        case phonesNotThisMac
        /// This Mac's own list, sync off.
        case thisMacOnly
    }

    /// The line at the top: "Blocking on Ruben's MacBook Air".
    public static func deviceLine(name: String?) -> String {
        let n = (name ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return n.isEmpty ? "Blocking on this device" : "Blocking on \(n)"
    }

    /// Which list the page shows, from what the app knows.
    /// - phoneSelected: an iPhone or iPad is picked (the page then shows the account's list).
    /// - macLocalList: this Mac keeps its own list in pax-guard (local key, protected).
    /// - macSyncOn: "Sync blocked sites across devices" is on for this Mac (nil: unknown).
    public static func sitesReach(phoneSelected: Bool, macLocalList: Bool, macSyncOn: Bool?) -> SitesReach {
        if phoneSelected { return macLocalList && macSyncOn == false ? .phonesNotThisMac : .allDevices }
        if macLocalList { return macSyncOn == false ? .thisMacOnly : .allDevices }
        return .allDevices
    }

    public static func sitesLine(_ reach: SitesReach) -> String {
        switch reach {
        case .allDevices:
            return "Sites: applies to all your devices."
        case .phonesNotThisMac:
            return "Sites: applies to all your iPhones and iPads. This Mac keeps its own list while sync is off."
        case .thisMacOnly:
            return "Sites: applies to this Mac only. Turn on sync in Settings › Blocking to use them on all your devices."
        }
    }

    /// Apps are always per device.
    public static func appsLine(phone: Bool, isIPad: Bool = false) -> String {
        phone ? "Apps: this \(isIPad ? "iPad" : "iPhone") only, chosen at set-up."
              : "Apps: this Mac only."
    }
}
