// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.21 (Ruben): the sidebar no longer has a "Home" row. The app opens on Home, and
/// a device row (or the Pax logo, the page's "Home" back link, Pax › Home ⇧⌘H) goes
/// back to it. "Blocked sites" is now "Blocked Sites / Apps", and that page says at the
/// top which device it is about and how far its blocks reach.
public enum AppNav {
    /// Sidebar row, compact header link and page title (v0.8.22: title case, like the Pax menu).
    public static let blockedTitle = "Blocked Sites / Apps"
    /// The Pax menu item (menus use title case).
    public static let blockedMenuTitle = "Blocked Sites / Apps"
    /// The rows under the device list, top to bottom. No "Home": the devices are Home.
    public static let sidebarRows = [blockedTitle, "Settings"]
    /// The back link on Settings and on Blocked Sites / Apps.
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

    // MARK: v0.8.27 which devices the page is about

    /// v0.8.27 (Ruben): the page lists only devices Pax is still on. Before, it followed the
    /// sidebar's local set-up record, so a phone that had been turned off (or retired, or was
    /// no longer on the account) kept its "Blocking on …" line and its apps from set-up.
    /// It now uses the same server status as Home (v0.8.26), refreshed on open, when the app
    /// becomes active, and from "Refresh status".
    public enum Subject: Equatable, Sendable {
        case phone(id: String)
        case mac
        /// No device is protected, in a turn-off wait or setting up: a plain empty state.
        case noDevice
    }

    /// One iPhone or iPad as this Mac knows it.
    public struct PhoneEntry: Equatable {
        public let id: String
        /// Set-up hasn't finished on it yet (the local record says so).
        public let settingUp: Bool
        /// The server's state (nil: not fetched yet, or the server couldn't be reached).
        public let state: PhoneStatus.State?
        /// The server answered, but the device isn't on the account any more (retired or gone).
        public let missing: Bool

        public init(id: String, settingUp: Bool, state: PhoneStatus.State?, missing: Bool) {
            self.id = id
            self.settingUp = settingUp
            self.state = state
            self.missing = missing
        }
    }

    /// Shown: setting up, Protected / trial day, a running turn-off wait, and Not checking in
    /// (Pax may still be on it, as its Home card keeps the Turn off controls). Hidden: Turned
    /// off, and not found on the account. With no server answer yet, the last known (set-up)
    /// state stands, so nothing disappears just because the network is down.
    public static func phoneShown(_ p: PhoneEntry) -> Bool {
        if p.settingUp { return true }
        if p.missing { return false }
        if case .turnedOff? = p.state { return false }
        return true
    }

    /// This Mac: shown while it has a Pax device (protected, in a turn-off wait, or still
    /// setting up its profile). Hidden once its wait is over (released) or Pax was removed.
    public static func macShown(hasDevice: Bool, released: Bool, removed: Bool) -> Bool {
        hasDevice && !released && !removed
    }

    /// The device the page is about: the phone picked in the sidebar if Pax is still on it,
    /// else this Mac if Pax is on it, else the first phone still shown, else none.
    public static func subject(selectedPhoneID: String?, phones: [PhoneEntry], macShown: Bool) -> Subject {
        let shown = phones.filter(phoneShown)
        if let sel = selectedPhoneID, shown.contains(where: { $0.id == sel }) { return .phone(id: sel) }
        if macShown { return .mac }
        if let first = shown.first { return .phone(id: first.id) }
        return .noDevice
    }

    /// The empty state.
    public static let emptyTitle = "No devices are protected right now"
    public static let emptyLine = "When Pax is on a device, its blocked sites and apps show here."
}
