// SPDX-License-Identifier: GPL-3.0-only
// Home after set-up, simplified (Ruben, 24 Oct 2026: "simple clean minimal and functional"):
//   * Home: the status ("Pax is on", the turn-off wait), the "Make Pax stronger" nudge only while
//     Screen Time isn't locked, and two actions: Blocked sites and Settings.
//   * Settings: everything else, as one-line rows in two groups, with Turn off Pax last.
// The same rule for each variant: a device set up from a Mac only shows that set-up and adds to it
// (no Screen Time, no DNS of this app's own, no apps or blocked apps, no computer set-up); a child's device has
// YouTube Restricted Mode always on.
import Foundation

enum SettingsItem: String, CaseIterable, Equatable {
    // Protection
    case lockScreenTime
    case encryptedDNS
    case appsToClose
    case blockedApps
    case blockedSites
    case youtube
    // Your account
    case trustedPerson
    case turnOffWait
    case computerSetup
    case account
    // Last, on its own
    case turnOff
}

enum HomeAction: String, Equatable {
    case blockedSites
    case settings
}

enum HomeLayout {
    /// Home's actions, always the same two.
    static let actions: [HomeAction] = [.blockedSites, .settings]

    /// The "Make Pax stronger" nudge (Lock Screen Time) shows only while it isn't done, and never on
    /// a device set up from a Mac (its Screen Time is the Mac's set-up's).
    static func showsNudge(_ p: PaxPolicy, macSetUp: Bool) -> Bool {
        !macSetUp && StrongerList.nudge(p)
    }

    static func protection(macSetUp: Bool) -> [SettingsItem] {
        macSetUp ? [.blockedSites, .youtube]
                 : [.lockScreenTime, .encryptedDNS, .appsToClose, .blockedApps, .blockedSites, .youtube]
    }

    static func yourAccount(macSetUp: Bool) -> [SettingsItem] {
        macSetUp ? [.trustedPerson, .turnOffWait, .account]
                 : [.trustedPerson, .turnOffWait, .computerSetup, .account]
    }

    /// Turn off Pax is always reachable, last and on its own (on a Mac set-up it says to turn it
    /// off from Pax on that Mac).
    static let last: [SettingsItem] = [.turnOff]

    static func all(macSetUp: Bool) -> [SettingsItem] {
        protection(macSetUp: macSetUp) + yourAccount(macSetUp: macSetUp) + last
    }
}
