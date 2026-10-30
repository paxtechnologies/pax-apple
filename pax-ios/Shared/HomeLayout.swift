// SPDX-License-Identifier: GPL-3.0-only
// Home after set-up, simplified (Ruben, 24 Oct 2026: "simple clean minimal and functional"):
//   * Home: the status ("Pax is on", the turn-off wait), the "Make Pax stronger" nudge only while
//     Screen Time isn't locked, and two actions: Blocked sites and Settings.
//   * Settings: everything else, as one-line rows in two groups, with Turn off Pax last.
// The same rule for each variant: a device set up from a Mac only shows that set-up and adds to it
// (no Screen Time lock, no DNS of this app's own, no apps to keep closed, no computer set-up); a
// child's device has YouTube Restricted Mode always on. 1.3: a device set up from a Mac also shows
// Blocked apps (the account's one list, AppsSync) once the server keeps that list; on a server
// without it (404), as in 1.2, it doesn't.
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

    static func protection(macSetUp: Bool, appsList: Bool = false) -> [SettingsItem] {
        if macSetUp {
            return AppsAccess.shows(macSetUp: true, serverHasList: appsList)
                ? [.blockedApps, .blockedSites, .youtube] : [.blockedSites, .youtube]
        }
        return [.lockScreenTime, .encryptedDNS, .appsToClose, .blockedApps, .blockedSites, .youtube]
    }

    static func yourAccount(macSetUp: Bool) -> [SettingsItem] {
        macSetUp ? [.trustedPerson, .turnOffWait, .account]
                 : [.trustedPerson, .turnOffWait, .computerSetup, .account]
    }

    /// Turn off Pax is always reachable, last and on its own (on a Mac set-up it says to turn it
    /// off from Pax on that Mac).
    static let last: [SettingsItem] = [.turnOff]

    static func all(macSetUp: Bool, appsList: Bool = false) -> [SettingsItem] {
        protection(macSetUp: macSetUp, appsList: appsList) + yourAccount(macSetUp: macSetUp) + last
    }
}
