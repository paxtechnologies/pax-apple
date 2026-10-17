// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.20: Pax supports macOS 12 Monterey, where the settings app is still called
/// System Preferences and profiles live in their own Profiles pane. macOS 13 renamed
/// it System Settings (profiles under Privacy & Security › Profiles), and macOS 15
/// moved them to General › Device Management. Text and the pane Pax opens follow the
/// Mac's own version.
public struct SystemSettingsPlace: Equatable, Sendable {
    public let macOSMajor: Int

    public init(macOSMajor: Int) { self.macOSMajor = macOSMajor }

    /// This Mac.
    public static var current: SystemSettingsPlace {
        SystemSettingsPlace(macOSMajor: ProcessInfo.processInfo.operatingSystemVersion.majorVersion)
    }

    /// "System Preferences" on macOS 12, "System Settings" on 13 and later.
    public var appName: String { macOSMajor <= 12 ? "System Preferences" : "System Settings" }

    /// Where an installed or downloaded profile is approved.
    public var profilesPath: String {
        switch macOSMajor {
        case ...12: return "Profiles"
        case 13, 14: return "Privacy & Security › Profiles"
        default: return "General › Device Management"
        }
    }

    /// The pane `open` shows for profiles.
    public var profilesPaneURL: String {
        macOSMajor <= 12 ? "x-apple.systempreferences:com.apple.preferences.configurationprofiles"
                         : "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
    }

    /// "System Preferences › Users & Groups" / "System Settings › Users & Groups".
    public var usersPath: String { "\(appName) › Users & Groups" }
}
