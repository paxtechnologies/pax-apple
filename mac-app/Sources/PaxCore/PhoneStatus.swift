// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.26: what an iPhone's or iPad's Home card says, taken from the Pax server and not
/// from what this Mac remembers. Before 0.8.26 the card kept saying "Protected" after Pax
/// was turned off (a finished turn-off wait, an emergency or trial-day turn-off, or a
/// support code), because it read the local set-up record.
///
/// States, in order of precedence:
///   * Turned off: the server released the removal password (or the request says "revealed").
///   * Turn-off wait running: as before ("Pax turns off in …" / "Telling your trusted person first").
///   * Not checking in: the server has seen no Pax DNS traffic from the account's iPhones and
///     iPads for 48 hours or more (`checking_in == false`). Shown only for a phone that uses
///     Pax's own filter; unknown (nil) never counts.
///   * Trial day, then Protected.
/// Nothing here ever turns protection off; when the server can't be reached the last known
/// state stays, with "Last checked …" under it.
public enum PhoneStatus {
    public enum State: Equatable {
        case protected
        case trial(until: Int)
        case turningOff(secondsLeft: Int, notifying: Bool)
        case turnedOff
        case notCheckingIn(lastSeen: String?)
    }

    /// The mapping, from plain values (testable without a server).
    public static func state(released: Bool, removalStatus: String?, secondsLeft: Int,
                             trial: EscrowClient.DeviceStatus.TrialState?, checkingIn: Bool?,
                             lastSeen: String? = nil, usesPaxFilter: Bool? = nil, now: Date = Date()) -> State {
        if released || removalStatus == "revealed" { return .turnedOff }
        if let r = removalStatus, r == "pending" || r == "notifying" {
            return .turningOff(secondsLeft: secondsLeft, notifying: r == "notifying")
        }
        // A phone set up to use another filter directly never talks to Pax DNS: never "quiet".
        if checkingIn == false, usesPaxFilter != false { return .notCheckingIn(lastSeen: lastSeen) }
        if TrialDay.isActive(trial, now: now), let t = trial { return .trial(until: t.until) }
        return .protected
    }

    /// The same, from the server's device status.
    public static func state(_ s: EscrowClient.DeviceStatus, secondsLeft: Int, usesPaxFilter: Bool? = nil,
                             now: Date = Date()) -> State {
        state(released: isReleased(s), removalStatus: s.removal_request?.status, secondsLeft: secondsLeft,
              trial: s.trial, checkingIn: s.checking_in, lastSeen: s.last_seen,
              usesPaxFilter: usesPaxFilter, now: now)
    }

    /// Released by any route. `released` is new in 0.8.26; `released_at` has always been sent.
    public static func isReleased(_ s: EscrowClient.DeviceStatus) -> Bool {
        s.released == true || s.released_at != nil || s.removal_request?.status == "revealed"
    }

    /// The trial / protected / turn-off states as Home's shared headline knows them.
    public static func homeStatus(_ st: State) -> HomeLayout.Status? {
        switch st {
        case .protected: return .protected
        case .trial(let until): return .trial(until: until)
        case .turningOff(let left, let notifying): return .turningOff(secondsLeft: left, notifying: notifying)
        case .turnedOff, .notCheckingIn: return nil
        }
    }

    // MARK: Words (calm; "turn-off wait", never "unlock")

    public static func headline(_ st: State) -> String {
        switch st {
        case .turnedOff: return "Turned off"
        case .notCheckingIn: return "Not checking in"
        default: return homeStatus(st).map(HomeLayout.headline) ?? "Protected"
        }
    }

    /// The short label under a device in the sidebar.
    public static func sidebarLabel(_ st: State) -> String {
        switch st {
        case .protected, .trial: return "Protected"
        case .turningOff: return "Turn-off wait"
        case .turnedOff: return "Turned off"
        case .notCheckingIn: return "Not checking in"
        }
    }

    /// "Pax is off on Ruben's iPhone."
    public static func offLine(name: String) -> String { "Pax is off on \(name)." }

    public static func offHint(isIPad: Bool) -> String {
        "If Pax's settings are still on the \(isIPad ? "iPad" : "iPhone"), remove them there in Settings › General › "
            + "VPN & Device Management."
    }

    public static let quietLine = "It may have been reset or removed."

    /// "Last seen Thu 15 Oct" from the server's UTC day ("2026-10-15"); nil if unreadable.
    public static func lastSeenLine(_ day: String?, locale: Locale = .current) -> String? {
        guard let day, let date = utcDay(day) else { return nil }
        let f = DateFormatter()
        f.locale = locale
        f.timeZone = TimeZone(identifier: "UTC")
        f.setLocalizedDateFormatFromTemplate("EEE d MMM")
        return "Last seen \(f.string(from: date))"
    }

    static func utcDay(_ day: String) -> Date? {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f.date(from: day)
    }

    // MARK: Remove from list

    public static let removeButton = "Remove from list"
    public static let setUpAgainButton = "Set up again"
    public static func removeTitle(name: String) -> String { "Remove \(name) from the list?" }
    /// Turned off: the server forgets it too.
    public static let removeMessageOff = "This removes it from the list on this Mac."
    /// Not checking in (or not found): Pax may still be on it, so say so.
    public static let removeMessageQuiet = "This removes it from the list on this Mac. If Pax is still on it, Pax stays on."
    /// A protected device (inside Device details): the honest text it has always had.
    public static let removeMessageProtected = "This only tidies the list on this Mac. Pax stays on the device."
    public static let notFoundLine = "Pax can't find this device on your account any more."

    // MARK: Refresh status

    public static let refreshButton = "Refresh status"
    /// The button works at most once every 10 seconds.
    public static let refreshMinInterval: TimeInterval = 10

    public static func canRefresh(lastTap: Date?, now: Date = Date()) -> Bool {
        guard let lastTap else { return true }
        return now.timeIntervalSince(lastTap) >= refreshMinInterval || now < lastTap
    }

    /// "Checked just now", "Last checked 12 min ago", plus a calm note when the last try
    /// failed, so a kept state is never shown as fresh. nil before the first check.
    public static func freshness(lastChecked: Date?, failed: Bool, now: Date = Date()) -> String? {
        guard let lastChecked else { return failed ? "Couldn't reach Pax to check just now." : nil }
        let age = max(0, now.timeIntervalSince(lastChecked))
        let base = (age < 60 && !failed) ? "Checked just now" : "Last checked \(ago(age))"
        return failed ? base + " · couldn't reach Pax just now" : base
    }

    static func ago(_ seconds: TimeInterval) -> String {
        let s = Int(seconds)
        if s < 60 { return "just now" }
        if s < 3600 { return "\(s / 60) min ago" }
        if s < 86_400 { return "\(s / 3600) h ago" }
        let d = s / 86_400
        return d == 1 ? "1 day ago" : "\(d) days ago"
    }
}
