// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.16: plain words for "the wait" (new users found the bare word confusing).
/// The wait is how long turning Pax off takes after you ask; the same wait applies to
/// any other loosening (unblocking a site or an app, a shorter wait, a new trusted person).
/// Everywhere else in the app it's called the "Turn-off wait".
public enum TurnOffWait {
    /// The set-up step.
    public static let setupTitle = "How long should turning Pax off take?"
    public static let setupHelp = "If you ever decide to switch Pax off, you'll ask first, then wait this long "
        + "before it turns off. You can cancel any time during the wait. Choose a time that would outlast a bad night."
    /// One quiet line under the choices: the same wait covers other loosenings.
    public static let setupAlsoApplies = "The same wait applies before a blocked site or app is unblocked."
    /// The step's short name in the progress bar.
    public static let stepTitle = "Turn-off wait"
    /// The name used everywhere after set-up, e.g. "Turn-off wait: 7 days".
    public static let label = "Turn-off wait"
    /// The first-hour grace, said the same way everywhere.
    public static let firstHour = "For your first hour, you can change your mind instantly."

    /// "Turn-off wait: 7 days".
    public static func row(seconds: Int) -> String { "\(label): \(duration(seconds: seconds))" }

    /// A wait length in plain words: "24 hours", "3 days", "7 days", "30 days", "36 hours".
    public static func duration(seconds: Int) -> String {
        let s = max(0, seconds)
        if s >= 2 * 86_400, s % 86_400 == 0 { return "\(s / 86_400) days" }
        if s >= 2 * 86_400, s % 3600 == 0 { return "\(s / 3600) hours" }
        if s >= 2 * 86_400 { return "\(s / 86_400) days" }
        if s >= 3600 {
            let h = s / 3600
            return h == 1 ? "1 hour" : "\(h) hours"
        }
        let m = max(1, s / 60)
        return m == 1 ? "1 minute" : "\(m) minutes"
    }

    /// The same, from a whole number of days (the set-up choices): "24 hours", "3 days".
    public static func duration(days: Int) -> String {
        days == 1 ? "24 hours" : "\(days) days"
    }

    /// A set-up choice's label: "1 day", "3 days", "7 days", "30 days".
    public static func choiceTitle(days: Int) -> String {
        days == 1 ? "1 day" : "\(days) days"
    }

    /// Time left, calm and readable: "2 days 14 h", "5 h 03 min", "12 min 09 s".
    public static func countdown(seconds: Int) -> String {
        let s = max(0, seconds)
        let d = s / 86_400, h = (s % 86_400) / 3600, m = (s % 3600) / 60, sec = s % 60
        if d > 0 { return "\(d) day\(d == 1 ? "" : "s") \(h) h" }
        if h > 0 { return String(format: "%d h %02d min", h, m) }
        return String(format: "%d min %02d s", m, sec)
    }

    /// "Pax turns off in 2 days 14 h" (the card puts "· Cancel" beside it as a button).
    public static func turnsOffIn(seconds: Int) -> String {
        seconds > 0 ? "Pax turns off in \(countdown(seconds: seconds))" : "Your turn-off wait is over."
    }
}
