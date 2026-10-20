// SPDX-License-Identifier: GPL-3.0-only
// The turn-off wait, as the app shows it. The server's clock is the one that counts:
// the app never clears anything until the server releases the escrowed secret.
import Foundation

/// Where a turn-off stands, read from the server's device status.
enum TurnOffPhase: Equatable {
    /// Nothing asked for.
    case none
    /// Asked for; the wait runs until this date (on the server's clock).
    case waiting(until: Date)
    /// The wait is over: confirming now releases the secret.
    case ready
    /// The server couldn't be read. Pax stays on and shows nothing new.
    case unknown
}

enum TurnOffRules {
    static func clampWait(days: Int) -> Int { min(max(days, Pax.minWaitDays), Pax.maxWaitDays) }

    static func inGrace(setUpAt: Date, now: Date) -> Bool {
        now >= setUpAt && now.timeIntervalSince(setUpAt) < Pax.graceSeconds
    }

    /// When a turn-off asked for at `requestedAt` can be confirmed (the server decides; this
    /// is only for what the app expects to show).
    static func unlockDate(setUpAt: Date, waitDays: Int, requestedAt: Date) -> Date {
        if inGrace(setUpAt: setUpAt, now: requestedAt) { return requestedAt }
        return requestedAt.addingTimeInterval(TimeInterval(clampWait(days: waitDays)) * 86_400)
    }

    /// The phase from the server's answer. `secondsRemaining` is used rather than the
    /// server's absolute time, so a wrong clock on the phone can't shorten anything.
    /// `requestStatus` nil means no open request.
    static func phase(requestStatus: String?, secondsRemaining: Double?, canReveal: Bool?,
                      now: Date) -> TurnOffPhase {
        guard let status = requestStatus else { return .none }
        switch status {
        case "pending", "revealed":
            if canReveal == true { return .ready }
            guard let left = secondsRemaining else { return .unknown }
            if left <= 0 { return canReveal == false ? .unknown : .ready }
            return .waiting(until: now.addingTimeInterval(left))
        default:
            return .none     // cancelled or lapsed
        }
    }

    /// Server waits are seconds; the app shows whole days, rounded up (never shorter).
    static func days(fromSeconds s: Int) -> Int { max(1, Int((Double(s) / 86_400).rounded(.up))) }

    /// "3 days", "1 week", "2 weeks", "30 days", "3 months", "6 months", "1 year".
    static func waitLabel(days d: Int) -> String {
        switch d {
        case 7: return "1 week"
        case 14: return "2 weeks"
        case 90: return "3 months"
        case 180: return "6 months"
        case 365: return "1 year"
        default: return d == 1 ? "1 day" : "\(d) days"
        }
    }

    /// Calm wording for what's left: "3 days, 4 hours", "2 hours", "less than a minute".
    static func describe(remaining seconds: TimeInterval) -> String {
        if seconds <= 0 { return "ready now" }
        let s = Int(seconds.rounded(.up))
        let d = s / 86_400, h = (s % 86_400) / 3600, m = (s % 3600) / 60
        func unit(_ n: Int, _ w: String) -> String { "\(n) \(w)\(n == 1 ? "" : "s")" }
        if d > 0 { return h > 0 ? "\(unit(d, "day")), \(unit(h, "hour"))" : unit(d, "day") }
        if h > 0 { return m > 0 ? "\(unit(h, "hour")), \(unit(m, "minute"))" : unit(h, "hour") }
        if m > 0 { return unit(m, "minute") }
        return "less than a minute"
    }
}
