// SPDX-License-Identifier: GPL-3.0-only
// The turn-off wait, as the app shows it. The server's clock is the one that counts:
// the app never clears anything until the server releases the escrowed secret.
import Foundation

enum TurnOffRules {
    static func clampWait(days: Int) -> Int { min(max(days, Pax.minWaitDays), Pax.maxWaitDays) }

    static func inGrace(setUpAt: Date, now: Date) -> Bool {
        now >= setUpAt && now.timeIntervalSince(setUpAt) < Pax.graceSeconds
    }

    /// When a turn-off asked for at `requestedAt` can be confirmed.
    static func unlockDate(setUpAt: Date, waitDays: Int, requestedAt: Date) -> Date {
        if inGrace(setUpAt: setUpAt, now: requestedAt) { return requestedAt }
        return requestedAt.addingTimeInterval(TimeInterval(clampWait(days: waitDays)) * 86_400)
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
