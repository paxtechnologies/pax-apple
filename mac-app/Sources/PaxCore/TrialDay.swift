// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(IOKit)
import IOKit
#endif

/// v0.8.18 trial day. On a genuinely new set-up the first 24 hours are a trial: Pax can
/// be turned off any time with no turn-off wait, so people can try it fully before
/// committing. After 24 hours the chosen turn-off wait applies by itself.
///
/// The app only ASKS for a trial; whoever holds the key decides. pax-guard (this Mac's
/// own key) anchors it in a marker that removing Pax leaves behind; the Pax server
/// (iPhone, iPad, or a Mac on the server path) anchors it in the account and a hash of
/// the hardware ID. Setting up again only ever gets what's left of the first day. The
/// trusted person, if there is one, is still told before Pax turns off.
public enum TrialDay {
    /// New set-ups ask for one.
    public static let setUpDefault = true
    public static let seconds = 86_400

    public static let title = "Trial day"
    /// The set-up line (replaces the old "first hour" line on the wait step).
    public static let setUpLine = "First time setting up Pax? Your first 24 hours are a trial day: you can turn Pax "
        + "off any time, with no wait. After that, your turn-off wait applies by itself."
    public static let startWaitButton = "Start my wait now"
    public static let confirmTitle = "End your trial day now?"
    public static let confirmMessage = "From now on, turning Pax off takes your turn-off wait. This can't be undone."

    /// "Trial day · turn off anytime until Sat 18 Oct at 12:43".
    public static func homeLine(until: Int, calendar: Calendar = .current, locale: Locale = .current) -> String {
        "\(title) · turn off anytime until \(when(until, calendar: calendar, locale: locale))"
    }

    /// The gentle countdown under it: "23 h 10 min left" / "Ends in 4 min 05 s".
    public static func countdown(secondsLeft: Int) -> String {
        let s = max(0, secondsLeft)
        if s == 0 { return "Your trial day is over. Your turn-off wait now applies." }
        return "\(TurnOffWait.countdown(seconds: s)) left"
    }

    /// The iPhone "You're protected" screen (the trial may or may not apply to a re-set-up).
    public static let doneLine = "Home shows how long you can still turn Pax off with no wait."

    /// The Turn off card's caption while the trial lasts.
    public static let turnOffCaption = "No wait today: it's your trial day. Your trusted person, if you added one, is told."

    /// Settings › Turning Pax off: the one-line state.
    public static func settingsLine(_ t: EscrowClient.DeviceStatus.TrialState?, now: Date = Date()) -> String? {
        guard let t else { return nil }
        if t.active, t.until > Int(now.timeIntervalSince1970) {
            return "Trial day until \(when(t.until)). Until then, turning Pax off needs no wait."
        }
        if let ended = t.ended_at {
            return "Trial day ended early on \(when(ended)). Your turn-off wait applies."
        }
        return nil
    }

    /// Is the trial running at `now`?
    public static func isActive(_ t: EscrowClient.DeviceStatus.TrialState?, now: Date = Date()) -> Bool {
        guard let t, t.active else { return false }
        return t.until > Int(now.timeIntervalSince1970)
    }

    public static func secondsLeft(_ t: EscrowClient.DeviceStatus.TrialState?, now: Date = Date()) -> Int {
        guard isActive(t, now: now), let t else { return 0 }
        return max(0, t.until - Int(now.timeIntervalSince1970))
    }

    static func when(_ ts: Int, calendar: Calendar = .current, locale: Locale = .current) -> String {
        let f = DateFormatter()
        f.calendar = calendar
        f.locale = locale
        f.timeZone = calendar.timeZone
        f.setLocalizedDateFormatFromTemplate("EEE d MMM HH:mm")
        return f.string(from: Date(timeIntervalSince1970: TimeInterval(ts)))
    }

    /// What the app sends the server as `hardware_id`: hex SHA-256 of a namespaced
    /// hardware identifier (an iPhone's ECID, a Mac's hardware UUID). The server
    /// hashes it again; the raw identifier never leaves the Mac.
    public static func hardwareID(_ raw: String) -> String? {
        let t = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !t.isEmpty else { return nil }
        return SHA256Hex.hash(Data(("pax-hw-v1:" + t).utf8))
    }

    /// This Mac's hardware UUID (IOPlatformUUID), for a Mac set up on the server path.
    public static func thisMacHardwareID() -> String? {
        #if canImport(IOKit)
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        guard let cf = IORegistryEntryCreateCFProperty(service, "IOPlatformUUID" as CFString,
                                                       kCFAllocatorDefault, 0)?.takeRetainedValue(),
              let uuid = cf as? String else { return nil }
        return hardwareID(uuid)
        #else
        return nil
        #endif
    }
}

/// v0.8.18 Home in three calm steps: 1 Status, 2 What's blocked, 3 Turn off. These are
/// the words and small decisions, kept here so they can be tested on any machine.
public enum HomeLayout {
    public static let statusTitle = "Status"
    public static let blockedTitle = "What's blocked"
    public static let turnOffTitle = "Turn off"
    /// The three cards, top to bottom.
    public static let steps = [statusTitle, blockedTitle, turnOffTitle]

    public enum Status: Equatable {
        case protected
        case trial(until: Int)
        case turningOff(secondsLeft: Int, notifying: Bool)
        case released
    }

    /// One big calm state. A running turn-off wins over the trial, which wins over plain "Protected".
    public static func status(removalStatus: String?, secondsLeft: Int, trial: EscrowClient.DeviceStatus.TrialState?,
                              now: Date = Date()) -> Status {
        if let r = removalStatus, ["pending", "notifying", "revealed"].contains(r) {
            if r == "revealed" { return .released }
            return .turningOff(secondsLeft: secondsLeft, notifying: r == "notifying")
        }
        if TrialDay.isActive(trial, now: now), let t = trial { return .trial(until: t.until) }
        return .protected
    }

    public static func headline(_ s: Status) -> String {
        switch s {
        case .protected, .trial: return "Protected"
        case .turningOff(let left, let notifying):
            return notifying ? "Telling your trusted person first" : TurnOffWait.turnsOffIn(seconds: left)
        case .released: return "Your turn-off wait is over"
        }
    }

    /// "1 thing to know", "2 things to know"; nil when there's nothing.
    public static func noticesSummary(count: Int) -> String? {
        guard count > 0 else { return nil }
        return count == 1 ? "1 thing to know" : "\(count) things to know"
    }

    /// "12 sites", "1 site", "No sites yet".
    public static func sitesCount(_ n: Int) -> String {
        n == 0 ? "No sites yet" : n == 1 ? "1 site" : "\(n) sites"
    }

    public static func appsCount(_ n: Int) -> String {
        n == 0 ? "No apps yet" : n == 1 ? "1 app" : "\(n) apps"
    }

    /// Only when something is unusual (the backup filter, nothing reachable, starting up).
    /// The normal filter isn't worth a line on Home. v0.8.18: Pax's own filter (with or
    /// without the extra family layer) is normal; its backup is not. An older pax-guard
    /// (no filter_mode) is normal on its first family upstream only.
    public static func filterNeedsNotice(_ dns: GuardClient.Status.DNS?) -> Bool {
        guard let dns else { return false }
        if dns.ready == false || dns.all_down == true { return true }
        switch dns.filter_mode {
        case "pax", "family-layer": return false
        case "fallback": return true
        default: break
        }
        return dns.active == nil || dns.active != "CleanBrowsing Family"
    }

    /// "Pax noticed a change to this Mac's security settings (sip, 17 Oct 2026 at 12:43)."
    public static func tamperNotice(kind: String, at ts: Int) -> String {
        let what = kind.replacingOccurrences(of: "changed:", with: "").replacingOccurrences(of: "_", with: " ")
        return "Pax noticed a change to this Mac's security settings (\(what), "
            + Date(timeIntervalSince1970: TimeInterval(ts)).formatted(date: .abbreviated, time: .shortened) + ")."
    }

    /// The one line under "What's blocked".
    public static let blockedFootnote = "Blocking is instant. Unblocking takes your turn-off wait."

    /// The Turn off card's caption when nothing is running.
    public static func turnOffCaption(waitSeconds: Int?, trialActive: Bool) -> String {
        if trialActive { return TrialDay.turnOffCaption }
        let wait = waitSeconds.map { TurnOffWait.duration(seconds: $0) } ?? "your turn-off wait"
        return "Takes \(wait) after you ask. You can cancel any time during the wait."
    }

    /// The button: one action whatever the state.
    public static func turnOffButton(trialActive: Bool) -> String {
        trialActive ? "Turn Pax off" : "Start the turn-off wait"
    }
}
