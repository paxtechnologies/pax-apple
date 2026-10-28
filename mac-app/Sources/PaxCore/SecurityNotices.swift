// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.23 (Ruben): Settings › Advanced › Security notices (and Home's "things to know")
/// listed every "dns:fallback on/off" pair, one each time pax-guard restarted after an
/// update (its filter starts on the backup until the lists load and the self-check
/// passes). Those aren't security changes. pax-guard still writes every one to the
/// tamper log; the app now shows a backup-filter episode only when it lasted at least
/// 10 minutes, in plain words, and never shows a raw log code. Real changes still show.
public enum SecurityNotices {
    /// Backup episodes shorter than this are not shown.
    public static let briefFallbackSeconds = 600
    public static let fallbackOn = "dns:fallback_on"
    public static let fallbackOff = "dns:fallback_off"

    public struct Notice: Equatable, Sendable {
        public let ts: Int
        public let text: String
    }

    /// Plain sentence for each kind pax-guard logs (no time, no full stop).
    public static func sentence(_ kind: String) -> String {
        switch kind {
        case "changed:admins": return "The list of administrators on this Mac changed"
        case "changed:paxadmin": return "Pax's administrator account on this Mac changed"
        case "changed:volume_owners": return "The accounts that can unlock this Mac's disk changed"
        case "changed:secure_token": return "The accounts allowed to unlock FileVault changed"
        case "changed:filevault": return "FileVault on this Mac was switched on or off"
        case "changed:recovery_key": return "This Mac's FileVault recovery key changed"
        case "changed:mdm": return "This Mac's device management enrolment changed"
        case "changed:startup_security": return "This Mac's startup security setting changed"
        case "changed:firmware": return "This Mac's firmware password setting changed"
        case "changed:sip": return "System Integrity Protection on this Mac changed"
        case "changed:guard_files": return "Pax's own background files on this Mac changed"
        case "changed:runtime": return "Some of Pax's own files on this Mac changed, and Pax repaired what it could"
        case "changed:login_agent": return "Pax's open-at-login item was removed or switched off, and Pax put it back"
        case "changed:installs_agent": return "Pax's install helper was removed or switched off, and Pax put it back"
        case "changed:pax_app": return "Pax was removed from Applications, and Pax put it back"
        case "accounts:made_standard": return "Pax made an account on this Mac a standard account again"
        case "admin:made_standard_again": return "An account was made an administrator, so Pax made it a standard account again"
        case "clock_backwards": return "This Mac's clock was set back"
        case "clock_forward": return "This Mac's clock jumped forward"
        case "trial_ended_early": return "The trial day was ended early"
        case "support_release_setting": return "Verified support release was changed"
        case "support_release_used": return "A verified support code was used"
        case "support_code_refused": return "A support code was refused"
        case "setting:adblock": return "Ads and trackers was switched"
        case "setting:youtube_restricted": return "YouTube Restricted Mode was switched"
        case "setting:pax_max": return "Pax Max was switched"
        case "setting:pax_max_off_requested": return "Turning off Pax Max was asked for"
        case "setting:pax_max_off_cancelled": return "Turning off Pax Max was cancelled"
        case "setting:family_layer": return "The extra family filter layer was switched"
        case "setting:family_layer_off_requested": return "Turning off the extra family filter layer was asked for"
        case "filters:pack_refused": return "A filter list update didn't pass Pax's checks, so Pax kept the lists it had"
        case "filters:pack_rolled_back": return "New filter lists failed Pax's self-test, so Pax went back to the previous lists"
        case fallbackOn, fallbackOff: return "Pax used its backup family filter for a while. You stayed protected"
        default:
            if kind.hasPrefix("changed:") { return "Pax noticed a change to this Mac's security settings" }
            if kind.hasPrefix("setting:") { return "A Pax setting on this Mac was changed" }
            return "Pax noticed a change on this Mac"
        }
    }

    /// "25 minutes", "1 hour 5 minutes", "3 hours".
    public static func duration(_ seconds: Int) -> String {
        let m = max(1, seconds / 60)
        if m < 60 { return m == 1 ? "1 minute" : "\(m) minutes" }
        let h = m / 60, r = m % 60
        let hs = h == 1 ? "1 hour" : "\(h) hours"
        return r == 0 ? hs : hs + " " + (r == 1 ? "1 minute" : "\(r) minutes")
    }

    static func day(_ ts: Int) -> String {
        Date(timeIntervalSince1970: TimeInterval(ts)).formatted(.dateTime.day().month(.abbreviated))
    }

    static func time(_ ts: Int) -> String {
        Date(timeIntervalSince1970: TimeInterval(ts)).formatted(date: .omitted, time: .shortened)
    }

    public static func fallbackEpisode(seconds: Int, startedAt: Int) -> String {
        "Pax used its backup family filter for \(duration(seconds)) on \(day(startedAt)) (its own filter wasn't "
            + "ready or didn't pass a self-check). You stayed protected."
    }

    public static func fallbackOngoing(since: Int) -> String {
        "Pax has been using its backup family filter since \(time(since)) on \(day(since)) (its own filter "
            + "isn't ready or didn't pass a self-check). You're still protected."
    }

    /// The notices to show, oldest first: each backup episode of 10 minutes or more as one
    /// line (an episode still running counts from its start), brief ones dropped, a stray
    /// "back on Pax's filter" with no start dropped, every other event as its sentence.
    public static func visible(_ events: [GuardClient.TamperEvent], now: Date = Date()) -> [Notice] {
        var out: [Notice] = []
        var openSince: Int?
        for e in events.sorted(by: { $0.ts < $1.ts }) {
            switch e.kind {
            case fallbackOn:
                if openSince == nil { openSince = e.ts }
            case fallbackOff:
                if let start = openSince {
                    let d = e.ts - start
                    if d >= briefFallbackSeconds { out.append(Notice(ts: start, text: fallbackEpisode(seconds: d, startedAt: start))) }
                    openSince = nil
                }
            default:
                out.append(Notice(ts: e.ts, text: HomeLayout.tamperNotice(kind: e.kind, at: e.ts)))
            }
        }
        if let start = openSince, Int(now.timeIntervalSince1970) - start >= briefFallbackSeconds {
            out.append(Notice(ts: start, text: fallbackOngoing(since: start)))
        }
        return out.sorted { $0.ts < $1.ts }
    }
}
