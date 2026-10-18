// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.15 "Allow verified support release". In a genuine emergency that Pax support
/// has checked, support can issue a one-time code that removes Pax from ONE device
/// straight away. pax-guard (this Mac's own key) or the Pax server (iPhone and iPad)
/// checks the code (guard/support_code.py), emails the trusted person first, and only
/// then releases. There is no universal code. The app only passes the code on.
public enum VerifiedSupportRelease {
    public static let title = "Allow verified support release"
    /// v0.8.18: the set-up checkbox on the turn-off wait step (ticked by default).
    public static let setUpCheckbox = "Allow verified support release (recommended)"
    /// The one calm line at set-up (the switch sits beside it, on by default).
    public static let setUpDetail = "If you ever face a genuine emergency, Pax support can check it and give you "
        + "a one-time code that removes Pax from this device only. Your trusted person is told first."
    public static let supportIDLabel = "Support ID"
    /// v0.8.27: the one plain line under "Support ID: XXXX" in the turn-off area.
    public static let supportIDLine = "Share this with Pax support if you can't turn Pax off the usual way."
    public static let codeFieldTitle = "I have a support code"
    public static let codePlaceholder = "PAXS-…"
    public static let codeExplainer = "Only for a genuine emergency that Pax support has checked. The code works "
        + "once, on this device only. Your trusted person is told before anything is released."

    /// Set-ups default to on; devices set up before 0.8.15 start off (they never agreed).
    public static let setUpDefault = true

    /// What the Details card says under the switch.
    public static func detail(allowed: Bool, pendingOnAt: Int?, tellingPartner: Bool = false,
                              trialActive: Bool = false) -> String {
        if allowed {
            return "On. Turning it off takes effect straight away."
        }
        if let at = pendingOnAt {
            let when = Date(timeIntervalSince1970: TimeInterval(at)).formatted(date: .abbreviated, time: .shortened)
            return "Turns on \(when), after your turn-off wait. Turning it off cancels that."
        }
        if tellingPartner {
            return "Telling your trusted person first. Your turn-off wait starts once they're told."
        }
        if trialActive {
            // v0.8.18: during the trial day turning it on is instant (Pax can be turned off with no wait anyway).
            return "Off: no support code works on this device. Turning it on is instant during your trial day; "
                + "your trusted person is told."
        }
        return "Off: no support code works on this device. Turning it on takes your full wait, "
            + "and your trusted person is told."
    }

    /// The server's error names for a refused code (escrow.SUPPORT_ERRORS) and their codes.
    public static let apiErrors: [String: String] = [
        "support_code_malformed": "PAX-ESCROW-012",
        "support_code_unverified": "PAX-ESCROW-013",
        "support_code_wrong_device": "PAX-ESCROW-014",
        "support_code_expired": "PAX-ESCROW-015",
        "support_code_used": "PAX-ESCROW-016",
        "support_release_off": "PAX-ESCROW-017",
        "support_partner_unreachable": "PAX-ESCROW-018",
        "support_rate_limited": "PAX-ESCROW-019",
    ]

    /// The code as typed or pasted, tidied once (v0.8.27): upper case; ASCII letters, digits and
    /// dashes kept (typographic dashes read as "-"); everything else dropped, so spaces, tabs,
    /// line breaks, non-breaking and zero-width spaces, quotes and full stops from an email
    /// don't matter. pax-guard and the server tidy the same way (support_code._clean), so this
    /// changes nothing they accept. One pass over the scalars: cheap even for a long paste.
    public static func cleaned(_ code: String) -> String {
        var out = String.UnicodeScalarView()
        for u in code.unicodeScalars {
            switch u.value {
            case 0x61...0x7A: out.append(Unicode.Scalar(u.value - 0x20) ?? u)       // a-z -> A-Z
            case 0x41...0x5A, 0x30...0x39, 0x2D: out.append(u)                     // A-Z 0-9 -
            case 0x2010...0x2015, 0x2212: out.append("-")                          // ‐ ‑ ‒ – — ― −
            default: continue
            }
        }
        return String(out)
    }

    /// Enough to be worth sending (the guard or server does the real check, and only on
    /// "Use support code": nothing is verified while typing or pasting).
    public static func looksComplete(_ code: String) -> Bool {
        cleaned(code).unicodeScalars.lazy.filter { $0 != "-" }.count >= 140
    }
}

/// v0.8.27 (Ruben): the Support ID sits with the turn-off controls (Settings › Turning Pax
/// off for this Mac; each iPhone's or iPad's Turn off card), not under Advanced or Device
/// details. It only shows when a support code could actually work on that device: verified
/// support release is switched on (not off, not still waiting to turn on, and not a device
/// set up before 0.8.15, whose status has no switch), and the device isn't turned off.
public enum SupportIDPlacement {
    /// "Support ID: ABCD-EFGH-IJKL-MNOP"
    public static func label(_ id: String) -> String { "\(VerifiedSupportRelease.supportIDLabel): \(id)" }

    /// The ID to show, or nil to show nothing.
    public static func visibleID(supportID: String?, supportRelease: EscrowClient.DeviceStatus.SupportReleaseState?,
                                 turnedOff: Bool) -> String? {
        guard !turnedOff, supportRelease?.allowed == true,
              let id = supportID?.trimmingCharacters(in: .whitespacesAndNewlines), !id.isEmpty else { return nil }
        return id
    }

    /// From a device status (this Mac's pax-guard or the server's for a phone). Turned off is
    /// released by any route (PhoneStatus.isReleased); `turnedOff` adds what the caller knows
    /// (e.g. this Mac's released phase, or a phone whose removal password is showing).
    public static func visibleID(_ status: EscrowClient.DeviceStatus?, turnedOff: Bool = false) -> String? {
        guard let s = status else { return nil }
        return visibleID(supportID: s.support_id, supportRelease: s.support_release,
                         turnedOff: turnedOff || PhoneStatus.isReleased(s))
    }
}
