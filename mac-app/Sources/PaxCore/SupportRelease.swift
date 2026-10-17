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

    /// The code as typed or pasted, tidied: spaces and line breaks removed, upper case.
    public static func cleaned(_ code: String) -> String {
        code.uppercased().filter { !$0.isWhitespace }
    }

    /// Enough to be worth sending (the guard or server does the real check).
    public static func looksComplete(_ code: String) -> Bool {
        let letters = cleaned(code).filter { $0.isLetter || $0.isNumber }
        return letters.count >= 140
    }
}
