// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.12 Pax Max wording, shared by set-up and Settings (project decision):
/// what it does before choosing, an honest note that it isn't perfect, what
/// happens after, and the rule for turning it off (partner first, then 1 hour).
public enum PaxMax {
    public static let offDelaySeconds = 3600

    public static let title = "Pax Max: blur images everywhere"

    /// Before choosing: what it does.
    public static let explanation = "Pax Max blurs pictures and video in Firefox on this Mac until a check "
        + "on this Mac finds them safe. Nothing you see is sent anywhere."

    /// Before choosing: the honest warning.
    public static let warning = "It isn't perfect. It can sometimes blur or hide ordinary pictures and video "
        + "too. If that gets in the way, you can turn it off; that takes 1 hour."

    /// The rule, in Settings.
    public static let rule = "Turning it on works straight away. Turning it off takes effect after 1 hour, "
        + "and your trusted person is told first if you've added one. You can cancel during that hour."

    /// At set-up, under the switch.
    public static let setUpDetail = explanation + " " + warning + " You can also turn it on later in Settings."

    /// Confirmations (after choosing).
    public static let turnedOn = "Pax Max is on. Pictures and video in Firefox stay blurred until they look safe. "
        + "If it hides things you need, you can turn it off in Settings; that takes 1 hour."
    public static let offRequested = "Pax Max turns off in 1 hour. Until then it keeps working, and you can "
        + "change your mind."
    public static let turnedOff = "Pax Max is off. Pictures and video in Firefox show as normal. You can turn "
        + "it on again any time."

    /// Asked before starting the hour.
    public static let confirmOffTitle = "Turn off Pax Max?"
    public static let confirmOffMessage = "Turning this off takes effect after 1 hour. Your trusted person is "
        + "told first, if you've added one. You can cancel until then."
    public static let confirmOnTitle = "Turn on Pax Max?"
    public static let confirmOnMessage = explanation + " " + warning

    /// Settings description for each state.
    public static func status(on: Bool?, pendingSeconds: Int?) -> String {
        if let s = pendingSeconds, on == true {
            let minutes = max(1, (s + 59) / 60)
            return "Pax Max is on and turns off in \(minutes) minute\(minutes == 1 ? "" : "s"). "
                + "You can change your mind until then."
        }
        switch on {
        case .some(true): return "Pax Max is on. Pictures and video in Firefox are blurred until they look safe."
        case .some(false): return "Pax Max is off."
        case .none: return "Pax Max was chosen when Pax was set up. Set Pax up again to switch it here."
        }
    }
}
