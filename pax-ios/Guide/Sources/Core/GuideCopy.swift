// SPDX-License-Identifier: GPL-3.0-only
// Every word the guide shows, in one place. The step names follow Pax for Mac's iPhone
// path (mac-app SetupFlowView / SetupModel: "iPhone or iPad", Plug in, What to block,
// Turn-off wait, Lock it in, "Protect my iPhone", Find My back on).
import Foundation

public enum PaxLinks {
    /// The Mac download paxpeace.com links to (latest signed, notarised release).
    public static let macDownload = URL(string: "https://github.com/paxtechnologies/pax-apple/releases/latest/download/Pax.dmg")!
    public static let site = URL(string: "https://paxpeace.com")!
    /// The Pax Peace privacy policy.
    public static let privacy = URL(string: "https://paxpeace.com/privacy")!
    public static let supportEmail = "hello@paxpeace.com"
    public static let support = URL(string: "mailto:hello@paxpeace.com")!
    public static let source = URL(string: "https://github.com/paxtechnologies/pax-apple")!
    /// The message that goes with the shared download link.
    public static let shareText = "Pax for Mac (free). Open this on your Mac to download it."
}

public struct GuideStep: Identifiable, Equatable, Sendable {
    public let id: Int          // 1-based, shown as the number
    public let title: String    // one action, plain words
    public let detail: String?  // one short line, or nil
}

public enum GuideCopy {
    /// "iPhone" or "iPad", so the words match the device in hand.
    public static func device(isPad: Bool) -> String { isPad ? "iPad" : "iPhone" }

    public static func tagline(isPad: Bool) -> String {
        "Pax keeps adult and explicit content off this \(device(isPad: isPad)), for you or your family. "
            + "Your Mac sets it up."
    }

    public static func title(isPad: Bool) -> String { "Protect this \(device(isPad: isPad))" }
    public static let subtitle = "With Pax Strict, set up from your Mac."

    public static let needTitle = "What you'll need"
    public static func needs(isPad: Bool) -> [String] {
        let d = device(isPad: isPad)
        return [
            "A Mac (macOS 12 Monterey or later)",
            "A cable to connect this \(d) to the Mac",
            "A backup of this \(d) (Pax for Mac can make one)",
        ]
    }

    public static func steps(isPad: Bool) -> [GuideStep] {
        let d = device(isPad: isPad)
        return [
            GuideStep(id: 1, title: "Get Pax on your Mac.",
                      detail: "Download it from paxpeace.com and open it."),
            GuideStep(id: 2, title: "In Pax, choose “iPhone or iPad”.", detail: nil),
            GuideStep(id: 3, title: "Plug this \(d) into the Mac.",
                      detail: "Unlock it, and tap Trust if it asks."),
            GuideStep(id: 4, title: "Choose what to block.",
                      detail: "Sensible choices are already made."),
            GuideStep(id: 5, title: "Choose your turn-off wait.",
                      detail: "How long Pax takes to turn off after anyone asks."),
            GuideStep(id: 6, title: "Turn off Find My for now.",
                      detail: "Settings › your name › Find My. You'll turn it back on at the end."),
            GuideStep(id: 7, title: "On the Mac, click “Protect my \(d)”.",
                      detail: "Keep it plugged in and unlocked, and follow the Mac. Enter your passcode and tap Trust when asked."),
            GuideStep(id: 8, title: "Turn Find My back on.",
                      detail: "When Pax says you're protected: Settings › your name › Find My."),
            GuideStep(id: 9, title: "Check you're protected.", detail: nil),
        ]
    }

    public static let sendToMac = "Send the link to my Mac"
    public static let copyLink = "Copy link"
    public static let copied = "Copied"

    public static let goodToKnowTitle = "Good to know"
    public static func goodToKnow(isPad: Bool) -> [String] {
        let d = device(isPad: isPad)
        return [
            "Setting up needs a Mac. After that, this \(d) stays protected on its own.",
            "“Keep my data” is the default: your apps, photos and Apple Account stay.",
            "On your first day, you can change your mind instantly.",
            "You can add someone you trust: a friend, a partner or a parent. They're emailed if anyone asks to turn Pax off. They never have to approve anything.",
            "For your family: set Pax up on your child's \(d), choose a long turn-off wait and add yourself as the trusted person. No browsing history is kept, so it protects without spying.",
            "A full restore from a computer erases the \(d) and removes Pax.",
        ]
    }

    public static let comingTitle = "Pax without a Mac"
    public static let comingBody = "We're working on a version of Pax that sets itself up on iPhone and iPad, "
        + "with no Mac needed. Until then, Pax Strict above is the way to protect this device."

    // The check
    public static let checkButton = "Check now"
    public static let checkAgain = "Check again"
    public static let checking = "Checking…"
    public static let checkPrivacy = "Looks up a few addresses on this device. Nothing is stored or sent to Pax."

    public static func resultTitle(_ o: ProtectionCheck.Outcome) -> String {
        switch o {
        case .protected: return "Protected by Pax"
        case .notProtected: return "Not protected"
        case .couldNotCheck(.offline): return "Couldn't check (offline)"
        case .couldNotCheck(.unclear): return "Couldn't check"
        }
    }

    public static func resultDetail(_ o: ProtectionCheck.Outcome, isPad: Bool) -> String {
        let d = device(isPad: isPad)
        switch o {
        case .protected:
            return "This \(d) is looking up websites through Pax's filter."
        case .notProtected:
            return "This \(d) isn't using Pax's filter yet. Follow the steps above. "
                + "If you picked a different filter under Advanced in Pax for Mac, this check can't see it."
        case .couldNotCheck(.offline):
            return "Connect to Wi-Fi or mobile data, then check again."
        case .couldNotCheck(.unclear):
            return "The answers were mixed, so Pax won't guess. Try again in a minute."
        }
    }
}
