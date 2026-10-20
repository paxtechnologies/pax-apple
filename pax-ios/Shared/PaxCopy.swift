// SPDX-License-Identifier: GPL-3.0-only
// The words the app shows, in one place, so they can be checked by tests: calm and
// warm, for individuals and families, "adult and explicit content", "someone you
// trust", "turn-off wait", honest about the limits, and always pointing to setting up
// from a Mac for the strongest protection.
import Foundation

enum PaxCopy {
    static func device(isPad: Bool) -> String { isPad ? "iPad" : "iPhone" }

    // MARK: setting up from a Mac (shown on Welcome, Home and in the set-up summary)

    static let macNoteTitle = "Strongest protection"
    static func macNote(isPad: Bool) -> String {
        "For the strongest protection, set Pax up from a Mac. It locks this \(device(isPad: isPad)) "
            + "more firmly and can't be switched off in Settings."
    }
    static let macLink = "How to set up from a Mac"
    static func macSummaryLine(isPad: Bool) -> String {
        "For the strongest protection, set Pax up from a Mac instead."
    }
    static let macSheetTitle = "Set up from a Mac"
    static func macSheetIntro(isPad: Bool) -> String {
        "Setting Pax up from a Mac locks this \(device(isPad: isPad)) more firmly: it can't be "
            + "switched off in Settings, and your photos and messages stay. It's free, like this app."
    }
    static let macSheetMore = "More at paxpeace.com"

    // MARK: welcome

    static let welcomeTitle = "Your calm self, in charge."
    static func welcomeBody(isPad: Bool) -> String {
        "Pax keeps adult and explicit content off this \(device(isPad: isPad)), for you or for your family. "
            + "If anyone ever wants it off, it turns off only after a wait chosen in advance."
    }
    static let welcomeFree = "Free and open source. Pax never keeps your browsing history."
    static let begin = "Begin"

    // MARK: who it's for

    static let audienceTitle = "Who is Pax for?"
    static let audienceMe = "Me"
    static func audienceMeDetail(isPad: Bool) -> String { "This is my \(device(isPad: isPad))." }
    static let audienceChild = "My child"
    static func audienceChildDetail(isPad: Bool) -> String {
        "I'm a parent setting Pax up on my child's \(device(isPad: isPad)), with them."
    }

    // MARK: account

    static func emailTitle(_ a: PaxAudience) -> String { a == .child ? "Your email" : "Your email" }
    static func emailBody(_ a: PaxAudience) -> String {
        a == .child
            ? "Use your own email, not your child's. Pax emails you if anyone asks to turn it off."
            : "Pax sends you a code to sign in, and copies of your own requests. Nothing else."
    }
    static let sendCode = "Send me a code"
    static let codeTitle = "Check your email"
    static func codeBody(email: String) -> String { "Enter the 6-digit code Pax sent to \(email). It works for 15 minutes." }
    static let codeContinue = "Continue"
    static let codeResend = "Send a new code"

    // MARK: someone you trust

    static func trustedTitle(_ a: PaxAudience) -> String {
        a == .child ? "Someone else you trust" : "Someone you trust"
    }
    static func trustedBody(_ a: PaxAudience) -> String {
        a == .child
            ? "Optional. Another parent or carer can be emailed too if anyone asks to turn Pax off."
            : "Optional. A friend, a partner or a parent. They're emailed if anyone asks to turn Pax off."
    }
    static let trustedWitness = "They never approve or stop anything. If the email to them can't be sent, nothing is turned off."
    static func trustedExisting(_ email: String) -> String { "Your account already has a trusted person: \(email)." }
    static let trustedSkip = "Not now"

    // MARK: turn-off wait

    static let waitTitle = "Your turn-off wait"
    static let waitBody = "If anyone asks to turn Pax off, it happens only after this wait. Hard moments pass; the wait lets them."
    static let waitGrace = "For the first hour after set-up there's no wait, in case you change your mind."
    static func waitKept(_ days: Int) -> String {
        "Your account already has a longer wait (\(TurnOffRules.waitLabel(days: days))), so Pax keeps it."
    }

    // MARK: Screen Time access

    static let accessTitle = "Screen Time access"
    static func accessBody(isPad: Bool) -> String {
        "\(device(isPad: isPad)) asks once, with Face ID or your passcode. This lets Pax switch on the "
            + "adult-site filter and stop itself being deleted."
    }
    static let accessButton = "Allow Screen Time access"
    static let accessDenied = "Screen Time access wasn't given, so Pax can't protect this device yet."

    // MARK: apps and sites

    static let appsTitle = "Apps and sites to keep closed"
    static let appsBody = "Choose any you'd like closed, such as X, Bluesky or browsers you don't trust. "
        + "Pax only gets an anonymous token for each, never a list of your apps."
    static let appsBrowsers = "Pax also closes a few browsers that can get round the filter."
    static let appsChoose = "Choose apps and sites"
    static func appsChosen(_ n: Int) -> String { n == 0 ? "Nothing chosen yet." : "\(n) chosen." }

    // MARK: Pax passcode

    static let passcodeTitle = "Lock Screen Time"
    static let passcodeBody = "This is what makes Pax hard to remove. Pax makes up a Screen Time passcode, "
        + "you type it into Settings once, and Pax keeps it safe until your turn-off wait ends."
    static let passcodeToggle = "Use a Pax passcode (recommended)"
    static let passcodeSkipWarning = "Without it, Face ID can switch Pax's Screen Time access off at any time."
    static func passcodeSteps(isPad: Bool) -> [String] {
        [
            "Open Settings › Screen Time and tap Lock Screen Time Settings (or Use Screen Time Passcode).",
            "Type the four digits below. Hold a box to see its digit.",
            "When \(device(isPad: isPad)) asks for an Apple Account for recovery, tap Cancel. Otherwise the passcode could be reset.",
        ]
    }
    static let passcodeDone = "I've set it"
    static let passcodeAfter = "Pax has already saved this passcode. It's shown again only when your turn-off wait ends."

    // MARK: switching Pax on

    static let lockTitle = "Ready to switch Pax on"
    static func lockLines(isPad: Bool, trusted: Bool, waitDays: Int) -> [String] {
        var l = [
            "Adult and explicit websites are blocked.",
            "Pax can't be deleted from this \(device(isPad: isPad)).",
            "Turning Pax off takes your turn-off wait: \(TurnOffRules.waitLabel(days: waitDays)).",
        ]
        if trusted { l.append("Your trusted person is emailed first if anyone asks to turn it off.") }
        return l
    }
    static let lockButton = "Switch Pax on"

    // MARK: encrypted DNS

    static let dnsTitle = "Encrypted DNS"
    static let dnsBody = "An extra layer that filters apps as well as websites, through Pax's own filter. "
        + "After you tap Add, open Settings › General › VPN & Device Management › DNS and choose Pax."
    static func dnsHonest(trusted: Bool) -> String {
        "Anyone can switch this layer off in Settings. If it's off, Pax shows it here"
            + (trusted ? " and emails your trusted person." : " and emails you.")
    }
    static let dnsAdd = "Add encrypted DNS"
    static let dnsOpenSettings = "Open Settings"
    static let dnsSkip = "Skip for now"

    // MARK: honest limits (set-up summary and Home)

    static let limitsTitle = "Good to know"
    static func limits(isPad: Bool, passcode: Bool) -> [String] {
        let d = device(isPad: isPad)
        var l = [
            "A full erase or a restore from a computer removes Pax.",
            "Anyone holding this \(d) can switch the encrypted DNS off in Settings. Pax notices and says so.",
        ]
        if !passcode { l.append(passcodeSkipWarning) }
        l.append(macSummaryLine(isPad: isPad))
        return l
    }

    static let doneTitle = "Pax is on"
    static let doneButton = "Done"

    // MARK: Home

    static let homeOn = "Pax is on"
    static let homeAccessLost = "Pax's Screen Time access is off"
    static func homeAccessLostBody(isPad: Bool, trusted: Bool) -> String {
        "Someone switched it off in Settings, so Pax can't protect this \(device(isPad: isPad)) right now."
            + (trusted ? " Your trusted person has been told." : "")
    }
    static let homeFilter = "Adult and explicit sites are blocked"
    static let homeDelete = "Pax can't be deleted"
    static let homePasscodeKept = "Pax keeps the Screen Time passcode"
    static let homeNoPasscode = "No Pax passcode: Face ID can switch Pax off"
    static let homeDNSOn = "Encrypted DNS is on"
    static let homeDNSOff = "Encrypted DNS is off. Turn it on in Settings › General › VPN & Device Management › DNS."
    static let homeDNSNotAdded = "Encrypted DNS isn't added yet"
    static func homeTrusted(_ email: String?) -> String {
        if let e = email, !e.isEmpty { return "Trusted person: \(e)" }
        return "No trusted person"
    }
    static func homeWait(_ days: Int) -> String { "Turn-off wait: \(TurnOffRules.waitLabel(days: days))" }
    static let homeGrace = "First hour: you can still turn Pax off with no wait."

    static let sitesTitle = "Your blocked sites"
    static let sitesFooter = "Adding a site is instant. Removing one takes your turn-off wait."
    static let sitesAdd = "Add"

    static let turnOffTitle = "Turn off Pax"
    static func turnOffIdle(trusted: Bool) -> String {
        "You can always turn Pax off. It takes your turn-off wait"
            + (trusted ? ", and your trusted person is emailed first." : ".")
    }
    static let turnOffAsk = "Ask to turn off"
    static let turnOffConfirmTitle = "Start your turn-off wait?"
    static func turnOffConfirmBody(trusted: Bool) -> String {
        (trusted ? "Your trusted person is emailed first. If the email can't be sent, nothing starts. " : "")
            + "You can cancel at any time during the wait."
    }
    static let turnOffStart = "Start the wait"
    static let keepOn = "Keep Pax on"
    static func turnOffWaiting(_ left: String) -> String { "You can turn Pax off in \(left)." }
    static let turnOffReady = "Your wait has ended."
    static let turnOffNow = "Turn off now"
    static let turnOffUnknown = "Pax couldn't reach its server. Pax stays on until it can."

    static let releasedTitle = "Pax is off"
    static let releasedPasscode = "Your Screen Time passcode is:"
    static let releasedHowTo = "To remove it: Settings › Screen Time › Change Screen Time Passcode › Turn Off Screen Time Passcode."
    static let releasedNoPasscode = "Pax's settings have been removed from this device. You can delete the app now."

    // MARK: account

    static let accountTitle = "Account"
    static let privacy = "Privacy policy"
    static let support = "Email Pax support"
    static let deleteTitle = "Delete my account"
    static func deleteBody(isActive: Bool) -> String {
        var s = "This deletes your email, trusted person, devices and blocked sites from the Pax server."
        if isActive {
            s += " Pax stays on this device after your account is deleted, and the Screen Time passcode Pax keeps "
                + "can't be given back. If you want it back, turn Pax off first (it takes your turn-off wait)."
        }
        return s
    }
    static let deleteConfirm = "Delete my account"
    static let deleteDone = "Your Pax account has been deleted."
    static let deleteRequested = "Your request is ready to send in your email app. Pax support deletes the account "
        + "and replies to confirm. Send it from your account's email address."
    static func deleteMailBody(email: String, accountRef: String) -> String {
        "Please delete my Pax account.\n\nAccount email: \(email)\nAccount reference: \(accountRef)\n\nSent from the Pax app on iPhone or iPad."
    }
    static let deleteMailSubject = "Delete my Pax account"

    /// Every visible string, for the copy tests.
    static func all(isPad: Bool) -> [String] {
        var out: [String] = [
            macNoteTitle, macNote(isPad: isPad), macLink, macSummaryLine(isPad: isPad), macSheetTitle,
            macSheetIntro(isPad: isPad), macSheetMore,
            welcomeTitle, welcomeBody(isPad: isPad), welcomeFree, begin,
            audienceTitle, audienceMe, audienceMeDetail(isPad: isPad), audienceChild, audienceChildDetail(isPad: isPad),
            sendCode, codeTitle, codeBody(email: "you@example.com"), codeContinue, codeResend,
            trustedWitness, trustedExisting("friend@example.com"), trustedSkip,
            waitTitle, waitBody, waitGrace, waitKept(30),
            accessTitle, accessBody(isPad: isPad), accessButton, accessDenied,
            appsTitle, appsBody, appsBrowsers, appsChoose, appsChosen(2),
            passcodeTitle, passcodeBody, passcodeToggle, passcodeSkipWarning, passcodeDone, passcodeAfter,
            lockTitle, lockButton,
            dnsTitle, dnsBody, dnsHonest(trusted: true), dnsHonest(trusted: false), dnsAdd, dnsOpenSettings, dnsSkip,
            limitsTitle, doneTitle, doneButton,
            homeOn, homeAccessLost, homeAccessLostBody(isPad: isPad, trusted: true), homeFilter, homeDelete,
            homePasscodeKept, homeNoPasscode, homeDNSOn, homeDNSOff, homeDNSNotAdded, homeTrusted(nil),
            homeTrusted("friend@example.com"), homeWait(7), homeGrace,
            sitesTitle, sitesFooter, sitesAdd,
            turnOffTitle, turnOffIdle(trusted: true), turnOffIdle(trusted: false), turnOffAsk, turnOffConfirmTitle,
            turnOffConfirmBody(trusted: true), turnOffStart, keepOn, turnOffWaiting("3 days"), turnOffReady,
            turnOffNow, turnOffUnknown, releasedTitle, releasedPasscode, releasedHowTo, releasedNoPasscode,
            accountTitle, privacy, support, deleteTitle, deleteBody(isActive: true), deleteBody(isActive: false),
            deleteConfirm, deleteDone, deleteRequested, deleteMailSubject,
        ]
        for a in [PaxAudience.me, .child] {
            out += [emailTitle(a), emailBody(a), trustedTitle(a), trustedBody(a)]
        }
        out += passcodeSteps(isPad: isPad)
        out += lockLines(isPad: isPad, trusted: true, waitDays: 7)
        out += limits(isPad: isPad, passcode: false)
        return out
    }
}
