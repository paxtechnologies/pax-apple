// SPDX-License-Identifier: GPL-3.0-only
// The words the app shows, in one place, so they can be checked by tests: calm and
// warm, for individuals and families, "adult and explicit content", "someone you
// trust", "turn-off wait", and honest about the limits.
import Foundation

enum PaxCopy {
    static func device(isPad: Bool) -> String { isPad ? "iPad" : "iPhone" }

    // MARK: welcome (one big button)

    static let welcomeTitle = "Your calm self, in charge."
    static func welcomeBody(isPad: Bool) -> String {
        "Pax keeps adult and explicit content off this \(device(isPad: isPad)), for you or for your family. "
            + "If you ever want it off, it turns off after a wait, so one hard moment never gets the final say."
    }
    static let welcomeFree = "Free and open source. Pax never keeps your browsing history."
    static let turnOn = "Turn Pax on"
    static func turnOnNote(isPad: Bool) -> String {
        "You'll confirm your email with a code, then \(device(isPad: isPad)) asks once for Screen Time access."
    }
    static let childLink = "Setting up for a child?"

    // MARK: child path (keeps the parent's email)

    static let childTitle = "Setting up for your child"
    static func childBody(isPad: Bool) -> String {
        "Do this on your child's \(device(isPad: isPad)), together. Use your own email, not your child's: "
            + "Pax emails you if anyone asks to turn it off."
    }
    static let childWaitNote = "On a child's device the turn-off wait starts at 30 days. You can change it later."
    static let emailPlaceholder = "you@example.com"
    static let sendCode = "Send me a code"
    static let codeTitle = "Check your email"
    static func codeBody(email: String) -> String { "Enter the 6-digit code Pax sent to \(email). It works for 15 minutes." }
    static let codeContinue = "Continue"
    static let codeResend = "Send again"
    static let codeResendNote = "Didn't get it? Check your spam folder, or send it again. Only the newest code works."
    static let codeSent = "A new code is on its way."
    static let codeWrong = "That code isn't right, or it has expired. Check the newest email from Pax, or send it again."
    static let emailInvalid = "That doesn't look like an email address."
    static let tooManyCodes = "Too many codes for now. Please wait a little, then try again."

    // MARK: your email (every Pax account has one, checked with a code)

    static let emailTitle = "Your email"
    static func emailBody(isPad: Bool) -> String {
        "Pax sends you a code to check it's yours. Your email keeps your account safe if this "
            + "\(device(isPad: isPad)) is ever lost or replaced, and Pax emails you a copy of your own requests. Nothing else."
    }

    // MARK: welcome back (the email already has a Pax account)

    static let welcomeBackTitle = "Welcome back"
    static func welcomeBackBody(isPad: Bool) -> String {
        "This email already has a Pax account. What's set there applies to this \(device(isPad: isPad)) too."
    }
    static func welcomeBackLines(_ a: ExistingAccount) -> [String] {
        var l: [String] = []
        var wait = "Turn-off wait: \(TurnOffRules.waitLabel(days: a.waitDays))"
        if let p = a.pendingWaitDays, p != a.waitDays { wait += " (changing to \(TurnOffRules.waitLabel(days: p)) later)" }
        l.append(wait + ".")
        if let longer = a.lengthenTo {
            l.append("Setting up here lengthens it to \(TurnOffRules.waitLabel(days: longer)), for every device on this account.")
        }
        l.append(a.trustedEmail.map { "Someone you trust: \($0)." } ?? "No one you trust added yet.")
        if a.devices.isEmpty {
            l.append("Pax isn't on any other device on this account right now.")
        } else {
            for d in a.devices { l.append("Pax is on \(d.name) (\(d.kind)).") }
        }
        return l
    }
    static let welcomeBackNote = "Setting up here never shortens your wait or removes anything."
    static let welcomeBackContinue = "Continue"
    static let welcomeBackLoadFailed = "Pax couldn't read your account just now. Check your connection, then try again."

    // MARK: turning on (Apple's Screen Time sheet, then the quiet work)

    static let turningOnTitle = "Turning Pax on"
    static func turningOnBody(isPad: Bool) -> String {
        "\(device(isPad: isPad)) asks once for Screen Time access, with Face ID or your passcode. Then it only takes a moment."
    }

    static let retryTitle = "Pax isn't on yet"
    static let retryBody = "Pax couldn't reach its server, so nothing has been switched on. "
        + "Check your connection, then try again."
    static let retryButton = "Try again"
    static let accessDenied = "Screen Time access wasn't given, so Pax can't protect this device yet. "
        + "You can try again whenever you're ready."

    // MARK: signing in again (the sign-in on this device was lost)

    static let signInAgainTitle = "Sign in to Pax again"
    static func signInAgainBody(isPad: Bool) -> String {
        "Pax is still on, but this \(device(isPad: isPad)) isn't signed in to your Pax account any more. "
            + "Sign in with your email and a code to change settings or turn Pax off."
    }
    static let signInButton = "Sign in"
    static let signedIn = "You're signed in again."
    static func wrongAccount(setUpWith email: String?, isPad: Bool) -> String {
        if let e = email, !e.isEmpty {
            return "That's a different Pax account. This \(device(isPad: isPad)) was set up with \(e), so please use that email."
        }
        return "That's a different Pax account from the one this \(device(isPad: isPad)) was set up with. Nothing has changed."
    }

    // MARK: done

    static let doneTitle = "Pax is on"
    static func doneLines(isPad: Bool, waitDays: Int) -> [String] {
        [
            "Adult and explicit websites are blocked.",
            "Pax can't be deleted from this \(device(isPad: isPad)).",
            "Turning Pax off takes your turn-off wait: \(TurnOffRules.waitLabel(days: waitDays)).",
        ]
    }
    static let doneNext = "On Home there are a few optional ways to make Pax stronger, whenever you like."
    static let doneButton = "Done"

    // MARK: Home status

    static let homeOn = "Pax is on"
    static let homeAccessLost = "Pax's Screen Time access is off"
    static func homeAccessLostBody(isPad: Bool, trusted: Bool) -> String {
        "Someone switched it off in Settings, so Pax can't protect this \(device(isPad: isPad)) right now."
            + (trusted ? " The person you trust has been told." : "")
    }
    static let homeFilter = "Adult and explicit sites are blocked"
    static let homeDelete = "Pax can't be deleted"
    static let homePasscodeKept = "Pax keeps the Screen Time passcode"
    static let homeNoPasscode = "Screen Time isn't locked yet: Face ID can switch Pax off"
    static let homeDNSOn = "Encrypted DNS is on"
    static let homeDNSOff = "Encrypted DNS is off. Turn it on in Settings › General › VPN & Device Management › DNS."
    static let homeDNSNotAdded = "Encrypted DNS isn't added yet"
    static func homeTrusted(_ email: String?) -> String {
        if let e = email, !e.isEmpty { return "Someone you trust: \(e)" }
        return "No one you trust added yet"
    }
    static func homeWait(_ days: Int) -> String { "Turn-off wait: \(TurnOffRules.waitLabel(days: days))" }
    static let homeGrace = "First hour: you can still turn Pax off with no wait."

    // MARK: Make Pax stronger

    static let strongerTitle = "Make Pax stronger"
    static func strongerProgress(done: Int, total: Int) -> String { "\(done) of \(total) done. All optional." }
    static let recommended = "Recommended"
    static let doneTag = "Done"

    // (a) Lock Screen Time
    static let lockTitle = "Lock Screen Time"
    static let lockBody = "Right now, Face ID alone can switch Pax off in Settings. A Screen Time passcode that "
        + "Pax keeps for you stops that, until your turn-off wait ends."
    static let lockButton = "Lock Screen Time"
    static let lockDone = "Pax keeps your Screen Time passcode. It's shown again only when your turn-off wait ends."
    static let lockIntro = "Pax makes up a four-digit Screen Time passcode and keeps it safe on its server. "
        + "You type it into Settings once and don't need to remember it."
    static let lockMake = "Make my passcode"
    static func passcodeSteps(isPad: Bool) -> [String] {
        [
            "Open Settings › Screen Time and tap Lock Screen Time Settings (or Use Screen Time Passcode).",
            "Type the four digits below. Hold a box to see its digit.",
            "When \(device(isPad: isPad)) asks for an Apple Account for recovery, tap Cancel. Otherwise the passcode could be reset.",
        ]
    }
    static let passcodeDone = "I've set it"
    static let passcodeAfter = "Pax has already saved this passcode. It's shown again only when your turn-off wait ends."
    static let passcodeLater = "Not now"
    static func lockRefused(_ r: LockRefusal, isPad: Bool) -> String {
        let d = device(isPad: isPad)
        switch r {
        case .turnOffOpen:
            return "A turn-off is in progress on this \(d), so Pax can't add a passcode right now. "
                + "If you'd like to keep Pax on, tap Keep Pax on, then try again."
        case .supportTurnOffOpen:
            return "A turn-off through Pax support is in progress on this \(d), so Pax can't add a passcode right now."
        case .released:
            return "Pax has already been turned off on this \(d), so there's nothing to lock."
        case .removed:
            return "This \(d) was removed from your Pax account, so there's nothing to lock."
        case .changed:
            return "Something changed on Pax's server while saving your passcode. Nothing was lost. Please try again."
        case .notOnAccount:
            return "Pax couldn't find this \(d) on the account you're signed in to. Nothing has changed."
        }
    }

    // (b) Someone you trust
    static let trustedTitle = "Add someone you trust"
    static let trustedBody = "A friend, a partner or a parent. They're emailed if anyone asks to turn Pax off "
        + "or shorten the wait."
    static let trustedWitness = "They never approve or stop anything. If the email to them can't be sent, nothing is turned off."
    static let trustedEmailPlaceholder = "Their email"
    static let trustedNamePlaceholder = "Your first name (optional)"
    static let trustedNameHint = "So they know who the emails are about."
    static let trustedSave = "Add them"
    static let trustedChangeNote = "Changing them takes your turn-off wait, and they're told first."
    static let trustedChange = "Change"
    static func trustedPending(_ email: String) -> String {
        email.isEmpty ? "Removing them when your wait ends." : "Changing to \(email) when your wait ends."
    }

    // (c) Encrypted DNS
    static let dnsTitle = "Encrypted DNS"
    static let dnsBody = "An extra layer that filters apps as well as websites, through Pax's own filter. "
        + "After you tap Add, open Settings › General › VPN & Device Management › DNS and choose Pax."
    static func dnsHonest(trusted: Bool) -> String {
        "Anyone can switch this layer off in Settings. If it's off, Pax shows it here"
            + (trusted ? " and emails the person you trust." : ".")
    }
    static let dnsAdd = "Add encrypted DNS"
    static let dnsOpenSettings = "Open Settings"

    // (d) Apps to keep closed
    static let appsTitle = "Choose apps to keep closed"
    static let appsBody = "Such as X, Bluesky or browsers you don't trust. Pax only gets an anonymous token "
        + "for each, never a list of your apps. Once closed, they stay closed."
    static let appsChoose = "Choose apps and sites"
    static func appsChosen(_ n: Int) -> String { n == 0 ? "Nothing chosen yet." : "\(n) chosen." }

    // (e) Turn-off wait
    static let waitTitle = "Change turn-off wait"
    static func waitBody(currentDays: Int) -> String {
        "Now: \(TurnOffRules.waitLabel(days: currentDays)). A longer wait starts straight away. "
            + "A shorter one comes in after your current wait, and the person you trust is told first."
    }
    static func waitPending(days: Int, on date: String) -> String {
        "Changing to \(TurnOffRules.waitLabel(days: days)) on \(date)."
    }
    static let waitSave = "Save"
    static let waitShorterTitle = "Shorten your turn-off wait?"
    static func waitShorterBody(currentDays: Int) -> String {
        "The shorter wait comes in after your current one (\(TurnOffRules.waitLabel(days: currentDays))). "
            + "If you've added someone you trust, they're emailed first."
    }
    static let waitShorterConfirm = "Shorten after the wait"
    static func waitLonger(days: Int) -> String { "Your turn-off wait is now \(TurnOffRules.waitLabel(days: days))." }

    // (f) Make Pax unremovable (setting up from a computer)
    static let computerTitle = "Make Pax unremovable"
    static let computerSubtitle = "Set up from a Mac or Windows PC"
    static func computerBody(isPad: Bool) -> String {
        "Setting Pax up from a computer locks this \(device(isPad: isPad)) more firmly: it can't be switched "
            + "off in Settings, and your photos and messages stay. It's free, like this app."
    }
    static let computerOpen = "Open paxpeace.com/setup"
    static let macLink = "Steps for a Mac"
    static let macSheetTitle = "Set up from a Mac"
    static func macSheetIntro(isPad: Bool) -> String {
        "Setting Pax up from a Mac locks this \(device(isPad: isPad)) more firmly: it can't be "
            + "switched off in Settings, and your photos and messages stay. It's free, like this app."
    }
    static let macSheetMore = "More at paxpeace.com"

    // MARK: honest limits (Home)

    static let limitsTitle = "Good to know"
    static func limits(isPad: Bool, passcode: Bool) -> [String] {
        let d = device(isPad: isPad)
        var l = [
            "A full erase or a restore from a computer removes Pax.",
            "Anyone holding this \(d) can switch the encrypted DNS off in Settings. Pax notices and says so.",
        ]
        if !passcode { l.append(passcodeSkipWarning) }
        return l
    }
    static let passcodeSkipWarning = "Until Screen Time is locked, Face ID can switch Pax's Screen Time access off at any time."

    // MARK: blocked sites

    static let sitesTitle = "Your blocked sites"
    static let sitesFooter = "Adding a site is instant. Removing one takes your turn-off wait."
    static let sitesAdd = "Add"

    // MARK: turning off

    static let turnOffTitle = "Turn off Pax"
    static func turnOffIdle(trusted: Bool) -> String {
        "You can always turn Pax off. It takes your turn-off wait"
            + (trusted ? ", and the person you trust is emailed first." : ".")
    }
    static let turnOffAsk = "Ask to turn off"
    static let turnOffConfirmTitle = "Start your turn-off wait?"
    static func turnOffConfirmBody(trusted: Bool) -> String {
        (trusted ? "The person you trust is emailed first. If the email can't be sent, nothing starts. " : "")
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
        var s = "This deletes your account from the Pax server: your email, the person you trust, "
            + "your devices and your blocked sites."
        if isActive {
            s += " Pax has to be off on every device on your account first. Turning Pax off takes your "
                + "turn-off wait, and deleting your account never skips it."
        }
        return s
    }
    static let deleteConfirm = "Delete my account"
    static let deleteDone = "Your Pax account has been deleted."
    static let deleteRequested = "Your request is ready to send in your email app. Pax support deletes the account "
        + "and replies to confirm."
    static func deleteMailBody(email: String, accountRef: String) -> String {
        "Please delete my Pax account.\n\nAccount email: \(email.isEmpty ? "(not shown on this device)" : email)\n"
            + "Account reference: \(accountRef)\n\nSent from the Pax app on iPhone or iPad."
    }
    static let deleteMailSubject = "Delete my Pax account"
    static let deleteRateLimited = "Too many tries. Please wait an hour, then try again."
    static let deleteStillOnTitle = "Pax is still on"
    static func deleteStillOnBody(count: Int) -> String {
        count == 1 ? "Your account can't be deleted while Pax is still on one of its devices:"
                   : "Your account can't be deleted while Pax is still on \(count) of its devices:"
    }
    static let deleteStillOnHowTo = "Turn Pax off on each one first, from Home › Turn off Pax. It takes your turn-off "
        + "wait, and deleting your account never skips it. When Pax is off everywhere, come back here to delete "
        + "your account."
    static let deleteStillOnNothingChanged = "Nothing has been deleted."
    static func deleteStillOnReason(_ reason: String, checkingIn: Bool?) -> String {
        var s: String
        switch reason {
        case "turn_off_wait": s = "Turn-off wait in progress"
        case "emergency_release": s = "Support turn-off in progress"
        case "pending_request": s = "A turn-off request is still open"
        default: s = "Pax is on"
        }
        if checkingIn == false { s += " · not seen online lately" }
        return s
    }

    /// Every visible string, for the copy tests.
    static func all(isPad: Bool) -> [String] {
        var out: [String] = [
            welcomeTitle, welcomeBody(isPad: isPad), welcomeFree, turnOn, turnOnNote(isPad: isPad), childLink,
            childTitle, childBody(isPad: isPad), childWaitNote, emailPlaceholder, sendCode, codeTitle,
            codeBody(email: "you@example.com"), codeContinue, codeResend, codeResendNote, codeSent, codeWrong,
            emailInvalid, tooManyCodes, emailTitle, emailBody(isPad: isPad),
            welcomeBackTitle, welcomeBackBody(isPad: isPad), welcomeBackNote, welcomeBackContinue, welcomeBackLoadFailed,
            turningOnTitle, turningOnBody(isPad: isPad), retryTitle, retryBody, retryButton, accessDenied,
            signInAgainTitle, signInAgainBody(isPad: isPad), signInButton, signedIn,
            wrongAccount(setUpWith: "you@example.com", isPad: isPad), wrongAccount(setUpWith: nil, isPad: isPad),
            doneTitle, doneNext, doneButton,
            homeOn, homeAccessLost, homeAccessLostBody(isPad: isPad, trusted: true), homeFilter, homeDelete,
            homePasscodeKept, homeNoPasscode, homeDNSOn, homeDNSOff, homeDNSNotAdded, homeTrusted(nil),
            homeTrusted("friend@example.com"), homeWait(7), homeGrace,
            strongerTitle, strongerProgress(done: 1, total: 4), recommended, doneTag,
            lockTitle, lockBody, lockButton, lockDone, lockIntro, lockMake, passcodeDone, passcodeAfter, passcodeLater,
            trustedTitle, trustedBody, trustedWitness, trustedEmailPlaceholder, trustedNamePlaceholder,
            trustedNameHint, trustedSave, trustedChangeNote, trustedChange, trustedPending("new@example.com"),
            trustedPending(""),
            dnsTitle, dnsBody, dnsHonest(trusted: true), dnsHonest(trusted: false), dnsAdd, dnsOpenSettings,
            appsTitle, appsBody, appsChoose, appsChosen(0), appsChosen(2),
            waitTitle, waitBody(currentDays: 7), waitPending(days: 3, on: "1 Nov"), waitSave, waitShorterTitle,
            waitShorterBody(currentDays: 7), waitShorterConfirm, waitLonger(days: 30),
            computerTitle, computerSubtitle, computerBody(isPad: isPad), computerOpen, macLink, macSheetTitle,
            macSheetIntro(isPad: isPad), macSheetMore,
            limitsTitle, passcodeSkipWarning,
            sitesTitle, sitesFooter, sitesAdd,
            turnOffTitle, turnOffIdle(trusted: true), turnOffIdle(trusted: false), turnOffAsk, turnOffConfirmTitle,
            turnOffConfirmBody(trusted: true), turnOffStart, keepOn, turnOffWaiting("3 days"), turnOffReady,
            turnOffNow, turnOffUnknown, releasedTitle, releasedPasscode, releasedHowTo, releasedNoPasscode,
            accountTitle, privacy, support, deleteTitle, deleteBody(isActive: true),
            deleteBody(isActive: false), deleteConfirm, deleteDone, deleteRequested, deleteMailSubject,
            deleteRateLimited, deleteStillOnTitle, deleteStillOnBody(count: 1), deleteStillOnBody(count: 2),
            deleteStillOnHowTo, deleteStillOnNothingChanged, deleteStillOnReason("pax_on", checkingIn: false),
            deleteStillOnReason("turn_off_wait", checkingIn: true), deleteStillOnReason("emergency_release", checkingIn: nil),
            deleteStillOnReason("pending_request", checkingIn: nil),
        ]
        out += passcodeSteps(isPad: isPad)
        out += [LockRefusal.turnOffOpen, .supportTurnOffOpen, .released, .removed, .changed, .notOnAccount]
            .map { lockRefused($0, isPad: isPad) }
        out += welcomeBackLines(ExistingAccount(waitSeconds: 3 * 86_400, pendingWaitSeconds: nil,
                                                trustedEmail: "friend@example.com",
                                                devices: [(name: "Sam's MacBook", platform: "mac", released: false)],
                                                child: false))
        out += welcomeBackLines(ExistingAccount(waitSeconds: 30 * 86_400, pendingWaitSeconds: 7 * 86_400,
                                                trustedEmail: nil, devices: [], child: false))
        out += doneLines(isPad: isPad, waitDays: 7)
        out += limits(isPad: isPad, passcode: false)
        return out
    }
}
