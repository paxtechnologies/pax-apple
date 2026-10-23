// SPDX-License-Identifier: GPL-3.0-only
// The on-phone set-up (1.2 "one-tap"), with the checks each step needs. Kept free of UI and
// Apple frameworks so it can be tested. Every Pax account has a verified email (server 0.8.31,
// docs/ONETAP_ACCOUNTS.md), so the account comes first:
//
//   For me:      Welcome ("Turn Pax on") → email → 6-digit code → Apple's Screen Time sheet → Done.
//   For a child: Welcome → "Setting up for a child?" (the parent's email) → code → Screen Time → Done.
//   An email that already has an account adds one screen after the code ("Welcome back"): what
//   is already set (the turn-off wait, someone you trust, its devices) applies here too.
//
// After the code, quietly and in this order: Screen Time access (asked once, never again), the
// turn-off wait (only ever lengthened: 7 days, 30 on a child's device), the release key escrowed
// on the server, and only then the adult-content filter and the delete block. If the server can't
// be reached nothing is switched on and a calm "Try again" is shown.
import Foundation

enum SetupStep: Int, CaseIterable, Equatable {
    case welcome = 0    // one big button: Turn Pax on
    case childEmail = 1 // child path: the parent's email
    case childCode = 2  // child path: the code the Pax server emailed
    case email = 3      // your email
    case code = 4       // the 6-digit code
    case welcomeBack = 5 // the email already had an account: what's already set
    case turningOn = 6  // Screen Time sheet (once), then the quiet work (wait, escrow, settings)
    case done = 7       // Pax is on
    case retry = 8      // the server couldn't be reached: nothing is on yet, try again
    case denied = 9     // Screen Time access wasn't given: nothing is on yet
}

/// What checking the emailed code came to.
enum VerifyOutcome: Equatable {
    /// A new account (its email now verified).
    case newAccount
    /// Signed in to the account this email already had: its wait, trusted person and devices apply.
    case existingAccount
    /// Wrong or expired code, or the server couldn't be reached. Nothing changed.
    case failed
}

/// What the quiet work after the code came to.
enum TurnOnOutcome: Equatable {
    /// Escrow saved, settings on.
    case on
    /// Screen Time access wasn't given. Nothing changed.
    case denied
    /// No working sign-in on this device (lost, or no longer valid): email and code again.
    case signedOut
    /// The server couldn't be reached or refused. Nothing switched on (fail closed).
    case failed
    /// This device was already set up from a Mac: joined that set-up, nothing added (StrictSync).
    case macSetUp
}

enum SetupRules {
    /// The screens someone sees, in order, for each path.
    static func path(child: Bool, existing: Bool) -> [SetupStep] {
        let start: [SetupStep] = child ? [.welcome, .childEmail, .childCode] : [.welcome, .email, .code]
        return start + (existing ? [.welcomeBack] : []) + [.turningOn, .done]
    }

    /// The first screen after Welcome.
    static func emailStep(child: Bool) -> SetupStep { child ? .childEmail : .email }
    static func codeStep(child: Bool) -> SetupStep { child ? .childCode : .code }

    /// Where the set-up goes after the code.
    static func after(_ v: VerifyOutcome, child: Bool) -> SetupStep? {
        switch v {
        case .newAccount: return .turningOn
        case .existingAccount: return .welcomeBack
        case .failed: return nil            // stay on the code screen
        }
    }

    /// Where the set-up goes after the quiet work.
    static func after(_ outcome: TurnOnOutcome, child: Bool) -> SetupStep {
        switch outcome {
        case .on, .macSetUp: return .done
        case .denied: return .denied
        case .signedOut: return emailStep(child: child)
        case .failed: return .retry
        }
    }

    /// Going back is allowed only before the account is signed in.
    static func back(from s: SetupStep) -> SetupStep? {
        switch s {
        case .childEmail, .email: return .welcome
        case .childCode: return .childEmail
        case .code: return .email
        default: return nil
        }
    }

    /// Where set-up resumes when the app opens: once Pax is on, never before it.
    static func resume(isActive: Bool) -> SetupStep { isActive ? .done : .welcome }

    /// The wait a new set-up asks for. Child devices get a longer one.
    static func defaultWait(child: Bool) -> Int { child ? Pax.childDefaultWaitDays : Pax.defaultWaitDays }

    static func normaliseEmail(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    static func isEmail(_ raw: String) -> Bool {
        let s = normaliseEmail(raw)
        guard s.count <= 254, !s.contains(" ") else { return false }
        let parts = s.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, parts[0].count <= 64 else { return false }
        let domain = parts[1].split(separator: ".", omittingEmptySubsequences: false)
        guard domain.count >= 2, domain.allSatisfy({ !$0.isEmpty }),
              let tld = domain.last, tld.count >= 2, tld.allSatisfy(\.isLetter) else { return false }
        return true
    }

    /// The server's sign-in code is six digits.
    static func isCode(_ raw: String) -> Bool {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return s.count == 6 && s.allSatisfy { $0.isASCII && $0.isNumber }
    }

    /// The trusted person must be an email that isn't the account's own.
    static func trustedProblem(_ raw: String, account: String?) -> String? {
        let t = normaliseEmail(raw)
        if t.isEmpty { return "Add their email address." }
        if !isEmail(t) { return "That doesn't look like an email address." }
        if let a = account, !a.isEmpty, t == normaliseEmail(a) {
            return "The person you trust needs their own email address."
        }
        return nil
    }

    /// Signing in again on a device Pax is on: only the account it was set up with. Known by its
    /// id, or (a device set up before ids were kept) by its email. Nothing known (an unreadable
    /// policy): accepted, since no other account can release this device's escrow anyway.
    static func sameAccount(setUpID: String?, setUpEmail: String?, signedInID: String, signedInEmail: String) -> Bool {
        if let id = setUpID, !id.isEmpty { return id == signedInID }
        if let e = setUpEmail, !e.isEmpty { return normaliseEmail(e) == normaliseEmail(signedInEmail) }
        return true
    }

    /// The longest first name the server takes (`from_name`).
    static let maxNameLength = 40

    /// A first name for the trusted person's emails: optional, one line, at most 40 characters.
    /// Line breaks, tabs and other control or format characters become spaces or go.
    static func cleanName(_ raw: String) -> String? {
        var out = ""
        for u in raw.unicodeScalars {
            if u == " " || u.properties.isWhitespace { out.append(" ") }
            else if u.properties.generalCategory == .control || u.properties.generalCategory == .format { continue }
            else { out.unicodeScalars.append(u) }
        }
        let s = out.split(separator: " ", omittingEmptySubsequences: true).joined(separator: " ")
        guard !s.isEmpty else { return nil }
        return String(s.prefix(maxNameLength)).trimmingCharacters(in: .whitespaces)
    }

    /// The server refuses names with links; say so before asking it.
    static func nameProblem(_ raw: String) -> String? {
        let s = raw.lowercased()
        if s.contains("://") || s.contains("www.") { return "Just a first name, please, with no links." }
        if raw.trimmingCharacters(in: .whitespacesAndNewlines).count > maxNameLength {
            return "Please keep your first name to \(maxNameLength) characters or fewer."
        }
        return nil
    }

    /// The turn-off waits offered on Home. A child's device never goes below 30 days (the
    /// server refuses it: 403 child_wait_fixed), so shorter ones aren't offered there.
    static func waitChoices(child: Bool) -> [Int] {
        child ? Pax.waitChoices.filter { $0 >= Pax.childDefaultWaitDays } : Pax.waitChoices
    }

    /// The account's wait is shared by all its devices. Set-up only ever lengthens it: nil when
    /// the account's wait is already as long or longer (nothing is sent).
    static func waitToSend(chosenDays: Int, currentSeconds: Int?) -> Int? {
        let chosen = TurnOffRules.clampWait(days: chosenDays)
        guard let cur = currentSeconds else { return chosen }
        return chosen * 86_400 > cur ? chosen : nil
    }
}

/// Changing the turn-off wait from Home. The server's rule: longer (or the same) is instant;
/// shorter takes the current wait to come in, and someone you trust is told first.
enum WaitChange: Equatable {
    case same
    case longerNow
    case shorterAfterWait
    static func of(currentDays: Int, newDays: Int) -> WaitChange {
        let n = TurnOffRules.clampWait(days: newDays)
        if n == currentDays { return .same }
        return n > currentDays ? .longerNow : .shorterAfterWait
    }
}

/// "Welcome back": what an existing account already has, read from GET /v1/accounts/me and
/// GET /v1/devices after the code. Shown as it is; set-up never shortens anything.
struct ExistingAccount: Equatable {
    struct Device: Equatable {
        let name: String
        let kind: String        // iPhone, iPad, Mac or Device
        /// Set up from a Mac (Pax for Mac's iPhone path), not from this app.
        var fromMac = false
    }
    var waitDays: Int
    /// A shorter wait the account already asked for, coming in later.
    var pendingWaitDays: Int?
    var trustedEmail: String?
    /// Devices Pax is on for this account (released ones aren't listed).
    var devices: [Device]
    /// The wait set-up will lengthen the account's to (nil: it stays as it is).
    var lengthenTo: Int?
    /// This device was already set up from a Mac on this account: the app joins it and changes
    /// nothing (no wait is sent, nothing is lengthened or shortened).
    var joiningMac = false

    /// `profiles`: each device's profile identifier, in the same order as `devices` (optional).
    init(waitSeconds: Int, pendingWaitSeconds: Int?, trustedEmail: String?,
         devices: [(name: String?, platform: String?, released: Bool?)], child: Bool,
         profiles: [String?] = [], joiningMac: Bool = false) {
        waitDays = TurnOffRules.days(fromSeconds: waitSeconds)
        pendingWaitDays = pendingWaitSeconds.map(TurnOffRules.days(fromSeconds:))
        self.trustedEmail = (trustedEmail ?? "").isEmpty ? nil : trustedEmail
        var list: [Device] = []
        for (i, d) in devices.enumerated() where d.released != true {
            list.append(Device(name: (d.name ?? "").isEmpty ? "A device" : d.name!, kind: ExistingAccount.kind(d.platform ?? ""),
                               fromMac: StrictSync.isMacSetUp(profileIdentifier: i < profiles.count ? profiles[i] : nil)))
        }
        self.devices = list
        self.joiningMac = joiningMac
        lengthenTo = joiningMac ? nil
            : SetupRules.waitToSend(chosenDays: SetupRules.defaultWait(child: child), currentSeconds: waitSeconds)
    }

    static func kind(_ platform: String) -> String {
        let p = platform.lowercased()
        if p.contains("ipad") { return "iPad" }
        if p.contains("iphone") || p == "ios" { return "iPhone" }
        if p.contains("mac") { return "Mac" }
        return "Device"
    }
}
