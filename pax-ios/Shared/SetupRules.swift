// SPDX-License-Identifier: GPL-3.0-only
// The on-phone set-up as a plain sequence of steps, with the checks each step needs.
// Kept free of UI and Apple frameworks so it can be tested.
import Foundation

enum SetupStep: Int, CaseIterable, Equatable {
    case welcome        // what Pax is, and the note about setting up from a Mac
    case audience       // me / my child's device
    case email          // account email
    case code           // the code the Pax server emailed
    case trusted        // someone you trust (optional, witness only)
    case wait           // turn-off wait, 3 days to 1 year
    case access         // Screen Time access (Face ID, once)
    case apps           // apps and sites to keep closed (picker)
    case passcodeChoice // Pax passcode on (default) or skip with a warning
    case lockIn         // summary, then: escrow saved on the server -> settings switched on
    case passcodeType   // type the Pax passcode into Settings (only if chosen)
    case dns            // encrypted DNS
    case done           // what's on, honest limits
}

enum SetupRules {
    /// The next step. The passcode typing step only follows if the person chose a passcode.
    static func next(after s: SetupStep, passcode: Bool) -> SetupStep {
        switch s {
        case .welcome: return .audience
        case .audience: return .email
        case .email: return .code
        case .code: return .trusted
        case .trusted: return .wait
        case .wait: return .access
        case .access: return .apps
        case .apps: return .passcodeChoice
        case .passcodeChoice: return .lockIn
        case .lockIn: return passcode ? .passcodeType : .dns
        case .passcodeType: return .dns
        case .dns: return .done
        case .done: return .done
        }
    }

    /// Going back is allowed only before anything is switched on.
    static func back(from s: SetupStep) -> SetupStep? {
        switch s {
        case .welcome, .lockIn, .passcodeType, .dns, .done: return nil
        case .code: return .email
        case .access: return nil          // Screen Time access was just asked for; carry on
        default: return SetupStep(rawValue: s.rawValue - 1)
        }
    }

    /// Where set-up resumes when the app opens: after Pax is switched on, never before it.
    static func resume(isActive: Bool) -> SetupStep { isActive ? .dns : .welcome }

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

    /// The trusted person is optional, but if given must be an email that isn't the account's.
    static func trustedProblem(_ raw: String, account: String) -> String? {
        let t = normaliseEmail(raw)
        if t.isEmpty { return nil }
        if !isEmail(t) { return "That doesn't look like an email address." }
        if t == normaliseEmail(account) { return "Your trusted person needs their own email address." }
        return nil
    }

    static func defaultWait(for audience: PaxAudience) -> Int {
        audience == .child ? Pax.childDefaultWaitDays : Pax.defaultWaitDays
    }

    /// The account's wait is shared by all its devices. A longer one is kept as it is;
    /// set-up only ever lengthens it (shortening would wait and email the trusted person).
    static func waitToSend(chosenDays: Int, currentSeconds: Int?) -> Int? {
        let chosen = TurnOffRules.clampWait(days: chosenDays)
        guard let cur = currentSeconds else { return chosen }
        return chosen * 86_400 >= cur ? chosen : nil
    }
}
