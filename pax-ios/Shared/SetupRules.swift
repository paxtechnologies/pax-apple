// SPDX-License-Identifier: GPL-3.0-only
// The on-phone set-up (1.2 "one-tap"), with the checks each step needs. Kept free of UI and
// Apple frameworks so it can be tested.
//
//   For me:      Welcome ("Turn Pax on") → Apple's Screen Time sheet → Done.
//   For a child: Welcome → "Setting up for a child?" → parent's email → code → Screen Time → Done.
//
// Everything else happens quietly after the Screen Time sheet: a private device account (no
// email), the 7-day turn-off wait, the release key escrowed on the server, and only then the
// adult-content filter and the delete block. If the server can't be reached nothing is
// switched on and a calm "Try again" is shown. Servers that can't make a private account yet
// ask for an email and a code instead (`email`, `code`), then carry on.
import Foundation

enum SetupStep: Int, CaseIterable, Equatable {
    case welcome        // one big button: Turn Pax on
    case childEmail     // child path: the parent's email
    case childCode      // child path: the code the Pax server emailed
    case turningOn      // Screen Time sheet, then the quiet work (account, escrow, settings)
    case email          // only when the server can't make a private account yet
    case code
    case retry          // the server couldn't be reached: nothing is on yet, try again
    case done           // Pax is on
}

/// What the quiet work after the Screen Time sheet came to.
enum TurnOnOutcome: Equatable {
    /// Escrow saved, settings on.
    case on
    /// Screen Time access wasn't given. Nothing changed.
    case denied
    /// This server can't make a private account: ask for an email and a code, then carry on.
    case needsEmail
    /// The server couldn't be reached or refused. Nothing switched on (fail closed).
    case failed
}

enum SetupRules {
    /// The screens someone sees, in order, for each path.
    static func path(child: Bool, privateAccounts: Bool) -> [SetupStep] {
        if child { return [.welcome, .childEmail, .childCode, .turningOn, .done] }
        return privateAccounts ? [.welcome, .turningOn, .done] : [.welcome, .turningOn, .email, .code, .done]
    }

    /// Where the set-up goes after the quiet work.
    static func after(_ outcome: TurnOnOutcome) -> SetupStep {
        switch outcome {
        case .on: return .done
        case .denied: return .welcome
        case .needsEmail: return .email
        case .failed: return .retry
        }
    }

    /// Going back is allowed only before anything is asked of Screen Time.
    static func back(from s: SetupStep) -> SetupStep? {
        switch s {
        case .childEmail: return .welcome
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

    /// A first name for the trusted person's emails: optional, short, one line.
    static func cleanName(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            .components(separatedBy: .newlines).joined(separator: " ")
        guard !s.isEmpty else { return nil }
        return String(s.prefix(40))
    }

    /// The account's wait is shared by all its devices. Set-up only ever lengthens it.
    static func waitToSend(chosenDays: Int, currentSeconds: Int?) -> Int? {
        let chosen = TurnOffRules.clampWait(days: chosenDays)
        guard let cur = currentSeconds else { return chosen }
        return chosen * 86_400 >= cur ? chosen : nil
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
