// SPDX-License-Identifier: GPL-3.0-only
// Home's "Make Pax stronger" list: optional steps, in a fixed order, after one-tap set-up.
// Lock Screen Time is pinned first with a gentle nudge until it's done, because without a
// Screen Time passcode Face ID alone can switch Pax off in Settings.
import Foundation

enum StrongerCard: String, CaseIterable, Equatable {
    case lockScreenTime     // the Screen Time passcode Pax keeps (escrow)
    case trustedPerson      // someone you trust (the only step asking for an email)
    case encryptedDNS
    case appsToClose
    case turnOffWait
    case computerSetup      // "Make Pax unremovable": set up from a computer

    /// Whether this one is done, from what the device knows.
    func isDone(_ p: PaxPolicy, hasApps: Bool) -> Bool {
        switch self {
        case .lockScreenTime: return p.passcodeEscrowed
        case .trustedPerson: return p.hasTrustedPerson
        case .encryptedDNS: return p.dnsInstalled
        case .appsToClose: return hasApps
        case .turnOffWait, .computerSetup: return false   // always offered, never "done"
        }
    }
}

enum StrongerList {
    /// Always the same order (Ruben, 2026-10-21): lock, trusted person, DNS, apps, wait, computer.
    static let order: [StrongerCard] = StrongerCard.allCases

    /// The nudge shows on the Lock Screen Time card until it's done.
    static func nudge(_ p: PaxPolicy) -> Bool { p.isActive && !p.passcodeEscrowed }

    /// "2 of 4 done" counts only the cards that can be done.
    static func progress(_ p: PaxPolicy, hasApps: Bool) -> (done: Int, total: Int) {
        let doable: [StrongerCard] = [.lockScreenTime, .trustedPerson, .encryptedDNS, .appsToClose]
        return (doable.filter { $0.isDone(p, hasApps: hasApps) }.count, doable.count)
    }
}

extension TurnOffRules {
    /// With a second escrow record (the passcode one), turning off is only as far along as the
    /// slower of the two. Anything unreadable reads as unknown (Pax stays on).
    static func combine(_ a: TurnOffPhase, _ b: TurnOffPhase?) -> TurnOffPhase {
        guard let b else { return a }
        switch (a, b) {
        case (.unknown, _), (_, .unknown): return .unknown
        case (.none, .none): return .none
        case (.ready, .ready): return .ready
        case (.waiting(let x), .waiting(let y)): return .waiting(until: max(x, y))
        case (.waiting(let x), .ready), (.ready, .waiting(let x)): return .waiting(until: x)
        default: return .none   // one asked for and one not: "Ask to turn off" asks again for the missing one
        }
    }
}
