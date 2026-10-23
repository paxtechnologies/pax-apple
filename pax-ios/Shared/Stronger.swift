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

    /// The cards Home shows. A device set up from a Mac already has the stronger protection
    /// (locked profile, filter, restrictions), so only what adds to the account is offered there:
    /// never Screen Time, a DNS configuration of this app's own, or another set-up.
    static func cards(macSetUp: Bool) -> [StrongerCard] {
        macSetUp ? order.filter { $0 == .trustedPerson || $0 == .turnOffWait } : order
    }

    /// The nudge shows on the Lock Screen Time card until it's done.
    static func nudge(_ p: PaxPolicy) -> Bool { p.isActive && !p.passcodeEscrowed }

    /// "2 of 4 done" counts only the cards that can be done.
    static func progress(_ p: PaxPolicy, hasApps: Bool) -> (done: Int, total: Int) {
        let doable: [StrongerCard] = [.lockScreenTime, .trustedPerson, .encryptedDNS, .appsToClose]
        return (doable.filter { $0.isDone(p, hasApps: hasApps) }.count, doable.count)
    }
}

/// Why the server refused to add the Screen Time passcode (PUT /v1/devices/{id}/escrow), in
/// calm words. Nothing on the device or the server changed in any of these.
enum LockRefusal: Equatable {
    case turnOffOpen        // 409 removal_request_open
    case supportTurnOffOpen // 409 emergency_open
    case released           // 409 released
    case removed            // 409 retired
    case changed            // 409 changed: try again
    case notOnAccount       // 404

    static func of(status: Int, reason: String?) -> LockRefusal? {
        switch (status, reason) {
        case (409, "removal_request_open"): return .turnOffOpen
        case (409, "emergency_open"): return .supportTurnOffOpen
        case (409, "released"): return .released
        case (409, "retired"): return .removed
        case (409, _): return .changed
        case (404, _): return .notOnAccount
        default: return nil         // not a refusal (offline, 5xx…): the general message
        }
    }

    func message(isPad: Bool) -> String { PaxCopy.lockRefused(self, isPad: isPad) }
}
