// SPDX-License-Identifier: GPL-3.0-only
// When this iPhone or iPad was ALREADY set up from a Mac (Pax for Mac's "iPhone or iPad" path:
// supervised, Pax's locked profile with encrypted DNS, Apple's web filter and restrictions, its
// removal password escrowed on the Pax server as a device record "org.paxpeace.pax.ios.<uuid>").
//
// iOS gives an App Store app no way to see supervision or the installed profiles, and
// NEDNSSettingsManager only ever sees this app's own DNS configuration. So the app tells a Mac
// set-up apart by two things it can check:
//   * on the device: names are looked up through Pax's filter (ProtectionCheck: X and Bluesky
//     media hosts answer 0.0.0.0) while this app has no DNS configuration of its own;
//   * on the account (after the email code): a device record made by Pax for Mac's iPhone path
//     that hasn't been released.
// Both: the app joins that set-up ("Set up from a Mac"). It only shows it and adds to it: no
// Screen Time request, no second device record, no DNS configuration over the locked one, and
// it never sends a turn-off wait. The Mac's settings always win.
import Foundation

enum StrictSync {
    /// Pax for Mac's iPhone/iPad profile identifiers (profile/make_profile.py PAX_ID_PREFIX + ".ios.").
    static let macProfilePrefix = "org.paxpeace.pax.ios."

    static func isMacSetUp(profileIdentifier: String?) -> Bool {
        (profileIdentifier ?? "").hasPrefix(macProfilePrefix)
    }

    /// One device record on the account, as GET /v1/devices lists it.
    struct AccountDevice: Equatable {
        var id: String
        var profileIdentifier: String?
        var released: Bool
    }

    /// The Mac set-ups on the account that are still protecting a device.
    static func macDevices(_ devices: [AccountDevice]) -> [AccountDevice] {
        devices.filter { !$0.released && isMacSetUp(profileIdentifier: $0.profileIdentifier) }
    }

    /// Does this device look up names through Pax's filter without this app's own DNS? Then
    /// something else put Pax's DNS here: a Mac set-up's locked profile.
    static func filteredHere(probe: ProtectionCheck.Outcome, ownDNSConfigured: Bool) -> Bool? {
        switch probe {
        case .protected: return ownDNSConfigured ? nil : true      // nil: can't tell (our own DNS)
        case .notProtected: return false
        case .couldNotCheck: return nil
        }
    }

    enum Decision: Equatable {
        /// No Mac set-up here: the usual set-up (Screen Time, device record, escrow).
        case normal
        /// This device was set up from a Mac on this account: join it, add nothing it has.
        case joinMacSetUp(deviceID: String?)
        /// Pax's filter is on this device, but this account has no Mac set-up: it belongs to
        /// another Pax account. Nothing is set up (no second account on one device).
        case otherAccount
        /// Couldn't tell (offline or mixed answers) while the account has a Mac set-up: check
        /// again rather than risk a second set-up over it.
        case checkAgain
    }

    /// After the email code. Fail closed: when in doubt, nothing is added.
    static func decide(filteredHere: Bool?, accountDevices: [AccountDevice]) -> Decision {
        let macs = macDevices(accountDevices)
        switch filteredHere {
        case .some(true):
            if macs.isEmpty { return .otherAccount }
            return .joinMacSetUp(deviceID: macs.count == 1 ? macs[0].id : nil)
        case .some(false):
            return .normal
        case .none:
            return macs.isEmpty ? .normal : .checkAgain
        }
    }

    /// Before the code, on the child path: a child account would be a second, separate account
    /// on a device a Mac already set up. Refused; the email used on the Mac signs in instead.
    static func childRefused(filteredHere: Bool?) -> Bool { filteredHere == true }
}

/// The child path (server 0.8.32, docs/CHILD_ACCOUNTS.md): /v1/accounts/child/start, /verify and
/// /signin. A server without these routes answers a plain 404: the app says it needs a Pax update
/// and never falls back to the parent's own account (/email/*).
enum ChildSetup {
    enum Problem: Equatable {
        case needsUpdate        // plain 404/405: the server doesn't have child accounts yet
        case wrongCode          // 401 (or a code the server can't read)
        case childLimit         // 429 child_limit (PAX-ESCROW-022): five children on this email
        case tooManyCodes       // 429 otherwise
        case invalidEmail       // 422 on /child/start
        case waitFixed          // 403 child_wait_fixed (PAX-ESCROW-021)
        case notChild           // the answer wasn't a child account: never kept
    }

    static func problem(status: Int, code: String?, starting: Bool) -> Problem? {
        switch status {
        case 404, 405: return .needsUpdate
        case 401: return .wrongCode
        case 422: return starting ? .invalidEmail : .wrongCode
        case 429: return code == "child_limit" ? .childLimit : .tooManyCodes
        case 403 where code == "child_wait_fixed": return .waitFixed
        default: return nil
        }
    }

    /// Only a child account's token is kept on the child path.
    static func keep(kind: String?) -> Bool { kind == "child" }

    /// "iPhone" / "iPad" for the server's label ("Sam's iPhone (child)").
    static func deviceName(isPad: Bool) -> String { isPad ? "iPad" : "iPhone" }

    static func message(_ p: Problem, isPad: Bool) -> String {
        switch p {
        case .needsUpdate: return PaxCopy.childNeedsUpdate
        case .wrongCode: return PaxCopy.codeWrong
        case .childLimit: return PaxCopy.childLimit
        case .tooManyCodes: return PaxCopy.tooManyCodes
        case .invalidEmail: return PaxCopy.emailInvalid
        case .waitFixed: return PaxCopy.childWaitFixed
        case .notChild: return PaxCopy.childNeedsUpdate
        }
    }
}
