// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.37 (Ruben, 21 Nov 2026): Pax for Mac was uninstalled and installed again. The Mac came
/// back (GuardReconnect, 0.8.34) but the iPhone it had protected did not: the list of phones
/// lived only in the app's preferences. Set-up then found the phone "already supervised",
/// stored a second removal password and failed to install with the raw DMC error, because the
/// phone is supervised by Pax's first key, which was destroyed after set-up by design.
///
/// Now:
///   1. The account's iPhones and iPads come back from the server (GET /v1/devices) and show
///      on Home with their usual settings (status, turn-off wait, emergency, support release).
///   2. Plugging a phone in reads it first (`pax_device.py inspect`, read-only). A phone that
///      already has Pax's protection profile is recognised and linked by that profile's
///      identifier, which is unique per set-up and which the server already keeps; nothing is
///      installed and no second password is stored.
///   3. A phone protected under another account says so, and offers nothing that would remove
///      or weaken its protection.
/// Nothing here gives anything away: it only brings back Home and the turn-off wait, which is
/// the same server wait as before.
public enum PhoneReconnect {
    /// Identifier prefixes of Pax's iPhone/iPad protection profile (profile/make_profile.py
    /// `org.paxpeace.pax.<platform>.<uuid>`). The App Store app's records use
    /// `org.paxpeace.pax.appstore.*`, which is not a profile on the phone, so they are never
    /// rebuilt here (their Home is the app on the phone).
    public static let phoneProfilePrefixes = ["org.paxpeace.pax.ios.", "org.paxpeace.pax.ipados."]

    public static func isPhoneProfile(_ identifier: String?) -> Bool {
        guard let id = identifier?.lowercased() else { return false }
        return phoneProfilePrefixes.contains { id.hasPrefix($0) }
    }

    /// MCInstall's refusal when the phone is supervised by someone else's key (also matched by
    /// `pax_device.py needs_supervisor`, which reports it as PAX-IOS-013 itself).
    public static func needsSupervisor(_ text: String) -> Bool {
        let t = text.lowercased()
        return t.contains("must be installed using a device management tool") || t.contains("dmcfatalerror")
    }

    // MARK: What the phone says (pax_device.py inspect)

    public struct Inspection: Equatable, Sendable {
        public let supervised: Bool
        public let organization: String?
        public let paxSupervised: Bool
        /// Pax protection profile identifiers installed on the phone (usually one).
        public let paxProfiles: [String]
        public let iosVersion: String?

        public init(supervised: Bool, organization: String? = nil, paxSupervised: Bool = false,
                    paxProfiles: [String] = [], iosVersion: String? = nil) {
            self.supervised = supervised
            self.organization = organization
            self.paxSupervised = paxSupervised
            self.paxProfiles = paxProfiles.filter { PhoneReconnect.isPhoneProfile($0) }
            self.iosVersion = iosVersion
        }

        public init(json: [String: Any]) {
            self.init(supervised: json["supervised"] as? Bool ?? false,
                      organization: json["organization"] as? String,
                      paxSupervised: json["pax_supervised"] as? Bool ?? false,
                      paxProfiles: json["pax_profiles"] as? [String] ?? [],
                      iosVersion: json["ios"] as? String)
        }

        /// Pax's protection is on this phone: never install again.
        public var hasPaxProtection: Bool { !paxProfiles.isEmpty }
    }

    // MARK: The account's phones (GET /v1/devices)

    /// One iPhone or iPad on the account, as the server lists it.
    public struct ServerPhone: Equatable, Sendable {
        public let deviceID: String
        public let name: String
        public let platform: String
        public let profileIdentifier: String?
        public let released: Bool
        public let installedAt: Int

        public init(deviceID: String, name: String, platform: String = "ios", profileIdentifier: String?,
                    released: Bool = false, installedAt: Int = 0) {
            self.deviceID = deviceID
            self.name = name
            self.platform = platform
            self.profileIdentifier = profileIdentifier
            self.released = released
            self.installedAt = installedAt
        }

        public init(_ s: EscrowClient.DeviceStatus) {
            self.init(deviceID: s.device_id, name: s.name, platform: s.platform,
                      profileIdentifier: s.profile_identifier, released: PhoneStatus.isReleased(s),
                      installedAt: s.installed_at)
        }

        public var isMac: Bool { platform == "mac" || platform == "macos" }
        public var isIPad: Bool { platform == "ipados" || (profileIdentifier?.lowercased().hasPrefix("org.paxpeace.pax.ipados.") ?? false) }
    }

    /// The phones to add to this Mac's list after a reinstall or a sign-in: the account's
    /// iPhones and iPads that were set up over USB (a Pax profile identifier), that Pax is still
    /// on (released ones are left out, as Home already does; retired ones the server never
    /// lists), that no record here is linked to yet, and that the user didn't remove from the
    /// list on this Mac. Oldest first, the order they were set up.
    public static func phonesToRestore(server: [ServerPhone], linkedDeviceIDs: Set<String>,
                                       hiddenDeviceIDs: Set<String>) -> [ServerPhone] {
        server
            .filter { !$0.isMac && !$0.released && isPhoneProfile($0.profileIdentifier) }
            .filter { !linkedDeviceIDs.contains($0.deviceID) && !hiddenDeviceIDs.contains($0.deviceID) }
            .sorted { ($0.installedAt, $0.deviceID) < ($1.installedAt, $1.deviceID) }
    }

    /// The local record id for a phone brought back from the server (its ECID isn't known
    /// until it is plugged in, and isn't needed: everything on Home goes by the server ID).
    public static func restoredRecordID(_ deviceID: String) -> String { "server:" + deviceID }

    // MARK: Matching a plugged-in phone to the account

    public enum Match: Equatable, Sendable {
        /// No Pax protection on the phone: normal set-up carries on.
        case notProtected
        /// Pax protects it and it is this account's device `deviceID`.
        case recognised(deviceID: String, by: MatchKey)
        /// Pax protects it, but this Mac isn't signed in to a Pax account yet.
        case needsSignIn
        /// Pax protects it under another account (or a set-up this account no longer lists).
        case otherAccount
    }

    public enum MatchKey: String, Equatable, Sendable {
        /// The protection profile's identifier: unique per set-up, kept by the server since 0.1.
        case profileIdentifier
        /// Last resort, only for a server that doesn't send `profile_identifier`.
        case name
    }

    /// - Parameters:
    ///   - server: the signed-in account's devices, or nil when this Mac has no account.
    ///   - phoneName: the plugged-in phone's name (only used as the last resort).
    public static func match(_ inspection: Inspection, phoneName: String, server: [ServerPhone]?) -> Match {
        guard inspection.hasPaxProtection else { return .notProtected }
        guard let server else { return .needsSignIn }
        let phones = server.filter { !$0.isMac }
        let onPhone = Set(inspection.paxProfiles.map { $0.lowercased() })
        // Newest first: if one phone somehow carries two set-ups, the latest wins.
        let byIdentifier = phones
            .filter { $0.profileIdentifier.map { onPhone.contains($0.lowercased()) } ?? false }
            .sorted { $0.installedAt > $1.installedAt }
        if let hit = byIdentifier.first { return .recognised(deviceID: hit.deviceID, by: .profileIdentifier) }
        // A server that sends identifiers has told us this phone's set-up isn't on the account.
        // Only when it sends none at all (very old) does the name decide, and only if exactly one
        // phone of the account has it, so a wrong guess can never pick between two.
        guard phones.allSatisfy({ $0.profileIdentifier == nil }) else { return .otherAccount }
        let byName = phones.filter { $0.name == phoneName && !$0.released }
        if byName.count == 1 { return .recognised(deviceID: byName[0].deviceID, by: .name) }
        return .otherAccount
    }

    /// After a phone was recognised: the account's other unreleased USB set-ups with the same
    /// name whose profile isn't on the phone that was plugged in. These are usually set-ups that
    /// never finished (a password was stored, the install failed); Home says so, and "Remove from
    /// list" hides them on this Mac only. The server keeps them, so nothing is turned off.
    public static func notOnThisPhone(recognised deviceID: String, inspection: Inspection, phoneName: String,
                                      server: [ServerPhone]) -> [String] {
        let onPhone = Set(inspection.paxProfiles.map { $0.lowercased() })
        return server.filter {
            !$0.isMac && !$0.released && $0.deviceID != deviceID && $0.name == phoneName
                && isPhoneProfile($0.profileIdentifier)
                && !onPhone.contains(($0.profileIdentifier ?? "").lowercased())
        }.map(\.deviceID)
    }

    // MARK: Words (calm; never the raw error)

    public static func recognisedTitle(isIPad: Bool) -> String {
        "This \(isIPad ? "iPad" : "iPhone") is already protected by Pax"
    }
    public static let recognisedLine = "Nothing on it was changed. It's back on Home with its usual settings."
    public static func openButton(name: String) -> String { "Open \(name)" }

    public static let signInLine = "Sign in with the Pax account you set it up with to see it here. "
        + "Its protection stays on."
    public static func otherAccountTitle(isIPad: Bool) -> String {
        "This \(isIPad ? "iPad" : "iPhone") is protected by Pax with another account"
    }
    public static let otherAccountLine = "Its protection stays on. To see it here, open Pax on the Mac it was "
        + "set up with, or email hello@paxpeace.com."

    /// Home, for a phone brought back from the server: the apps were chosen at set-up and live
    /// in the phone's protection settings; this Mac no longer has their names.
    public static let restoredAppsLine = "Chosen at set-up · kept on the phone"
    /// Home, for the other set-ups `notOnThisPhone` found.
    public static func notOnPhoneLine(name: String) -> String {
        "This set-up isn't on the \(name) that was plugged in. It may be from a set-up that didn't finish. "
            + "Removing it here only hides it on this Mac."
    }
    /// Home, while two or more set-ups share a name and none was confirmed by plugging in.
    public static func duplicateNameLine(name: String) -> String {
        "There's more than one \(name) on your account. Plug it in and choose Add iPhone or iPad to check "
            + "which one it is. Nothing will be installed again."
    }
}
