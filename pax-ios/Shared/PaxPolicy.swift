// SPDX-License-Identifier: GPL-3.0-only
// What the person chose, kept in the App Group so the extensions can re-apply it.
// No browsing history is ever stored here or anywhere else.
//
// Fail closed: every field decodes on its own (a missing or new field never throws), and
// if saved data exists but can't be read at all, Pax treats itself as ON. It never
// reads "off" from something it couldn't read.
import Foundation

/// Who Pax is protecting on this device.
enum PaxAudience: String, Codable, Equatable {
    case me
    case child
}

/// A blocked site the person asked to remove (1.2). The Pax server holds the request: it
/// emailed the person they trust first and keeps the site blocked for the turn-off wait. This
/// device removes the site only once the server's list no longer has it AND the server's own
/// clock is past `effectiveAt` (see SiteRemoval.reconcile). Never removed on the device alone.
struct PendingSiteRemoval: Codable, Equatable {
    var domain: String
    var requestID: String
    /// Server time (Unix seconds) the wait ends.
    var effectiveAt: Int
}

struct PaxPolicy: Codable, Equatable {
    var isActive = false
    /// Set-up finished (passcode and DNS steps done or skipped). Home shows only then.
    var setUpFinished = false
    var audience: PaxAudience = .me
    var accountEmail: String?
    var setUpAt: Date?
    var waitDays = Pax.defaultWaitDays
    var blockedDomains: [String] = []
    var trustedEmail: String?
    var passcodeEscrowed = false
    var deviceID: String?
    /// SHA-256 (hex) of the release key escrowed with the server. See EscrowSecret.
    var releaseKeyHash: String?
    /// Encrypted DNS was saved to iPhone's settings by Pax.
    var dnsInstalled = false
    /// Pax has seen the encrypted DNS switched on at least once.
    var dnsSeenOn = false
    /// When Pax first noticed the encrypted DNS was off (nil while it's on).
    var dnsOffSince: Date?
    /// Which DNS alert was already sent ("off:<timestamp>" or "never"), so it's sent once.
    var dnsAlertSent: String?
    /// The trusted person was told Pax's Screen Time access was switched off.
    var accessAlertSent = false
    /// The Pax account this device was set up with, so signing in again (a lost token) can't
    /// silently move it to another account.
    var accountID: String?
    /// 1.2: a release key hash written down BEFORE the escrow on the server is replaced, so a
    /// crash between the server call and the save can never leave this device unable to match.
    var pendingReleaseKeyHash: String?
    /// The first name the trusted person sees in Pax's emails (`from_name`), if one was given.
    var displayName: String?
    /// 1.2: removals waiting on the server (the turn-off wait), see PendingSiteRemoval.
    var pendingSiteRemovals: [PendingSiteRemoval] = []
    /// 1.2: this device was already set up from a Mac (supervised, Pax's locked profile). The app
    /// joined that set-up's account and only shows it and adds to it: no Screen Time request, no
    /// device record, no DNS configuration of its own (see StrictSync).
    var macSetUp = false
    /// The Mac set-up's device record on the server, when exactly one matched.
    var macDeviceID: String?
    /// 1.2: apps blocked by bundle ID, installed or not (BlockedApps.swift). Adding is instant;
    /// one comes off only after the server's turn-off wait (AppRemoval).
    var blockedApps: [BlockedApp] = []
    /// 1.2: app removals waiting on the server.
    var pendingAppRemovals: [PendingAppRemoval] = []
    /// 1.3, a device set up from a Mac: Screen Time (.individual) was asked for, once, when the
    /// person first added an app there (PhoneAppLayer). Written before asking, so it's never asked
    /// again: a second request after approval lifts the delete block.
    var phoneAppsAuthAsked = false

    /// Every release key hash this device accepts for its main record.
    var acceptedReleaseHashes: [String] { [releaseKeyHash, pendingReleaseKeyHash].compactMap { $0 }.filter { !$0.isEmpty } }

    var hasTrustedPerson: Bool { !(trustedEmail ?? "").isEmpty }

    init() {}

    private enum K: String, CodingKey {
        case isActive, setUpFinished, audience, accountEmail, setUpAt, waitDays, blockedDomains,
             trustedEmail, passcodeEscrowed, deviceID, releaseKeyHash, dnsInstalled, dnsSeenOn,
             dnsOffSince, dnsAlertSent, accessAlertSent, accountID, pendingReleaseKeyHash, displayName,
             pendingSiteRemovals, macSetUp, macDeviceID, blockedApps, pendingAppRemovals, phoneAppsAuthAsked
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: K.self)
        func v<T: Decodable>(_ k: K, _ fallback: T) -> T {
            if let x = try? c.decodeIfPresent(T.self, forKey: k) { return x }
            return fallback
        }
        func o<T: Decodable>(_ k: K) -> T? {
            if let x = try? c.decodeIfPresent(T.self, forKey: k) { return x }
            return nil
        }
        isActive = v(.isActive, false)
        setUpFinished = v(.setUpFinished, false)
        audience = v(.audience, PaxAudience.me)
        accountEmail = o(.accountEmail)
        setUpAt = o(.setUpAt)
        waitDays = v(.waitDays, Pax.defaultWaitDays)
        blockedDomains = v(.blockedDomains, [String]())
        trustedEmail = o(.trustedEmail)
        passcodeEscrowed = v(.passcodeEscrowed, false)
        deviceID = o(.deviceID)
        releaseKeyHash = o(.releaseKeyHash)
        dnsInstalled = v(.dnsInstalled, false)
        dnsSeenOn = v(.dnsSeenOn, false)
        dnsOffSince = o(.dnsOffSince)
        dnsAlertSent = o(.dnsAlertSent)
        accessAlertSent = v(.accessAlertSent, false)
        accountID = o(.accountID)
        pendingReleaseKeyHash = o(.pendingReleaseKeyHash)
        displayName = o(.displayName)
        pendingSiteRemovals = v(.pendingSiteRemovals, [PendingSiteRemoval]())
        macSetUp = v(.macSetUp, false)
        macDeviceID = o(.macDeviceID)
        blockedApps = v(.blockedApps, [BlockedApp]())
        pendingAppRemovals = v(.pendingAppRemovals, [PendingAppRemoval]())
        phoneAppsAuthAsked = v(.phoneAppsAuthAsked, false)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: K.self)
        try c.encode(isActive, forKey: .isActive)
        try c.encode(setUpFinished, forKey: .setUpFinished)
        try c.encode(audience, forKey: .audience)
        try c.encodeIfPresent(accountEmail, forKey: .accountEmail)
        try c.encodeIfPresent(setUpAt, forKey: .setUpAt)
        try c.encode(waitDays, forKey: .waitDays)
        try c.encode(blockedDomains, forKey: .blockedDomains)
        try c.encodeIfPresent(trustedEmail, forKey: .trustedEmail)
        try c.encode(passcodeEscrowed, forKey: .passcodeEscrowed)
        try c.encodeIfPresent(deviceID, forKey: .deviceID)
        try c.encodeIfPresent(releaseKeyHash, forKey: .releaseKeyHash)
        try c.encode(dnsInstalled, forKey: .dnsInstalled)
        try c.encode(dnsSeenOn, forKey: .dnsSeenOn)
        try c.encodeIfPresent(dnsOffSince, forKey: .dnsOffSince)
        try c.encodeIfPresent(dnsAlertSent, forKey: .dnsAlertSent)
        try c.encode(accessAlertSent, forKey: .accessAlertSent)
        try c.encodeIfPresent(accountID, forKey: .accountID)
        try c.encodeIfPresent(pendingReleaseKeyHash, forKey: .pendingReleaseKeyHash)
        try c.encodeIfPresent(displayName, forKey: .displayName)
        try c.encode(pendingSiteRemovals, forKey: .pendingSiteRemovals)
        try c.encode(macSetUp, forKey: .macSetUp)
        try c.encodeIfPresent(macDeviceID, forKey: .macDeviceID)
        try c.encode(blockedApps, forKey: .blockedApps)
        try c.encode(pendingAppRemovals, forKey: .pendingAppRemovals)
        try c.encode(phoneAppsAuthAsked, forKey: .phoneAppsAuthAsked)
    }

    static let key = "pax.policy.v1"

    /// Reads the saved policy. Unreadable data counts as ON (fail closed).
    static func decode(_ data: Data?) -> PaxPolicy {
        guard let data else { return PaxPolicy() }
        if let p = try? JSONDecoder().decode(PaxPolicy.self, from: data) { return p }
        var p = PaxPolicy()
        p.isActive = true
        p.setUpFinished = true
        return p
    }

    static func load(from defaults: UserDefaults = Pax.shared) -> PaxPolicy {
        decode(defaults.data(forKey: key))
    }

    func save(to defaults: UserDefaults = Pax.shared) {
        if let data = try? JSONEncoder().encode(self) { defaults.set(data, forKey: Self.key) }
    }

    /// Adding a site is instant; removing one takes the turn-off wait on the server (SiteRemoval).
    mutating func addDomain(_ raw: String) -> Bool {
        guard let d = Self.normalise(raw), !blockedDomains.contains(d) else { return false }
        blockedDomains.append(d)
        return true
    }

    /// "https://WWW.Example.com/path" -> "example.com". Returns nil for anything that isn't a host name.
    static func normalise(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let i = s.firstIndex(where: { "/?#:".contains($0) }) { s = String(s[..<i]) }
        if s.hasPrefix("www.") { s.removeFirst(4) }
        while s.hasSuffix(".") { s.removeLast() }
        let labels = s.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, s.count <= 253 else { return nil }
        let ok = labels.allSatisfy { l in
            !l.isEmpty && l.count <= 63 && !l.hasPrefix("-") && !l.hasSuffix("-")
                && l.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" }
        }
        return ok ? s : nil
    }
}
