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

    var hasTrustedPerson: Bool { !(trustedEmail ?? "").isEmpty }

    init() {}

    private enum K: String, CodingKey {
        case isActive, setUpFinished, audience, accountEmail, setUpAt, waitDays, blockedDomains,
             trustedEmail, passcodeEscrowed, deviceID, releaseKeyHash, dnsInstalled, dnsSeenOn,
             dnsOffSince, dnsAlertSent, accessAlertSent
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

    /// Adding a site is instant; removing one waits (handled by the server, like on a Mac).
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
