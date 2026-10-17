// SPDX-License-Identifier: GPL-3.0-only
// What the person chose, kept in the App Group so the extensions can re-apply it.
// No browsing history is ever stored here or anywhere else.
import Foundation

struct PaxPolicy: Codable, Equatable {
    var isActive = false
    var setUpAt: Date?
    var waitDays = Pax.defaultWaitDays
    var blockedDomains: [String] = []
    var hasPartner = false
    var passcodeEscrowed = false
    var deviceID: String?
    /// SHA-256 (hex) of the release key escrowed with the server. See EscrowSecret.
    var releaseKeyHash: String?

    private static let key = "pax.policy.v1"

    static func load(from defaults: UserDefaults = Pax.shared) -> PaxPolicy {
        guard let data = defaults.data(forKey: key),
              let p = try? JSONDecoder().decode(PaxPolicy.self, from: data) else { return PaxPolicy() }
        return p
    }

    func save(to defaults: UserDefaults = Pax.shared) {
        if let data = try? JSONEncoder().encode(self) { defaults.set(data, forKey: Self.key) }
    }

    /// Adding a site is instant; removing one waits (handled by the server, like Pax Strict).
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
