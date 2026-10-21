// SPDX-License-Identifier: GPL-3.0-only
// What the server holds until the turn-off wait ends. It goes in the existing
// `removal_password` field of POST /v1/devices (20-256 chars), so the server's
// wait, partner email (fail closed) and reveal logic apply unchanged.
import Foundation
import Security
import CryptoKit

struct EscrowSecret: Codable, Equatable {
    var v = 1
    /// The Screen Time passcode Pax generated, if the person chose passcode escrow.
    var screenTimePasscode: String?
    /// 32 random bytes, base64url. The app keeps only its SHA-256.
    var releaseKey: String

    static let prefix = "paxios1."

    static func make(passcode: String?) -> EscrowSecret {
        EscrowSecret(screenTimePasscode: passcode, releaseKey: randomBytes(32).base64URL)
    }

    var sealed: String { Self.prefix + ((try? JSONEncoder().encode(self)) ?? Data()).base64URL }

    static func open(_ s: String) -> EscrowSecret? {
        guard s.hasPrefix(prefix), let data = Data(base64URL: String(s.dropFirst(prefix.count))) else { return nil }
        return try? JSONDecoder().decode(EscrowSecret.self, from: data)
    }

    var releaseKeyHash: String { Self.sha256Hex(releaseKey) }

    static func sha256Hex(_ s: String) -> String {
        SHA256.hash(data: Data(s.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// Four digits for the Screen Time passcode, avoiding the obvious ones (1234, 0000, 1212, years 19xx/20xx).
    static func makePasscode() -> String {
        while true {
            let bytes = randomBytes(8)
            let digits = bytes.prefix(4).map { Int($0) % 10 }
            // Reject the small bias region so every digit is uniform.
            if bytes.prefix(4).contains(where: { $0 >= 250 }) { continue }
            let code = digits.map(String.init).joined()
            if isObvious(code) { continue }
            return code
        }
    }

    static func isObvious(_ c: String) -> Bool {
        let d = c.compactMap { $0.wholeNumberValue }
        guard d.count == 4 else { return true }
        if Set(d).count == 1 { return true }                                   // 0000
        let steps = zip(d, d.dropFirst()).map { $1 - $0 }
        if steps.allSatisfy({ $0 == 1 }) || steps.allSatisfy({ $0 == -1 }) { return true } // 1234, 4321
        if d[0] == d[2] && d[1] == d[3] { return true }                         // 1212
        if c.hasPrefix("19") || c.hasPrefix("20") { return true }               // years
        return false
    }

    static func randomBytes(_ n: Int) -> Data {
        var d = Data(count: n)
        let rc = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        precondition(rc == errSecSuccess, "no secure random bytes")
        return d
    }
}

extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    init?(base64URL s: String) {
        var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b.count % 4 != 0 { b += "=" }
        self.init(base64Encoded: b)
    }
}

/// What the app does with what the server released. Only `.release` clears anything.
enum ReleaseDecision: Equatable {
    case release(passcode: String?)
    case stayOn(reason: String)
}

extension EscrowSecret {
    /// Fail closed: anything other than a sealed secret whose release key matches the hash
    /// this device kept at set-up leaves Pax on.
    static func decide(sealed: String?, expectedHash: String?) -> ReleaseDecision {
        decide(sealed: sealed, acceptedHashes: [expectedHash].compactMap { $0 })
    }

    /// The same, accepting any of a few hashes this device wrote down (the current one and one
    /// saved just before the server's copy was replaced). Empty strings never match.
    static func decide(sealed: String?, acceptedHashes: [String]) -> ReleaseDecision {
        let accepted = Set(acceptedHashes.filter { !$0.isEmpty })
        guard !accepted.isEmpty else {
            return .stayOn(reason: "This device has no release record, so Pax stays on.")
        }
        guard let sealed, let secret = open(sealed) else {
            return .stayOn(reason: "Pax couldn't read what the server sent, so Pax stays on.")
        }
        guard accepted.contains(secret.releaseKeyHash) else {
            return .stayOn(reason: "The release didn't match this device, so Pax stays on.")
        }
        return .release(passcode: secret.screenTimePasscode)
    }
}
