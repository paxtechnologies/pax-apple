// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// v0.8.0 automatic updates. pax-guard (root) downloads, checks and installs
/// them (guard/pax_update.py); the app only shows the state and offers
/// "Update now". The same Ed25519 public key is pinned here and in
/// guard/pax_signing.py, so the app can check a manifest itself too.
public enum UpdatePolicy {
    /// Ed25519 public key (hex) that signs pax-update.json and lists-manifest.json.
    /// The private key is the GitHub Actions secret PAX_UPDATE_SIGNING_KEY (docs/UPDATES.md).
    public static let publicKeysHex = ["0ad387f103fcd5104604b968741da264cc6e97242aaf228b2e2f57d80f497204"]
    public static let manifestURLs = [
        URL(string: "https://github.com/paxtechnologies/pax-apple/releases/latest/download/pax-update.json")!,
        URL(string: "https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/pax-update.json")!,
    ]
    public static let checkInterval: TimeInterval = 6 * 3600
}

/// "0.8.0" style versions, compared numerically.
public struct AppVersion: Comparable, Sendable, CustomStringConvertible {
    public let parts: [Int]
    public init?(_ text: String) {
        let p = text.split(separator: ".").map { Int($0) }
        guard p.count == 3, !p.contains(where: { $0 == nil || $0! < 0 }) else { return nil }
        parts = p.map { $0! }
    }
    public static func < (a: AppVersion, b: AppVersion) -> Bool { a.parts.lexicographicallyPrecedes(b.parts) }
    public var description: String { parts.map(String.init).joined(separator: ".") }
}

/// The signed manifest pax-guard reads (same rules as guard/pax_update.py).
public struct UpdateManifest: Decodable, Sendable, Equatable {
    public let schema: String
    public let version: String
    public let minimum_version: String
    public let url: String
    public let sha256: String
    public let size: Int

    /// What to do with this manifest when `installed` is running.
    public enum Decision: Equatable { case upToDate, install, installNow, refuse(String) }

    public func decision(installed: String) -> Decision {
        guard schema == "pax.update.v1", let v = AppVersion(version), let min = AppVersion(minimum_version),
              let cur = AppVersion(installed) else { return .refuse("malformed") }
        guard url.hasPrefix("https://"), sha256.count == 64 else { return .refuse("malformed") }
        if min > v { return .refuse("minimum above version") }
        if v <= cur { return .upToDate }
        return cur < min ? .installNow : .install
    }
}

public enum SignedDocument {
    public enum Problem: Error, Equatable { case notSigned, badSignature, malformed, unsupported }

    /// Canonical JSON of the payload, byte-for-byte what pax_signing.canonical
    /// makes: keys sorted, no spaces, non-ASCII kept as UTF-8, "/" not escaped.
    public static func canonical(_ value: Any) -> String {
        switch value {
        case let d as [String: Any]:
            return "{" + d.keys.sorted().map { "\(jsonString($0)):\(canonical(d[$0]!))" }.joined(separator: ",") + "}"
        case let a as [Any]:
            return "[" + a.map(canonical).joined(separator: ",") + "]"
        case let s as String:
            return jsonString(s)
        case let n as NSNumber:
            if String(cString: n.objCType) == "c" { return n.boolValue ? "true" : "false" }
            if n.doubleValue == n.doubleValue.rounded(), abs(n.doubleValue) < 1e15 { return String(n.int64Value) }
            return "\(n.doubleValue)"
        case is NSNull:
            return "null"
        default:
            return "null"
        }
    }

    static func jsonString(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            default:
                if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
            }
        }
        return out + "\""
    }

    /// The payload of a document signed by a pinned key, or a Problem.
    public static func verify(_ data: Data, keysHex: [String] = UpdatePolicy.publicKeysHex) -> Result<[String: Any], Problem> {
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let payload = obj["payload"] as? [String: Any] else { return .failure(.malformed) }
        guard let sigB64 = obj["signature"] as? String, !sigB64.isEmpty else { return .failure(.notSigned) }
        guard let sig = Data(base64Encoded: sigB64) else { return .failure(.badSignature) }
        let message = Data(canonical(payload).utf8)
        #if canImport(CryptoKit)
        for hex in keysHex {
            guard let raw = Data(hexString: hex),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else { continue }
            if key.isValidSignature(sig, for: message) { return .success(payload) }
        }
        return .failure(.badSignature)
        #else
        _ = (sig, message)
        return .failure(.unsupported)      // Linux test builds: pax-guard does the real check
        #endif
    }
}

extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        var i = hexString.startIndex
        while i < hexString.endIndex {
            let j = hexString.index(i, offsetBy: 2)
            guard let b = UInt8(hexString[i..<j], radix: 16) else { return nil }
            bytes.append(b)
            i = j
        }
        self.init(bytes)
    }
}

// MARK: - SHA-256 (Foundation-only, so the escrow receipt check runs on Linux too)

public enum SHA256Hex {
    public static func hash(_ data: Data) -> String {
        var h: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        let k: [UInt32] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
        var msg = [UInt8](data)
        let bitLen = UInt64(msg.count) * 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in (0..<8).reversed() { msg.append(UInt8((bitLen >> (UInt64(i) * 8)) & 0xff)) }
        func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }
        var w = [UInt32](repeating: 0, count: 64)
        for chunk in stride(from: 0, to: msg.count, by: 64) {
            for i in 0..<16 {
                let b = chunk + i * 4
                w[i] = UInt32(msg[b]) << 24 | UInt32(msg[b + 1]) << 16 | UInt32(msg[b + 2]) << 8 | UInt32(msg[b + 3])
            }
            for i in 16..<64 {
                let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
                let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
            }
            var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
            for i in 0..<64 {
                let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
                let ch = (e & f) ^ (~e & g)
                let t1 = hh &+ s1 &+ ch &+ k[i] &+ w[i]
                let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
                let maj = (a & b) ^ (a & c) ^ (b & c)
                let t2 = s0 &+ maj
                hh = g; g = f; f = e; e = d &+ t1; d = c; c = b; b = a; a = t1 &+ t2
            }
            h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d
            h[4] = h[4] &+ e; h[5] = h[5] &+ f; h[6] = h[6] &+ g; h[7] = h[7] &+ hh
        }
        return h.map { String(format: "%08x", $0) }.joined()
    }
}

/// The deposit step's receipt: `local_escrow.py deposit` prints
/// {"stored": "paxadmin", "sha256": "<hex>"} and the app checks it matches.
public enum LocalEscrowReceipt {
    public static func matches(_ output: String, password: String) -> Bool {
        let want = SHA256Hex.hash(Data(password.utf8))
        for line in output.split(whereSeparator: \.isNewline) {
            guard let d = line.data(using: .utf8),
                  let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { continue }
            if obj["stored"] as? String == "paxadmin", obj["sha256"] as? String == want { return true }
        }
        return false
    }
}
