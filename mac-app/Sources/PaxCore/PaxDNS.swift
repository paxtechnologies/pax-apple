// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Per-user pax-dns URLs (v0.3). Swift port of `user_doh_url` / `mask_token_url`
/// in profile/make_profile.py; the tests pin both to the same outputs.
public enum PaxDNS {
    /// v0.8.8: Pax's own DoH filter (two servers behind one name).
    public static let defaultBase = "https://dns.paxpeace.com"

    /// v0.8.8: where a new iPhone/iPad set-up points its DNS. PAX_DNS_BASE wins (testing,
    /// self-hosting); otherwise Pax's filter, unless the user chose CleanBrowsing directly
    /// under Advanced (nil) or the Core strength, which only exists on the direct path.
    public static func setupBase(environment: [String: String] = ProcessInfo.processInfo.environment,
                                 directCleanBrowsing: Bool, filter: DNSFilter = .family) -> String? {
        if let b = environment["PAX_DNS_BASE"], !b.isEmpty { return b }
        if directCleanBrowsing || filter != .family { return nil }
        return defaultBase
    }

    /// v0.8.8: true when `<base>/health` answers 200 with `"ok": true`.
    public static func isHealthy(base: String, session: URLSession = .shared) async -> Bool {
        guard let url = healthURL(base: base) else { return false }
        var req = URLRequest(url: url)
        req.timeoutInterval = 15
        guard let (data, resp) = try? await session.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return false }
        return obj["ok"] as? Bool == true
    }

    /// v0.8.8: `<base>/health` of Pax's DNS filter, checked before a profile that
    /// points at it is locked onto a phone (a profile can't be changed later).
    public static func healthURL(base: String) -> URL? {
        var b = base.trimmingCharacters(in: .whitespacesAndNewlines)
        while b.hasSuffix("/") { b.removeLast() }
        return URL(string: b + "/health")
    }

    public enum URLError: Error, LocalizedError, Equatable {
        case badToken
        case badBase(String)

        public var errorDescription: String? {
            switch self {
            case .badToken: return "The Pax DNS token must be 22–128 URL-safe characters."
            case .badBase(let b): return "The Pax DNS address must be an https:// URL without a query (got \(b))."
            }
        }
    }

    static let tokenAlphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

    public static func isValidToken(_ token: String) -> Bool {
        (22...128).contains(token.count) && token.allSatisfy { tokenAlphabet.contains($0) }
    }

    /// `https://dns.paxpeace.com/u/<token>/dns-query` (RFC 8484).
    public static func userDoHURL(token: String, base: String? = nil,
                                  environment: [String: String] = ProcessInfo.processInfo.environment) throws -> String {
        let token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isValidToken(token) else { throw URLError.badToken }
        var b = (base ?? environment["PAX_DNS_BASE"] ?? defaultBase).trimmingCharacters(in: .whitespacesAndNewlines)
        while b.hasSuffix("/") { b.removeLast() }
        guard let comps = URLComponents(string: b), comps.scheme == "https",
              let host = comps.host, !host.isEmpty, comps.query == nil, comps.fragment == nil else {
            throw URLError.badBase(b)
        }
        return "\(b)/u/\(token)/dns-query"
    }

    /// For logs: keeps the first 4 token characters.
    public static func mask(_ url: String) -> String {
        guard let r = url.range(of: "/u/") else { return url }
        let rest = url[r.upperBound...]
        guard let slash = rest.firstIndex(of: "/") else { return url }
        let token = rest[..<slash]
        guard token.count > 4 else { return url }
        return String(url[..<r.upperBound]) + token.prefix(4) + "…" + String(rest[slash...])
    }
}

/// Finds a bundled helper script: an env var set by hand, then the app bundle's
/// Resources (DMG builds), then a path relative to the working directory (dev).
public enum ResourceLocator {
    public static func locate(envKey: String, bundled name: String, devPath: String,
                              environment: [String: String] = ProcessInfo.processInfo.environment,
                              resourceDirectory: URL? = Bundle.main.resourceURL,
                              fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> URL {
        if let chosen = environment[envKey], !chosen.isEmpty { return URL(fileURLWithPath: chosen) }
        if let res = resourceDirectory {
            let candidate = res.appendingPathComponent(name)
            if fileExists(candidate.path) { return candidate }
        }
        return URL(fileURLWithPath: devPath)
    }
}
