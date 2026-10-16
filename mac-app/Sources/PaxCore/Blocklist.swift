// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Server models (server/pax_server/blocklist.py)

public struct BlocklistRequest: Decodable, Sendable, Equatable, Identifiable {
    public let request_id: String
    public let action: String            // "unblock" | "allow" | "rotate_token"
    public let domain: String?
    public let display_domain: String?
    public let status: String
    public let created_at: Int
    public let effective_at: Int
    public let seconds_remaining: Int
    public var id: String { request_id }
}

public struct BlockedSite: Decodable, Sendable, Equatable, Identifiable {
    public let domain: String
    public let display_domain: String
    public let added_at: Int
    public let pending_removal: BlocklistRequest?
    public var id: String { domain }
}

public struct AllowedSite: Decodable, Sendable, Equatable, Identifiable {
    public let domain: String
    public let display_domain: String
    public let added_at: Int
    public var id: String { domain }
}

public struct BlocklistLimits: Decodable, Sendable, Equatable {
    public let max_blocked: Int
    public let max_allowed: Int
    public let delay_seconds: Int
}

public struct BlocklistView: Decodable, Sendable, Equatable {
    public let now: Int
    public let blocked: [BlockedSite]
    public let allowed: [AllowedSite]
    public let pending: [BlocklistRequest]
    public let limits: BlocklistLimits
}

public struct BlocklistAddResult: Decodable, Sendable {
    public let domain: String
    public let created: Bool
    public let list: BlocklistView
}

public struct BlocklistRequestResult: Decodable, Sendable {
    public let request: BlocklistRequest
    public let list: BlocklistView
}

public struct DNSInfo: Decodable, Sendable {
    public let doh_url: String
    public let token: String
    public let created_at: Int
}

// MARK: - API calls

extension EscrowClient {
    public func blocklist() async throws -> BlocklistView {
        try await send("GET", "v1/blocklist")
    }

    /// Immediate.
    public func blockSite(_ domain: String) async throws -> BlocklistAddResult {
        try await send("POST", "v1/blocklist", body: ["domain": domain])
    }

    /// Starts the wait (default 72 h); cancellable.
    public func requestUnblock(_ domain: String) async throws -> BlocklistRequestResult {
        try await send("POST", "v1/blocklist/remove", body: ["domain": domain])
    }

    /// Starts the wait (default 72 h); cancellable.
    public func requestAllow(_ domain: String) async throws -> BlocklistRequestResult {
        try await send("POST", "v1/allowlist", body: ["domain": domain])
    }

    /// Immediate.
    public func removeAllow(_ domain: String) async throws -> BlocklistView {
        try await send("POST", "v1/allowlist/remove", body: ["domain": domain])
    }

    public func cancelBlocklistRequest(_ id: String) async throws -> BlocklistView {
        try await send("POST", "v1/blocklist/requests/\(id)/cancel")
    }

    public func dnsInfo() async throws -> DNSInfo {
        try await send("GET", "v1/dns")
    }

    /// v0.8.8: the account's settings on Pax's own DNS filter (iPhone/iPad).
    /// YouTube Restricted Mode switches at once. v0.8.13: pictures and video on X
    /// and Bluesky are always blocked, so they're not sent (the server refuses
    /// turning them off: 422 media_always_blocked, PAX-DNS-016).
    public func setDNSSettings(youtubeRestricted: Bool) async throws {
        let _: [String: AnyDecodable] = try await send("PUT", "v1/dns/settings", body: [
            "youtube_restricted": youtubeRestricted,
        ])
    }
}

// MARK: - Pure helpers (unit-tested)

/// Light client-side clean-up so the field accepts what people paste. The server
/// does the real validation (IDNA, public suffixes, limits).
public enum DomainInput {
    public static func normalise(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let cut = s.firstIndex(where: { "/?#".contains($0) }) { s = String(s[..<cut]) }
        if let at = s.lastIndex(of: "@") { s = String(s[s.index(after: at)...]) }
        if s.filter({ $0 == ":" }).count == 1, let colon = s.firstIndex(of: ":") { s = String(s[..<colon]) }
        while s.hasSuffix(".") { s.removeLast() }
        if s.hasPrefix("*.") { s.removeFirst(2) }
        guard !s.isEmpty, s.contains("."), !s.contains("*"), !s.contains(":"),
              !s.contains(where: { $0.isWhitespace }) else { return nil }
        // Dotted digits only: an IPv4 address.
        if s.allSatisfy({ $0.isNumber || $0 == "." }) { return nil }
        return s
    }
}

public enum Countdown {
    /// "71h 59m 59s" under 4 days, "6d 23h" beyond, "now" at zero.
    public static func string(seconds: Int) -> String {
        let s = max(0, seconds)
        if s == 0 { return "now" }
        let d = s / 86_400, h = (s % 86_400) / 3600, m = (s % 3600) / 60, sec = s % 60
        if s >= 4 * 86_400 { return "\(d)d \(h)h" }
        let hours = d * 24 + h
        if hours > 0 { return String(format: "%dh %02dm %02ds", hours, m, sec) }
        return String(format: "%dm %02ds", m, sec)
    }

    /// Seconds left at local time `now`, correcting for the server clock (`serverNow`
    /// was the server's time when `fetchedAt` was the local time).
    public static func remaining(effectiveAt: Int, serverNow: Int, fetchedAt: Date, now: Date) -> Int {
        let elapsed = Int(now.timeIntervalSince(fetchedAt).rounded(.down))
        return max(0, effectiveAt - (serverNow + elapsed))
    }
}

/// Keeps the escrow API token between launches (Keychain in the app).
public protocol TokenStore: Sendable {
    func load() -> String?
    func save(_ token: String) throws
    func clear()
}

public final class InMemoryTokenStore: TokenStore, @unchecked Sendable {
    private let lock = NSLock()
    private var token: String?
    public init(_ token: String? = nil) { self.token = token }
    public func load() -> String? { lock.lock(); defer { lock.unlock() }; return token }
    public func save(_ token: String) throws { lock.lock(); self.token = token; lock.unlock() }
    public func clear() { lock.lock(); token = nil; lock.unlock() }
}
