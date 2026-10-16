// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - v0.8.9 wait limits

/// The waits a path accepts. v0.8.9: 24 hours to 365 days on the Pax server and on a
/// Mac's own key alike (server/pax_server/config.py, guard/local_escrow.py). A server
/// older than 0.8.9 doesn't say, and refused anything under 3 days.
public struct WaitLimits: Equatable, Sendable {
    public let minSeconds: Int
    public let maxSeconds: Int

    public init(minSeconds: Int, maxSeconds: Int) {
        self.minSeconds = minSeconds
        self.maxSeconds = max(minSeconds, maxSeconds)
    }

    /// 0.8.9 everywhere, and always a Mac's own key (pax-guard).
    public static let standard = WaitLimits(minSeconds: 86_400, maxSeconds: 365 * 86_400)
    /// A Pax server from before 0.8.9 (no wait_limits in /v1/health).
    public static let legacyServer = WaitLimits(minSeconds: 3 * 86_400, maxSeconds: 365 * 86_400)

    /// Whole days the picker may offer.
    public var dayRange: ClosedRange<Int> {
        let lo = max(1, Int((Double(minSeconds) / 86_400).rounded(.up)))
        let hi = max(lo, maxSeconds / 86_400)
        return lo...hi
    }

    public func allows(days: Int) -> Bool { dayRange.contains(days) }

    /// The preset choices this path accepts.
    public func choices(_ days: [Int]) -> [Int] { days.filter(allows) }

    /// The nearest wait this path accepts.
    public func clamp(days: Int) -> Int { min(max(days, dayRange.lowerBound), dayRange.upperBound) }

    /// From GET /v1/health's `wait_limits` (nil = an older server).
    public static func fromHealth(_ obj: [String: Any]?) -> WaitLimits {
        guard let w = obj?["wait_limits"] as? [String: Any],
              let lo = (w["min_wait_seconds"] as? NSNumber)?.intValue,
              let hi = (w["max_wait_seconds"] as? NSNumber)?.intValue, lo > 0, hi >= lo else {
            return .legacyServer
        }
        return WaitLimits(minSeconds: lo, maxSeconds: hi)
    }
}

extension EscrowClient {
    /// The waits this server accepts (v0.8.9 /v1/health `wait_limits`); a server that
    /// doesn't say is treated as an older one (3 days minimum).
    public func waitLimits() async -> WaitLimits {
        var req = URLRequest(url: baseURL.appendingPathComponent("v1/health"))
        req.timeoutInterval = 10
        guard let (data, response) = try? await session.data(for: req),
              (response as? HTTPURLResponse)?.statusCode == 200 else { return .legacyServer }
        return WaitLimits.fromHealth((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])
    }
}

// MARK: - v0.8.9 blocked-sites sync

extension EscrowClient {
    public struct SyncLink: Decodable, Sendable, Equatable {
        public let link_id: String
        public let sync_token: String
        public let account_email: String?
    }

    /// A narrow sign-in for this Mac's pax-guard: read and add to the account's
    /// blocked sites, ask to remove one (the one removal rule), cancel. Nothing else.
    public func createSyncLink(deviceName: String) async throws -> SyncLink {
        try await send("POST", "v1/sync/links", body: ["device_name": String(deviceName.prefix(100))])
    }

    /// Sign in to an existing account (same email, set up on another Mac): a
    /// one-time code goes to the email. The answer is the same for any address.
    public func startSignIn(email: String) async throws {
        let _: [String: AnyDecodable] = try await send("POST", "v1/accounts/signin/start", body: ["email": email])
    }

    public func signIn(email: String, code: String, label: String = "Mac") async throws -> Account {
        try await send("POST", "v1/accounts/signin", body: [
            "email": email, "code": code.trimmingCharacters(in: .whitespacesAndNewlines),
            "label": String(label.prefix(100)),
        ])
    }

    /// True when registering failed because the email already has an account
    /// (HTTP 409): the app then offers to sign in with a code instead.
    public static func isExistingAccount(_ error: Error) -> Bool {
        (error as? APIError)?.status == 409
    }
}

extension GuardClient {
    public struct SyncStatus: Decodable, Sendable, Equatable {
        public let enabled: Bool
        public let linked: Bool
        public let account_email: String?
        public let last_ok: Int?
        public let queued: Int?
        public let pending: Int?
        public let delay_seconds: Int?

        public init(enabled: Bool, linked: Bool, account_email: String? = nil, last_ok: Int? = nil,
                    queued: Int? = 0, pending: Int? = 0, delay_seconds: Int? = nil) {
            self.enabled = enabled
            self.linked = linked
            self.account_email = account_email
            self.last_ok = last_ok
            self.queued = queued
            self.pending = pending
            self.delay_seconds = delay_seconds
        }
    }

    public func syncStatus() async throws -> SyncStatus {
        try decode(SyncStatus.self, try await call(["cmd": "sync.get"]), key: "sync")
    }

    /// "Sync blocked sites across devices". Off never unblocks anything (this Mac
    /// keeps its copy); on merges both lists (nothing removed). Logged by pax-guard.
    public func setSync(_ on: Bool) async throws -> SyncStatus {
        try decode(SyncStatus.self, try await call(["cmd": "sync.set", "enabled": on]), key: "sync")
    }

    /// Hands pax-guard the account's sync sign-in. The token goes over the local
    /// socket only and pax-guard never returns it.
    public func linkSync(serverURL: String, token: String, accountEmail: String?) async throws -> SyncStatus {
        var req: [String: Any] = ["cmd": "sync.link", "server_url": serverURL, "token": token]
        if let accountEmail { req["account_email"] = accountEmail }
        return try decode(SyncStatus.self, try await call(req), key: "sync")
    }
}

/// When the app links this Mac's list to the account: zero extra steps. A Mac on its
/// own key, protected, with sync on but not linked yet, and the app signed in to an
/// account (made when an iPhone was set up from this Mac, for partner emails, or by
/// signing in with a code). An older pax-guard (no sync.get) is never linked.
public enum ListSyncLinker {
    public static func shouldLink(localKey: Bool, protected: Bool, hasAccount: Bool,
                                  status: GuardClient.SyncStatus?) -> Bool {
        guard localKey, protected, hasAccount, let status else { return false }
        return status.enabled && !status.linked
    }

    /// The calm line under the switch.
    public static func detail(_ s: GuardClient.SyncStatus?) -> String {
        guard let s else { return "Shares one list between this Mac, your iPhone and your iPad." }
        if !s.enabled {
            return "Off: this Mac keeps its own list. Nothing was unblocked."
        }
        if !s.linked {
            return "On. Your list joins your iPhone and iPad as soon as one is set up with Pax."
        }
        return "On. Sites you add here are blocked on your iPhone and iPad within seconds, and theirs here."
    }
}
