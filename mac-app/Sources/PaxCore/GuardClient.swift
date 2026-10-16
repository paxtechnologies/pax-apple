// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// v0.8.0: where this Mac keeps the key that undoes Pax.
/// `.local` (default): pax-guard holds it on this Mac, no server needed.
/// `.server`: the Pax escrow server (v0.4-v0.7), under Settings › Advanced.
/// iPhones and iPads always use the server path.
public enum MacEscrowMode: String, Sendable, CaseIterable {
    case local, server
    public static let defaultsKey = "pax.mac.escrowMode"
    public static func current(_ defaults: UserDefaults = .standard) -> MacEscrowMode {
        MacEscrowMode(rawValue: defaults.string(forKey: defaultsKey) ?? "") ?? .local
    }
}

/// v0.8.7: where the "Ads and trackers" switch on Home goes.
public enum AdblockSwitch: Equatable, Sendable {
    /// Local escrow with a pax-guard that has the switch (0.8.7+): immediate.
    case guardLive
    /// Server escrow: the Pax server's account setting, which pax-guard reads within a minute.
    case server
    /// Local escrow with an older pax-guard that only reads the set-up choice:
    /// shown as set at set-up, not as a switch that does nothing.
    case setUpOnly

    public static func mode(localEscrow: Bool, settings: GuardClient.Settings?) -> AdblockSwitch {
        guard localEscrow else { return .server }
        return settings?.adblock != nil ? .guardLive : .setUpOnly
    }
}

/// Sends one JSON line to pax-guard and reads one JSON line back.
public protocol GuardTransport: Sendable {
    func exchange(_ request: Data) async throws -> Data
}

/// /var/run/pax-guard.sock (root's pax-guard listens; 0666 so the Standard account's app can talk to it).
public struct UnixSocketTransport: GuardTransport {
    public let path: String
    public let timeoutSeconds: Int

    public init(path: String = "/var/run/pax-guard.sock", timeoutSeconds: Int = 15) {
        self.path = path
        self.timeoutSeconds = timeoutSeconds
    }

    public func exchange(_ request: Data) async throws -> Data {
        let path = self.path
        let timeout = self.timeoutSeconds
        return try await Task.detached { try Self.blockingExchange(request, path: path, timeout: timeout) }.value
    }

    static func blockingExchange(_ request: Data, path: String, timeout: Int) throws -> Data {
        #if canImport(Darwin)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard fd >= 0 else { throw GuardClient.Failure(code: "PAX-GUARD-012", message: "no socket") }
        defer { close(fd) }
        var tv = timeval(tv_sec: timeout, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < capacity else { throw GuardClient.Failure(code: "PAX-GUARD-012", message: "path too long") }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, b) in bytes.enumerated() { raw[i] = b }
            raw[bytes.count] = 0
        }
        #if canImport(Darwin)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        #endif
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard ok == 0 else {
            throw GuardClient.Failure(code: "PAX-GUARD-012", message: "Pax's background protection isn't answering")
        }
        var out = request
        out.append(0x0A)
        let sent = out.withUnsafeBytes { send(fd, $0.baseAddress, out.count, 0) }
        guard sent == out.count else { throw GuardClient.Failure(code: "PAX-GUARD-012", message: "send failed") }
        var reply = Data()
        var buf = [UInt8](repeating: 0, count: 65_536)
        while true {
            let n = recv(fd, &buf, buf.count, 0)
            if n <= 0 { break }
            reply.append(contentsOf: buf[0..<n])
            if buf[n - 1] == 0x0A { break }
        }
        guard !reply.isEmpty else { throw GuardClient.Failure(code: "PAX-GUARD-012", message: "no answer") }
        return reply
    }
}

/// The app's side of pax-guard's socket (guard/guard_ipc.py).
public struct GuardClient: Sendable {
    public struct Failure: Error, LocalizedError, Equatable {
        public let code: String
        public let message: String
        public var errorDescription: String? { "\(code): \(message)" }
    }

    public struct Status: Decodable, Sendable {
        public let version: String
        public let escrow_mode: String
        public let released: Bool?
        public let dns: DNS?
        public let update: Update?
        public let tamper: Tamper?
        /// v0.8.6: the user's switches (YouTube Restricted Mode).
        public let settings: Settings?
        /// v0.8.14: whether Chrome's locked extension list is older than this version's.
        public let browser_rules: BrowserRules?

        public struct BrowserRules: Decodable, Sendable, Equatable {
            public let browser: String?
            public let outdated: Bool
            public let missing: [String]
        }

        public struct DNS: Decodable, Sendable {
            public let active: String?
            public let ready: Bool?
            public let all_down: Bool?
        }
        public struct Tamper: Decodable, Sendable {
            public let intact: Bool
            public let count: Int
            public let recent: [TamperEvent]
        }
    }

    /// v0.8.6 Settings › This Mac switches kept by pax-guard (state/settings.json).
    public struct Settings: Decodable, Sendable, Equatable {
        public let youtube_restricted: Bool
        /// False when this Mac's DNS doesn't go through pax-guard (dns_mode "profile").
        public let youtube_available: Bool?
        /// v0.8.7: "Ads and trackers" in effect. nil from a pax-guard older than 0.8.7.
        public let adblock: Bool?
        /// v0.8.7: true when pax-guard holds the ads setting (local escrow); false when
        /// the Pax server does (server escrow).
        public let adblock_local: Bool?
        // v0.8.13: no x_media / bluesky_media: pictures and video on X and Bluesky are
        // always blocked (a 0.8.12 pax-guard's extra keys are ignored when decoding).
        /// v0.8.12: Pax Max after set-up. nil from a pax-guard older than 0.8.12.
        public let pax_max: PaxMaxView?
        public init(youtube_restricted: Bool, youtube_available: Bool? = true,
                    adblock: Bool? = nil, adblock_local: Bool? = nil,
                    pax_max: PaxMaxView? = nil) {
            self.pax_max = pax_max
            self.youtube_restricted = youtube_restricted
            self.youtube_available = youtube_available
            self.adblock = adblock
            self.adblock_local = adblock_local
        }
    }

    public struct Update: Decodable, Sendable, Equatable {
        public let installed: String
        public let last_checked: Int?
        public let latest: String?
        public let state: String?
        public let notice: String?
        public let last_error: String?
    }

    public struct TamperEvent: Decodable, Sendable, Equatable {
        public let ts: Int
        public let kind: String
    }

    /// What escrow.reveal hands back after the wait.
    public struct Released: Decodable, Sendable, Equatable {
        public let device_id: String
        public let reason: String
        public let removal_password: String?
        public let recovery_key: String?
        public let firmware_password: String?
    }

    public struct PartnerView: Decodable, Sendable, Equatable {
        public let partner: String?
        public let owner_email: String?
        public let pending_partner: Pending?
        public let transport: Transport?
        public struct Pending: Decodable, Sendable, Equatable {
            public let email: String?
            public let effective_at: Int
        }
        public struct Transport: Decodable, Sendable, Equatable {
            public let kind: String?
            public let url: String?
            public let host: String?
        }
    }

    let transport: GuardTransport

    public init(transport: GuardTransport = UnixSocketTransport()) {
        self.transport = transport
    }

    /// Sends a request; returns the answer's JSON object, or throws the guard's coded error.
    func call(_ request: [String: Any]) async throws -> [String: Any] {
        let body = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
        let data = try await transport.exchange(body)
        guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw Failure(code: "PAX-GUARD-012", message: "unreadable answer")
        }
        if obj["ok"] as? Bool != true {
            throw Failure(code: obj["code"] as? String ?? "PAX-GUARD-012",
                          message: obj["error"] as? String ?? "pax-guard said no")
        }
        return obj
    }

    func decode<T: Decodable>(_ type: T.Type, _ obj: [String: Any], key: String? = nil) throws -> T {
        let value: Any = key.map { obj[$0] ?? NSNull() } ?? obj
        let data = try JSONSerialization.data(withJSONObject: value)
        return try JSONDecoder().decode(T.self, from: data)
    }

    // MARK: Status and updates

    public func status() async throws -> Status { try decode(Status.self, try await call(["cmd": "status"])) }

    public func updateNow() async throws -> Update {
        try decode(Update.self, try await call(["cmd": "update.now"]), key: "update")
    }

    /// v0.8.6: YouTube Restricted Mode. Both directions apply at once (no wait, no
    /// partner email; the maintainer's decision); pax-guard logs the change.
    public func settings() async throws -> Settings {
        try decode(Settings.self, try await call(["cmd": "settings.get"]), key: "settings")
    }

    public func setYouTubeRestricted(_ on: Bool) async throws -> Settings {
        try decode(Settings.self, try await call(["cmd": "settings.set", "youtube_restricted": on]), key: "settings")
    }

    /// v0.8.7: "Ads and trackers" on local escrow. Both directions apply at once (no
    /// wait, no partner email: a convenience filter, not restricted-content
    /// protection); pax-guard logs the change and keeps restricted names blocked.
    public func setAdblock(_ on: Bool) async throws -> Settings {
        try decode(Settings.self, try await call(["cmd": "settings.set", "adblock": on]), key: "settings")
    }

    // MARK: v0.8.7 Blocked apps (local escrow)

    public struct BlockedApp: Decodable, Sendable, Equatable, Identifiable {
        public let bundle_id: String
        public let name: String
        public let team_id: String?
        public let added_at: Int
        /// A waiting unblock (your wait, partner told first), if any.
        public let pending_removal: BlocklistRequest?
        public var id: String { bundle_id }
    }

    /// v0.8.12 Pax Max on this Mac (pax-guard `paxmax.*`). `switchable` false: chosen
    /// at set-up only (set up before 0.8.12, or the key is on a Pax server).
    public struct PaxMaxView: Decodable, Sendable, Equatable {
        public let switchable: Bool
        public let on: Bool?
        public let pending: BlocklistRequest?
        public let off_delay_seconds: Int?
        public init(switchable: Bool, on: Bool?, pending: BlocklistRequest? = nil, off_delay_seconds: Int? = 3600) {
            self.switchable = switchable
            self.on = on
            self.pending = pending
            self.off_delay_seconds = off_delay_seconds
        }
    }

    public func paxMax() async throws -> PaxMaxView {
        try decode(PaxMaxView.self, try await call(["cmd": "paxmax.get"]), key: "pax_max")
    }

    /// Instant, any time after set-up (it makes Pax stricter); cancels a waiting "off".
    public func turnPaxMaxOn() async throws -> PaxMaxView {
        try decode(PaxMaxView.self, try await call(["cmd": "paxmax.on"]), key: "pax_max")
    }

    /// A loosening: your partner is told first (PAX-ESCROW-010 if they can't be: the
    /// hour hasn't started), then it takes a fixed hour. Refused offline (PAX-GUARD-014).
    public func requestPaxMaxOff() async throws -> PaxMaxView {
        try decode(PaxMaxView.self, try await call(["cmd": "paxmax.off"]), key: "pax_max")
    }

    public func cancelPaxMaxOff(requestID: String) async throws -> PaxMaxView {
        try decode(PaxMaxView.self, try await call(["cmd": "paxmax.cancel", "request_id": requestID]), key: "pax_max")
    }

    public struct AppsView: Decodable, Sendable, Equatable {
        public struct Limits: Decodable, Sendable, Equatable {
            public let max_apps: Int
            public let delay_seconds: Int
        }
        public let now: Int
        public let apps: [BlockedApp]
        public let pending: [BlocklistRequest]
        public let limits: Limits
    }

    public func blockedApps() async throws -> AppsView {
        try decode(AppsView.self, try await call(["cmd": "apps.get"]), key: "apps")
    }

    /// Adding is instant. pax-guard reads the app at `path` itself (bundle ID and
    /// code signature, as root) and refuses Pax, Apple's apps and password managers
    /// (PAX-MAC-016).
    public func addBlockedApp(path: String) async throws -> AppsView {
        try decode(AppsView.self, try await call(["cmd": "apps.add", "path": path]), key: "apps")
    }

    /// Unblocking is a loosening: it waits like unblocking a site, partner told first.
    public func unblockApp(bundleID: String) async throws -> AppsView {
        try decode(AppsView.self, try await call(["cmd": "apps.unblock", "bundle_id": bundleID]), key: "apps")
    }

    public func cancelAppRequest(_ requestID: String) async throws -> AppsView {
        try decode(AppsView.self, try await call(["cmd": "apps.cancel", "request_id": requestID]), key: "apps")
    }

    public func tamperEvents() async throws -> [TamperEvent] {
        try decode([TamperEvent].self, try await call(["cmd": "tamper.list"]), key: "events")
    }

    // MARK: Local escrow (same shape as the server's device status)

    public func device() async throws -> EscrowClient.DeviceStatus {
        try decode(EscrowClient.DeviceStatus.self, try await call(["cmd": "escrow.status"]), key: "device")
    }

    public func requestRemoval(reason: String = "remove") async throws -> EscrowClient.DeviceStatus {
        try decode(EscrowClient.DeviceStatus.self, try await call(["cmd": "escrow.request", "reason": reason]),
                   key: "device")
    }

    public func cancelRemoval() async throws -> EscrowClient.DeviceStatus {
        try decode(EscrowClient.DeviceStatus.self, try await call(["cmd": "escrow.cancel"]), key: "device")
    }

    public func emergency(reason: String) async throws -> EscrowClient.DeviceStatus {
        try decode(EscrowClient.DeviceStatus.self, try await call(["cmd": "escrow.emergency", "reason": reason]),
                   key: "device")
    }

    public func setWait(seconds: Int) async throws -> EscrowClient.DeviceStatus {
        try decode(EscrowClient.DeviceStatus.self, try await call(["cmd": "escrow.set_wait", "seconds": seconds]),
                   key: "device")
    }

    public func reveal() async throws -> Released {
        try decode(Released.self, try await call(["cmd": "escrow.reveal"]), key: "released")
    }

    // MARK: Partner emails (local escrow)

    public func partner() async throws -> PartnerView {
        try decode(PartnerView.self, try await call(["cmd": "partner.get"]), key: "partner")
    }

    public func setPartner(_ email: String?) async throws {
        _ = try await call(["cmd": "partner.set", "email": email ?? NSNull()])
    }

    /// `transport` is ["kind": "relay", "url": …, "token": …] or
    /// ["kind": "smtp", "host": …, "port": …, "security": "starttls"|"ssl", "username": …, "password": …, "from": …].
    public func setEmailTransport(_ transport: [String: Any]?, ownerEmail: String?) async throws -> PartnerView {
        var req: [String: Any] = ["cmd": "partner.transport"]
        if let transport { req["transport"] = transport }
        if let ownerEmail { req["owner_email"] = ownerEmail }
        return try decode(PartnerView.self, try await call(req), key: "partner")
    }
}

// MARK: - The blocked-sites list, from the server or from pax-guard

/// What "Blocked sites" needs, whoever keeps the list.
public protocol BlocklistBackend: Sendable {
    func blocklist() async throws -> BlocklistView
    func blockSite(_ domain: String) async throws -> BlocklistAddResult
    func requestUnblock(_ domain: String) async throws -> BlocklistRequestResult
    func requestAllow(_ domain: String) async throws -> BlocklistRequestResult
    func removeAllow(_ domain: String) async throws -> BlocklistView
    func cancelBlocklistRequest(_ id: String) async throws -> BlocklistView
}

extension EscrowClient: BlocklistBackend {}

extension GuardClient: BlocklistBackend {
    public func blocklist() async throws -> BlocklistView {
        try decode(BlocklistView.self, try await call(["cmd": "blocklist.get"]), key: "list")
    }

    public func blockSite(_ domain: String) async throws -> BlocklistAddResult {
        try decode(BlocklistAddResult.self, try await call(["cmd": "blocklist.add", "domain": domain]))
    }

    public func requestUnblock(_ domain: String) async throws -> BlocklistRequestResult {
        try decode(BlocklistRequestResult.self, try await call(["cmd": "blocklist.unblock", "domain": domain]))
    }

    public func requestAllow(_ domain: String) async throws -> BlocklistRequestResult {
        try decode(BlocklistRequestResult.self, try await call(["cmd": "blocklist.allow", "domain": domain]))
    }

    public func removeAllow(_ domain: String) async throws -> BlocklistView {
        try decode(BlocklistView.self, try await call(["cmd": "blocklist.remove_allow", "domain": domain]), key: "list")
    }

    public func cancelBlocklistRequest(_ id: String) async throws -> BlocklistView {
        try decode(BlocklistView.self, try await call(["cmd": "blocklist.cancel", "request_id": id]), key: "list")
    }
}

/// Plain words for Home's filter line.
public enum FilterStatusText {
    public static func line(_ dns: GuardClient.Status.DNS?) -> String {
        guard let dns else { return "Checking the filter…" }
        if dns.ready == false { return "Starting the filter…" }
        if dns.all_down == true || dns.active == nil {
            return "No filter is reachable, so websites won't open for now."
        }
        if dns.active == "CleanBrowsing Family" { return "Filtering through CleanBrowsing." }
        return "Filtering through \(dns.active ?? "the backup filter") (backup)."
    }
}
