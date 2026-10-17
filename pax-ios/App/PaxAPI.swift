// SPDX-License-Identifier: GPL-3.0-only
// Client for the existing Pax server (api.paxpeace.com). Same endpoints Pax Strict uses:
// the server keeps the wait, emails the partner first (and refuses if it can't), and only
// then reveals the escrowed secret. Errors never lead to anything being removed.
import Foundation

struct PaxAPIError: Error, LocalizedError {
    let status: Int
    let message: String
    var errorDescription: String? { message }
}

final class PaxAPI {
    var base: URL
    var token: String? { Keychain.get("account-token") }

    init(base: URL = Pax.apiBase) { self.base = base }

    struct Account: Decodable { let account_id: String; let token: String }
    /// The server's device status (escrow.device_status).
    struct DeviceStatus: Decodable {
        let device_id: String
        let in_grace_period: Bool?
        let removal_request: RemovalRequest?
    }
    struct RemovalRequest: Decodable {
        let status: String
        let unlock_at: Double
        let seconds_remaining: Double?
        let can_reveal: Bool?
    }
    struct Reveal: Decodable { let removal_password: String }

    func createAccount(email: String) async throws {
        let a: Account = try await send("POST", "/v1/accounts", ["email": email], auth: false)
        Keychain.set(a.token, for: "account-token")
    }

    func setWait(days: Int) async throws {
        let _: Empty = try await send("PUT", "/v1/accounts/me/wait", ["wait_days": TurnOffRules.clampWait(days: days)])
    }

    func setPartner(email: String?) async throws {
        let _: Empty = try await send("PUT", "/v1/accounts/me/partner", ["email": email.map { $0 as Any } ?? NSNull()])
    }

    func registerDevice(name: String, platform: String, installID: String, secret: EscrowSecret) async throws -> String {
        let d: DeviceStatus = try await send("POST", "/v1/devices", [
            "name": name, "platform": platform,
            "profile_identifier": "org.paxpeace.pax.appstore.\(installID)",
            "removal_password": secret.sealed,
            "support_release": true,
        ])
        return d.device_id
    }

    func requestTurnOff(device: String) async throws -> DeviceStatus {
        try await send("POST", "/v1/devices/\(device)/removal-request", [String: Any]())
    }

    func cancelTurnOff(device: String) async throws {
        let _: Empty = try await send("POST", "/v1/devices/\(device)/removal-request/cancel", [String: Any]())
    }

    func confirmTurnOff(device: String) async throws -> String {
        let r: Reveal = try await send("POST", "/v1/devices/\(device)/removal-request/confirm", ["confirm": true])
        return r.removal_password
    }

    func status(device: String) async throws -> DeviceStatus {
        try await get("/v1/devices/\(device)")
    }

    func addBlocked(domain: String) async throws {
        let _: Empty = try await send("POST", "/v1/blocklist", ["domain": domain])
    }

    // MARK: - plumbing

    struct Empty: Decodable { init(from decoder: Decoder) throws {} }

    private func get<T: Decodable>(_ path: String) async throws -> T {
        try await send("GET", path, nil)
    }

    private func send<T: Decodable>(_ method: String, _ path: String, _ body: [String: Any]?, auth: Bool = true) async throws -> T {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = method
        req.timeoutInterval = 30
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if auth, let t = token { req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
        if let body { req.httpBody = try JSONSerialization.data(withJSONObject: body) }
        let (data, resp) = try await URLSession.shared.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let detail = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["detail"]
            throw PaxAPIError(status: status, message: (detail as? String) ?? "Pax couldn't reach its server (\(status)).")
        }
        return try JSONDecoder().decode(T.self, from: data.isEmpty ? Data("{}".utf8) : data)
    }
}
