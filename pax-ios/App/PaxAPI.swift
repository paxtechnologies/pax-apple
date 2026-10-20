// SPDX-License-Identifier: GPL-3.0-only
// Client for the Pax server (api.paxpeace.com), the same endpoints the Mac app uses. The
// server keeps the turn-off wait, emails the trusted person first (and refuses if it
// can't: HTTP 503), and only then reveals the escrowed secret. Errors never lead to
// anything being removed on the device.
import Foundation

struct PaxAPIError: Error, LocalizedError {
    let status: Int
    let code: String?
    let message: String
    var errorDescription: String? { message }
}

final class PaxAPI {
    var base: URL
    var token: String? { Keychain.get("account-token") }
    var signedIn: Bool { token != nil }

    init(base: URL = Pax.apiBase) { self.base = base }

    struct Account: Decodable { let account_id: String; let token: String }
    struct AccountStatus: Decodable {
        let account_id: String
        let email: String
        let wait_seconds: Int
        let partner_email: String?
        let pending_partner_email: String?
    }
    /// The server's device status (escrow.device_status).
    struct DeviceStatus: Decodable {
        let device_id: String
        let in_grace_period: Bool?
        let grace_until: Double?
        let released: Bool?
        let wait_seconds: Int?
        let removal_request: RemovalRequest?
    }
    struct RemovalRequest: Decodable {
        let status: String
        let kind: String?
        let unlock_at: Double
        let seconds_remaining: Double?
        let can_reveal: Bool?
    }
    struct Reveal: Decodable { let removal_password: String }
    struct DNSInfo: Decodable { let doh_url: String }
    struct Empty: Decodable { init(from decoder: Decoder) throws {} }

    enum CreateResult { case created, exists }

    // MARK: account and sign-in (email code)

    /// Creates the account if the email is new. An existing email answers 409 (sign_in).
    /// The token from a new account is not kept: every device signs in with an emailed
    /// code, so the address is always checked.
    func createAccount(email: String) async throws -> CreateResult {
        do {
            let _: Account = try await send("POST", "/v1/accounts", ["email": email], auth: false)
            return .created
        } catch let e as PaxAPIError where e.status == 409 {
            return .exists
        }
    }

    func startSignIn(email: String) async throws {
        let _: Empty = try await send("POST", "/v1/accounts/signin/start", ["email": email], auth: false)
    }

    func finishSignIn(email: String, code: String, label: String) async throws {
        let a: Account = try await send("POST", "/v1/accounts/signin",
                                        ["email": email, "code": code, "label": label], auth: false)
        Keychain.set(a.token, for: "account-token")
    }

    func signOutLocally() { Keychain.delete("account-token") }

    func me() async throws -> AccountStatus { try await send("GET", "/v1/accounts/me", nil) }

    func setWait(days: Int) async throws {
        let _: Empty = try await send("PUT", "/v1/accounts/me/wait", ["wait_days": TurnOffRules.clampWait(days: days)])
    }

    func setTrustedPerson(email: String) async throws {
        let _: Empty = try await send("PUT", "/v1/accounts/me/partner", ["email": email])
    }

    /// Account deletion. The server has no delete route yet; a 404/405 answer means
    /// "not available", and the app falls back to an emailed request.
    enum DeleteResult { case deleted, notAvailable }
    func deleteAccount() async throws -> DeleteResult {
        do {
            let _: Empty = try await send("DELETE", "/v1/accounts/me", nil)
            return .deleted
        } catch let e as PaxAPIError where e.status == 404 || e.status == 405 {
            return .notAvailable
        }
    }

    // MARK: device and turn-off

    func registerDevice(name: String, platform: String, installID: String, secret: EscrowSecret) async throws -> DeviceStatus {
        try await send("POST", "/v1/devices", [
            "name": name, "platform": platform,
            "profile_identifier": "org.paxpeace.pax.appstore.\(installID)",
            "removal_password": secret.sealed,
            "support_release": true,
        ])
    }

    func status(device: String) async throws -> DeviceStatus {
        try await send("GET", "/v1/devices/\(device)", nil)
    }

    func requestTurnOff(device: String) async throws -> DeviceStatus {
        try await send("POST", "/v1/devices/\(device)/removal-request", [String: Any]())
    }

    func cancelTurnOff(device: String) async throws -> DeviceStatus {
        try await send("POST", "/v1/devices/\(device)/removal-request/cancel", [String: Any]())
    }

    func confirmTurnOff(device: String) async throws -> String {
        let r: Reveal = try await send("POST", "/v1/devices/\(device)/removal-request/confirm", ["confirm": true])
        return r.removal_password
    }

    // MARK: blocked sites, DNS, alerts

    func addBlocked(domain: String) async throws {
        let _: Empty = try await send("POST", "/v1/blocklist", ["domain": domain])
    }

    func dnsInfo() async throws -> URL {
        let d: DNSInfo = try await send("GET", "/v1/dns", nil)
        guard let u = URL(string: d.doh_url), u.scheme == "https", u.host == Pax.dnsHost else {
            throw PaxAPIError(status: 0, code: "bad_dns_url", message: "Pax couldn't get its DNS address.")
        }
        return u
    }

    /// The server's notify relay: the trusted person's copy is sent first (fail closed).
    func notify(_ m: PaxAlertEmail, trustedEmail: String?) async throws {
        var body: [String: Any] = ["kind": m.kind, "subject": m.subject, "body": m.body]
        if let t = trustedEmail, !t.isEmpty {
            body["partner_email"] = t
            body["partner_body"] = m.trustedBody
        }
        let _: Empty = try await send("POST", "/v1/notify", body)
    }

    // MARK: plumbing

    private func send<T: Decodable>(_ method: String, _ path: String, _ body: [String: Any]?, auth: Bool = true) async throws -> T {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = method
        req.timeoutInterval = 30
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if auth {
            guard let t = token else {
                throw PaxAPIError(status: 401, code: "signed_out", message: "Please sign in to Pax again.")
            }
            req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization")
        }
        if let body { req.httpBody = try JSONSerialization.data(withJSONObject: body) }
        let pair: (Data, URLResponse)
        do {
            pair = try await URLSession.shared.data(for: req)
        } catch {
            throw PaxAPIError(status: 0, code: "offline",
                              message: "Pax couldn't reach its server. Check your connection and try again.")
        }
        let (data, resp) = pair
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw PaxAPI.error(status: status, data: data)
        }
        return try JSONDecoder().decode(T.self, from: data.isEmpty ? Data("{}".utf8) : data)
    }

    /// The server answers errors as {"error": code, "message": text, "pax_code": …}.
    static func error(status: Int, data: Data) -> PaxAPIError {
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        let code = obj?["error"] as? String
        var message = (obj?["message"] as? String) ?? (obj?["detail"] as? String)
        if status == 503 {
            message = "Pax couldn't email your trusted person, so nothing has changed. Please try again later."
        } else if status == 429 {
            message = "Too many tries. Please wait a little and try again."
        }
        if let m = message, let first = m.first {
            var tidy = first.uppercased() + m.dropFirst()
            if !tidy.hasSuffix(".") { tidy += "." }
            message = tidy
        }
        return PaxAPIError(status: status, code: code,
                           message: message ?? "Pax's server couldn't do that (\(status)). Pax stays as it is.")
    }
}
