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
    /// 409 answers carry a `reason` (PUT /v1/devices/{id}/escrow).
    var reason: String? = nil
    var errorDescription: String? { message }
}

final class PaxAPI {
    var base: URL
    var token: String? { Keychain.get("account-token") }
    var signedIn: Bool { token != nil }

    init(base: URL = Pax.apiBase) { self.base = base }

    /// POST /v1/accounts/email/verify: 201 created:true (a new account, its email verified) or
    /// 200 created:false (signed in to the account this email already has).
    struct Verified: Decodable { let account_id: String; let token: String; let created: Bool? }
    struct AccountStatus: Decodable {
        let account_id: String
        let email: String?
        let email_verified: Bool?
        /// The holder's first name in their trusted person's emails (`from_name`).
        let display_name: String?
        let wait_seconds: Int
        let partner_email: String?
        let pending_partner_email: String?
        let pending_wait_seconds: Int?
        let pending_wait_effective_at: Double?
        let pending_partner_effective_at: Double?
    }
    /// The server's device status (escrow.device_status).
    struct DeviceStatus: Decodable {
        let device_id: String
        let name: String?
        let platform: String?
        let in_grace_period: Bool?
        let grace_until: Double?
        let released: Bool?
        let wait_seconds: Int?
        let removal_request: RemovalRequest?
    }
    struct DeviceList: Decodable { let devices: [DeviceStatus] }
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

    // MARK: account: every account has a verified email (server 0.8.31, docs/ONETAP_ACCOUNTS.md)

    /// Emails a 6-digit code (a new address gets a sign-up code, a known one a sign-in code;
    /// the answer is always the same 202). Codes last 15 minutes, only the newest works.
    func startEmail(email: String) async throws {
        let _: Empty = try await send("POST", "/v1/accounts/email/start", ["email": email], auth: false)
    }

    /// Checks the code. Nothing is kept here: the caller decides whether to keep the token
    /// (see `keep(token:)`), so a sign-in to the wrong account never replaces anything.
    func verifyEmail(email: String, code: String, label: String) async throws -> Verified {
        try await send("POST", "/v1/accounts/email/verify",
                       ["email": email, "code": code, "label": String(label.prefix(100))], auth: false)
    }

    /// The token lives in this device's Keychain only (AfterFirstUnlockThisDeviceOnly). If it's
    /// ever lost, the same email and code sign in again.
    func keep(token: String) { Keychain.set(token, for: "account-token") }

    func signOutLocally() { Keychain.delete("account-token") }

    func me() async throws -> AccountStatus { try await send("GET", "/v1/accounts/me", nil) }

    /// Longer: instant. Shorter: the server makes it pending for the current wait and tells the
    /// trusted person first (503 if it can't, and nothing changes).
    @discardableResult
    func setWait(days: Int) async throws -> AccountStatus {
        try await send("PUT", "/v1/accounts/me/wait", ["wait_days": TurnOffRules.clampWait(days: days)])
    }

    /// `fromName` is the holder's first name in the trusted person's emails (one line, at most
    /// 40 characters). nil leaves it as it is; "" clears it.
    @discardableResult
    func setTrustedPerson(email: String, fromName: String?) async throws -> AccountStatus {
        var body: [String: Any] = ["email": email]
        if let n = fromName { body["from_name"] = n }
        return try await send("PUT", "/v1/accounts/me/partner", body)
    }

    /// Account deletion (server 0.8.30: 204 / 401 / 409 devices_still_protected / 429).
    /// Servers without the route answer 404 or 405 (0.8.29), which means "not available":
    /// the app falls back to an emailed request. See AccountDeletion.
    func deleteAccount() async throws -> AccountDeletion.Outcome {
        guard token != nil else { return .signedOut }
        let (status, data) = try await sendRaw("DELETE", "/v1/accounts/me")
        return AccountDeletion.outcome(status: status, body: data)
    }

    // MARK: device and turn-off

    /// Escrow first: the release key is saved here before anything is switched on.
    func registerDevice(name: String, platform: String, installID: String, secret: EscrowSecret) async throws -> DeviceStatus {
        try await send("POST", "/v1/devices", [
            "name": name, "platform": platform,
            "profile_identifier": "org.paxpeace.pax.appstore.\(installID)",
            "removal_password": secret.sealed,
            "support_release": true,
        ])
    }

    /// Replaces this device's escrowed secret (Home › Lock Screen Time adds the Screen Time
    /// passcode). Never loosens anything. The server refuses with 409 and a `reason` (released,
    /// retired, removal_request_open, emergency_open, changed) or 404; see `LockRefusal`.
    func replaceEscrow(device: String, secret: EscrowSecret) async throws {
        let _: Empty = try await send("PUT", "/v1/devices/\(device)/escrow", ["removal_password": secret.sealed])
    }

    func devices() async throws -> [DeviceStatus] {
        let l: DeviceList = try await send("GET", "/v1/devices", nil)
        return l.devices
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

    /// The status and body as they came, for answers the caller reads itself.
    private func sendRaw(_ method: String, _ path: String) async throws -> (Int, Data) {
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = method
        req.timeoutInterval = 30
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if let t = token { req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            return ((resp as? HTTPURLResponse)?.statusCode ?? 0, data)
        } catch {
            throw PaxAPIError(status: 0, code: "offline",
                              message: "Pax couldn't reach its server. Check your connection and try again.")
        }
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
                           message: message ?? "Pax's server couldn't do that (\(status)). Pax stays as it is.",
                           reason: obj?["reason"] as? String)
    }
}
