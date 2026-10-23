// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Minimal client for the Pax escrow server (server/ in this repo).
public struct EscrowClient: Sendable {
    public struct APIError: Error, LocalizedError {
        public let status: Int
        public let code: String
        public let message: String
        public var errorDescription: String? { message }
    }

    public struct Account: Decodable, Sendable {
        public let account_id: String
        public let token: String
    }

    public struct Device: Decodable, Sendable {
        public let device_id: String
        public let installed_at: Int
        public let grace_until: Int
    }

    public let baseURL: URL
    public var token: String?
    let session: URLSession

    public init(baseURL: URL, token: String? = nil, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.token = token
        self.session = session
    }

    func send<T: Decodable>(_ method: String, _ path: String, body: [String: Any?]? = nil) async throws -> T {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body {
            let cleaned = body.mapValues { $0 ?? NSNull() }
            req.httpBody = try JSONSerialization.data(withJSONObject: cleaned)
        }
        let (data, response) = try await session.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            throw APIError(status: status, code: obj?["error"] as? String ?? "http_\(status)",
                           message: obj?["message"] as? String ?? "Server error \(status)")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    // v0.8.32: no registerAccount. POST /v1/accounts no longer makes accounts (410
    // app_update_required); every account is made by an emailed code (EmailCode.swift).

    public func setWait(days: Int) async throws {
        let _: [String: AnyDecodable] = try await send("PUT", "v1/accounts/me/wait", body: ["wait_days": days])
    }

    public func setPartner(email: String?) async throws {
        let _: [String: AnyDecodable] = try await send("PUT", "v1/accounts/me/partner", body: ["email": email])
    }

    /// v0.8.15: `supportRelease` is the set-up choice "Allow verified support release".
    /// Left out (an older app), the server keeps it off.
    /// v0.8.18: `trial` asks for a trial day and `hardwareID` (TrialDay.hardwareID) lets the
    /// server count it from this hardware's first one; without it the server grants none.
    public func registerDevice(name: String, platform: String, profileIdentifier: String,
                               removalPassword: String, supportRelease: Bool = false,
                               trial: Bool = false, hardwareID: String? = nil) async throws -> Device {
        var body: [String: Any?] = [
            "name": name, "platform": platform,
            "profile_identifier": profileIdentifier, "removal_password": removalPassword,
            "support_release": supportRelease,
        ]
        if trial, let hw = hardwareID {
            body["trial"] = true
            body["hardware_id"] = hw
        }
        return try await send("POST", "v1/devices", body: body)
    }
}

/// Decodes and discards any JSON value.
public struct AnyDecodable: Decodable, Sendable {
    public init(from decoder: Decoder) throws {
        _ = try? decoder.singleValueContainer()
    }
}
