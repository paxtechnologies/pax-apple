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

    public func registerAccount(email: String) async throws -> Account {
        try await send("POST", "v1/accounts", body: ["email": email])
    }

    public func setWait(days: Int) async throws {
        let _: [String: AnyDecodable] = try await send("PUT", "v1/accounts/me/wait", body: ["wait_days": days])
    }

    public func setPartner(email: String?) async throws {
        let _: [String: AnyDecodable] = try await send("PUT", "v1/accounts/me/partner", body: ["email": email])
    }

    public func registerDevice(name: String, platform: String, profileIdentifier: String,
                               removalPassword: String) async throws -> Device {
        try await send("POST", "v1/devices", body: [
            "name": name, "platform": platform,
            "profile_identifier": profileIdentifier, "removal_password": removalPassword,
        ])
    }
}

/// Decodes and discards any JSON value.
public struct AnyDecodable: Decodable, Sendable {
    public init(from decoder: Decoder) throws {
        _ = try? decoder.singleValueContainer()
    }
}
