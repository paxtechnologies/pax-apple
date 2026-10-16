// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// v0.5: which escrow server the app talks to. Order: the PAX_SERVER_URL
/// environment variable (developers), then the URL saved in Settings › Advanced
/// (self-hosting), then the production Pax server https://api.paxpeace.com/
/// (v0.8.5; before that http://127.0.0.1:8080/). Plain http is accepted only
/// for this Mac and private networks (a self-hosted LAN box); anything on the
/// internet must be https, because the escrowed password travels in the body.
public enum ServerURLSetting {
    public static let defaultsKey = "pax.serverURL"
    public static let defaultURL = URL(string: "https://api.paxpeace.com/")!

    public enum Problem: Error, Equatable, LocalizedError {
        case empty
        case notAURL
        case unsupportedScheme
        case insecureRemote
        case extraParts

        public var errorDescription: String? {
            switch self {
            case .empty: return "Enter the server's address, for example https://pax.example.org."
            case .notAURL: return "That isn't a web address."
            case .unsupportedScheme: return "The address must start with https:// (or http:// for this Mac or your home network)."
            case .insecureRemote: return "A server on the internet needs https://. Plain http:// is only allowed for this Mac or a private network."
            case .extraParts: return "Leave out user names, passwords, ? and # parts."
            }
        }
    }

    /// Parse what the user typed. "pax.example.org" becomes https://pax.example.org/,
    /// "127.0.0.1:8080" becomes http://127.0.0.1:8080/. The result always ends in "/".
    public static func validate(_ raw: String) -> Result<URL, Problem> {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .failure(.empty) }
        if !text.contains("://") {
            let host = text.split(separator: "/").first.map(String.init) ?? text
            let bareHost = host.hasPrefix("[") ? host : String(host.split(separator: ":").first ?? "")
            text = (isLocalOrPrivate(host: bareHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]")))
                    ? "http://" : "https://") + text
        }
        guard var comps = URLComponents(string: text), let scheme = comps.scheme?.lowercased(),
              let host = comps.host, !host.isEmpty else { return .failure(.notAURL) }
        guard scheme == "https" || scheme == "http" else { return .failure(.unsupportedScheme) }
        if comps.user != nil || comps.password != nil || comps.query != nil || comps.fragment != nil {
            return .failure(.extraParts)
        }
        if scheme == "http" && !isLocalOrPrivate(host: host) { return .failure(.insecureRemote) }
        comps.scheme = scheme
        if !host.contains(":") { comps.host = host.lowercased() }   // leave IPv6 literals alone
        if !comps.path.hasSuffix("/") { comps.path += "/" }
        guard let url = comps.url else { return .failure(.notAURL) }
        return .success(url)
    }

    /// The URL the app should use now.
    public static func resolve(environment: [String: String], stored: String?) -> URL {
        if let env = environment["PAX_SERVER_URL"], !env.isEmpty, let url = URL(string: env) {
            return url
        }
        if let stored, case .success(let url) = validate(stored) { return url }
        return defaultURL
    }

    /// localhost, loopback, RFC 1918 / link-local IPv4, IPv6 loopback / ULA, *.local.
    public static func isLocalOrPrivate(host raw: String) -> Bool {
        let host = raw.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        if host == "localhost" || host.hasSuffix(".local") || host == "::1" { return true }
        if host.hasPrefix("fc") || host.hasPrefix("fd") { return host.contains(":") }
        let parts = host.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4, host.split(separator: ".").count == 4,
              parts.allSatisfy({ (0...255).contains($0) }) else { return false }
        switch (parts[0], parts[1]) {
        case (127, _), (10, _), (192, 168), (169, 254): return true
        case (172, let b) where (16...31).contains(b): return true
        default: return false
        }
    }
}

/// v0.8.5: partner emails for a Mac on local escrow go through a Pax server's
/// POST /v1/notify relay: by default the server the app uses (the production
/// server unless Settings › Advanced names another), signed in with this Mac's
/// own account token on it. A different relay URL needs its own token.
public enum PartnerRelay {
    /// The relay to use: the app's server when nothing (or just "https://") was
    /// typed, else what was typed, checked like the server address.
    public static func url(typed: String, appServer: URL) -> Result<URL, ServerURLSetting.Problem> {
        let text = typed.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.isEmpty || text == "https://" || text == "http://" { return .success(appServer) }
        return ServerURLSetting.validate(text)
    }

    /// True when no token was typed and the relay is the app's own server: the
    /// app then uses its account there (registering one first if it has none).
    public static func usesAppAccount(relay: URL, typedToken: String, appServer: URL) -> Bool {
        typedToken.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && relay.absoluteString == appServer.absoluteString
    }

    /// What pax-guard's partner.transport takes (guard/partner.py validate_transport).
    public static func transport(relay: URL, token: String) -> [String: String] {
        ["kind": "relay", "url": relay.absoluteString, "token": token]
    }
}

extension EscrowClient {
    /// GET /v1/health: true if a Pax server answers at baseURL.
    public func health() async throws -> Bool {
        let _: [String: AnyDecodable] = try await send("GET", "v1/health")
        return true
    }
}
