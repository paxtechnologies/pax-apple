// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Security
import PaxCore

/// Keeps the escrow API token in the login Keychain so "Blocked sites" works after
/// a relaunch and on later set-ups (same account, same synced blocklist).
final class KeychainTokenStore: TokenStore, @unchecked Sendable {
    // TODO: rename with the bundle ID (org.paxpeace.pax) once a migration exists.
    private let service = "org.paxmobile.pax.escrow-token"
    private let account: String

    init(serverURL: URL) {
        account = serverURL.absoluteString
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    func load() -> String? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func save(_ token: String) throws {
        let data = Data(token.utf8)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let s = SecItemAdd(add as CFDictionary, nil)
            guard s == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(s)) }
        } else if status != errSecSuccess {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }

    func clear() {
        SecItemDelete(query as CFDictionary)
    }
}
