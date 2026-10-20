// SPDX-License-Identifier: GPL-3.0-only
// Encrypted DNS through Pax's own filter (https://dns.paxpeace.com/u/<token>/dns-query).
// The person turns it on in Settings › General › VPN & Device Management › DNS, and can
// turn it off there too: iOS doesn't let an App Store app lock it. Pax checks each time
// it opens and tells the trusted person if it's off (hardware test T10). No query logs.
import Foundation
import NetworkExtension

enum PaxDNS {
    static func install(dohURL: URL) async throws {
        let m = NEDNSSettingsManager.shared()
        try await m.loadFromPreferences()
        let s = NEDNSOverHTTPSSettings(servers: [])
        s.serverURL = dohURL
        m.dnsSettings = s
        m.localizedDescription = "Pax"
        try await m.saveToPreferences()
    }

    /// nil when iPhone couldn't say (Pax then changes nothing and sends nothing).
    static func isEnabled() async -> Bool? {
        let m = NEDNSSettingsManager.shared()
        do { try await m.loadFromPreferences() } catch { return nil }
        guard m.dnsSettings != nil else { return false }
        return m.isEnabled
    }

    /// Only after the server released the secret (turning Pax off).
    static func remove() async {
        let m = NEDNSSettingsManager.shared()
        do {
            try await m.loadFromPreferences()
            try await m.removeFromPreferences()
        } catch {}
    }
}
