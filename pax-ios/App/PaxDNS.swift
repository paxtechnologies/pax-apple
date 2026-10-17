// SPDX-License-Identifier: GPL-3.0-only
// Encrypted DNS through Pax's own filter (dns.paxpeace.com/u/<token>/dns-query).
// The person turns it on in Settings › General › VPN & Device Management › DNS, and can
// turn it off there too: iOS doesn't let an App Store app lock it. Pax checks each time
// it opens and tells the partner if it's off (hardware test T10). No query logs on the server.
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

    static func isEnabled() async -> Bool {
        let m = NEDNSSettingsManager.shared()
        do { try await m.loadFromPreferences() } catch { return false }
        return m.isEnabled
    }
}
