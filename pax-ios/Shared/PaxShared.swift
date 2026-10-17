// SPDX-License-Identifier: GPL-3.0-only
// Constants shared by the app and its extensions.
import Foundation

enum Pax {
    static let appGroup = "group.org.paxpeace.pax"
    static let storeName = "pax"
    static let apiBase = URL(string: "https://api.paxpeace.com")!
    /// The turn-off wait the person picks at set-up (days). Same range as Pax Strict.
    static let minWaitDays = 3
    static let maxWaitDays = 365
    static let defaultWaitDays = 7
    /// First hour after set-up: turning off needs no wait (the server enforces the same grace).
    static let graceSeconds: TimeInterval = 3600
    /// Reported limit for the system web filter's extra domains (to test on hardware).
    static let maxCustomDomains = 50
    /// Apps that would get round the filter (other engines, built-in VPNs, remote browsers).
    /// Blocked by bundle ID if iOS allows it under individual authorization (hardware test T6).
    static let bypassAppBundleIDs: [String] = [
        "com.opera.OperaTouch",
        "com.opera.mini",
        "com.brave.ios.browser",
        "com.duckduckgo.mobile.ios",
        "org.torproject.ios.onionbrowser",
        "com.openai.chat",
        "tech.butterfly.app",
    ]
    static let dailyActivity = "org.paxpeace.pax.daily"

    static var shared: UserDefaults { UserDefaults(suiteName: appGroup) ?? .standard }
}
