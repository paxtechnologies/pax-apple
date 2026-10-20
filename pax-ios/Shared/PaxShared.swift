// SPDX-License-Identifier: GPL-3.0-only
// Constants shared by the app and its extensions.
import Foundation

enum Pax {
    static let appGroup = "group.org.paxpeace.pax"
    static let storeName = "pax"
    static let apiBase = URL(string: "https://api.paxpeace.com")!
    /// Pax's own filtering resolver. The per-account DoH address comes from GET /v1/dns.
    static let dnsHost = "dns.paxpeace.com"
    static let privacyURL = URL(string: "https://paxpeace.com/privacy")!
    static let siteURL = URL(string: "https://paxpeace.com")!
    static let supportEmail = "hello@paxpeace.com"

    /// The turn-off wait the person picks at set-up (days): 3 days to 1 year.
    static let minWaitDays = 3
    static let maxWaitDays = 365
    static let defaultWaitDays = 7
    /// A longer suggestion when a parent sets Pax up on a child's device.
    static let childDefaultWaitDays = 30
    /// The choices the set-up offers.
    static let waitChoices = [3, 7, 14, 30, 90, 180, 365]
    /// First hour after set-up: turning off needs no wait (the server enforces the same grace).
    static let graceSeconds: TimeInterval = 3600
    /// Reported limit for the system web filter's extra domains (to test on hardware, T7).
    static let maxCustomDomains = 50
    /// Browsers that can get round the system web filter. Closed by bundle ID if iOS allows
    /// it under individual authorization (hardware test T6). Anything else the person
    /// chooses with the picker.
    static let bypassAppBundleIDs: [String] = [
        "com.opera.OperaTouch",
        "com.opera.mini",
        "com.brave.ios.browser",
        "com.duckduckgo.mobile.ios",
        "org.torproject.ios.onionbrowser",
    ]
    /// Device Activity schedules that wake the monitor extension to re-assert the settings
    /// (self-heal). Four windows a day, so it runs at least every six hours.
    static let monitorWindows: [(name: String, start: Int, end: Int)] = [
        ("org.paxpeace.pax.w0", 0, 5),
        ("org.paxpeace.pax.w1", 6, 11),
        ("org.paxpeace.pax.w2", 12, 17),
        ("org.paxpeace.pax.w3", 18, 23),
    ]

    static var shared: UserDefaults { UserDefaults(suiteName: appGroup) ?? .standard }
}
