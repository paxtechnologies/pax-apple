// SPDX-License-Identifier: GPL-3.0-only
// App Store screenshots only. Debug builds on the simulator read two launch arguments:
//   -PaxShotStep <n>   open set-up at that step (SetupStep raw value: 1 child, 3 email, 7 done)
//   -PaxShotHome YES   show Home with sample settings, in memory only (nothing saved,
//                      no network, no Screen Time or DNS calls)
//   -PaxShotScroll <id> with -PaxShotHome: scroll Home to "sites" or "end"
//   -PaxShotSites YES  with -PaxShotHome: one of the sample sites has a removal waiting
//   -PaxShotDNS YES    with -PaxShotHome: the encrypted DNS steps sheet is open
//   -PaxShotMac YES    Home for a device already set up from a Mac (sample, in memory only)
//   -PaxShotChildUpdate YES  with -PaxShotStep 1: the "needs a Pax update" message
//   -PaxShotMacWelcome YES   with -PaxShotStep 5: "Welcome back" for a device set up from a Mac
//   (24 Oct 2026, simplified Home)
//   -PaxShotChild YES        Home for a child's device (sample, in memory only)
//   -PaxShotSettings YES     with a Home: Settings is open
//   -PaxShotYouTube on|pending  as if the server could do the YouTube wait: the switch, or a
//                            turn-off waiting ("Turning off, available in …" + Cancel)
//   -PaxShotApps YES         with a Home: Blocked apps is open; -PaxShotAppSearch <text> fills the search
//   -PaxShotAppsRemoving YES with -PaxShotApps: as if the server kept the list, one removal waiting
// None of this is compiled into Release, so the App Store build has no hidden mode.
#if DEBUG
import Foundation

enum ScreenshotMode {
    private static var args: UserDefaults { .standard }

    static var step: SetupStep? {
        guard args.object(forKey: "PaxShotStep") != nil else { return nil }
        return SetupStep(rawValue: args.integer(forKey: "PaxShotStep"))
    }

    static var home: Bool { args.bool(forKey: "PaxShotHome") }
    static var macHome: Bool { args.bool(forKey: "PaxShotMac") }
    static var childHome: Bool { args.bool(forKey: "PaxShotChild") }
    static var any: Bool { home || macHome || childHome }
    static var settings: Bool { args.bool(forKey: "PaxShotSettings") }
    static var youtubeShot: String? { args.string(forKey: "PaxShotYouTube") }
    static var apps: Bool { args.bool(forKey: "PaxShotApps") }
    static var appSearch: String { args.string(forKey: "PaxShotAppSearch") ?? "" }
    static var appsRemoving: Bool { args.bool(forKey: "PaxShotAppsRemoving") }

    /// Today's servers (0.8.31 / 0.8.32): on, no switch. With -PaxShotYouTube: as a server with the wait.
    static func sampleYouTube(_ p: PaxPolicy) -> YouTubeRow {
        if p.audience == .child { return YouTubeRow(value: .alwaysOn, canSwitch: false, turningOff: nil) }
        switch youtubeShot {
        case "on": return YouTubeRow(value: .on, canSwitch: true, turningOff: nil)
        case "pending":
            return YouTubeRow(value: .on, canSwitch: true,
                              turningOff: YouTubeTurnOff(requestID: "sample",
                                                         effectiveAt: Int(Date().timeIntervalSince1970) + 30 * 86_400 - 3_600))
        default: return .fallback
        }
    }

    /// A child's device, set up by a parent; Screen Time not locked yet (so the nudge shows).
    static var sampleChildPolicy: PaxPolicy {
        var p = PaxPolicy()
        p.isActive = true
        p.setUpFinished = true
        p.audience = .child
        p.accountEmail = "parent@example.com"
        p.setUpAt = Date().addingTimeInterval(-2 * 86_400)
        p.waitDays = 30
        p.blockedDomains = ["reddit.com"]
        p.trustedEmail = "parent@example.com"
        p.dnsInstalled = true
        p.dnsSeenOn = true
        return p
    }
    static var scroll: String? { args.string(forKey: "PaxShotScroll") }
    static var sites: Bool { args.bool(forKey: "PaxShotSites") }
    static var dnsGuide: Bool { args.bool(forKey: "PaxShotDNS") }
    static var childUpdate: Bool { args.bool(forKey: "PaxShotChildUpdate") }
    /// With -PaxShotStep 5: "Welcome back" on a device already set up from a Mac.
    static var macWelcome: Bool { args.bool(forKey: "PaxShotMacWelcome") }
    static var sampleMacExisting: ExistingAccount {
        ExistingAccount(waitSeconds: 30 * 86_400, pendingWaitSeconds: nil, trustedEmail: "friend@example.com",
                        devices: [(name: "Sam's iPhone", platform: "ios", released: false),
                                  (name: "Sam's MacBook Air", platform: "mac", released: false)],
                        child: false, profiles: ["org.paxpeace.pax.ios.sample", "org.paxpeace.pax.macos.sample"],
                        joiningMac: true)
    }

    /// A device set up from a Mac that this app joined.
    static var sampleMacPolicy: PaxPolicy {
        var p = PaxPolicy()
        p.macSetUp = true
        p.setUpFinished = true
        p.accountEmail = "you@example.com"
        p.setUpAt = Date().addingTimeInterval(-20 * 86_400)
        p.waitDays = 30
        p.blockedDomains = ["reddit.com"]
        p.trustedEmail = "friend@example.com"
        return p
    }

    static var samplePolicy: PaxPolicy {
        var p = PaxPolicy()
        p.isActive = true
        p.setUpFinished = true
        p.audience = .me
        p.accountEmail = "you@example.com"
        p.setUpAt = Date().addingTimeInterval(-3 * 86_400)
        p.waitDays = 30
        p.blockedDomains = ["reddit.com", "youtube.com"]
        p.trustedEmail = "friend@example.com"
        p.passcodeEscrowed = true
        p.dnsInstalled = true
        p.dnsSeenOn = true
        p.blockedApps = [BlockedApp(bundleID: "com.zhiliaoapp.musically", name: "TikTok"),
                         BlockedApp(bundleID: "com.reddit.Reddit", name: "Reddit")]
        if appsRemoving {
            p.pendingAppRemovals = [PendingAppRemoval(bundleID: "com.zhiliaoapp.musically", requestID: "sample",
                                                      effectiveAt: Int(Date().timeIntervalSince1970) + 30 * 86_400 - 3_600)]
        }
        if sites {
            p.pendingSiteRemovals = [PendingSiteRemoval(domain: "youtube.com", requestID: "sample",
                                                        effectiveAt: Int(Date().timeIntervalSince1970) + 30 * 86_400 - 3_600)]
        }
        return p
    }
}
#endif
