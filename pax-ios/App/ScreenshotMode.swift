// SPDX-License-Identifier: GPL-3.0-only
// App Store screenshots only. Debug builds on the simulator read two launch arguments:
//   -PaxShotStep <n>   open set-up at that step (SetupStep raw value: 1 child, 7 done)
//   -PaxShotHome YES   show Home with sample settings, in memory only (nothing saved,
//                      no network, no Screen Time or DNS calls)
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
        return p
    }
}
#endif
