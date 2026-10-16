// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.3: per-user DoH URL, profile generator arguments, blocked-sites models and helpers.
final class BlocklistTests: XCTestCase {
    let token = "Abc_def-GHIjklMNOpqrSTUvwx"   // same token as profile/tests/test_user_token.py

    // MARK: PaxDNS (mirrors make_profile.user_doh_url)

    func testUserDoHURLDefaultBase() throws {
        XCTAssertEqual(try PaxDNS.userDoHURL(token: token, environment: [:]),
                       "https://dns.paxpeace.com/u/\(token)/dns-query")
    }

    func testUserDoHURLCustomBaseAndEnv() throws {
        XCTAssertEqual(try PaxDNS.userDoHURL(token: token, base: "https://dns.example.test/", environment: [:]),
                       "https://dns.example.test/u/\(token)/dns-query")
        XCTAssertEqual(try PaxDNS.userDoHURL(token: token, environment: ["PAX_DNS_BASE": "https://staging.example.test"]),
                       "https://staging.example.test/u/\(token)/dns-query")
    }

    func testUserDoHURLRejectsBadInput() {
        for bad in ["", "short", "has space in it 1234567890", String(repeating: "x", count: 129), "../../../../../../../../.."] {
            XCTAssertThrowsError(try PaxDNS.userDoHURL(token: bad, environment: [:]), bad)
        }
        for base in ["http://dns.example", "dns.example", "https://a.b/?x=1"] {
            XCTAssertThrowsError(try PaxDNS.userDoHURL(token: token, base: base, environment: [:]), base)
        }
    }

    func testMaskHidesToken() {
        let masked = PaxDNS.mask("https://dns.paxpeace.com/u/\(token)/dns-query")
        XCTAssertEqual(masked, "https://dns.paxpeace.com/u/Abc_…/dns-query")
        XCTAssertFalse(masked.contains(token))
    }

    // MARK: Profile generator arguments

    func testProfileArgumentsWithUserToken() {
        let args = ProfileGenerator.arguments(
            script: URL(fileURLWithPath: "/x/make_profile.py"), platform: "ios",
            out: URL(fileURLWithPath: "/t/p"), escrow: URL(fileURLWithPath: "/t/e"),
            filter: .family, resolverURL: "https://ignored.example/dns-query",
            blockApps: [], blockURLs: [], userToken: token, dnsBase: "https://dns.example.test")
        XCTAssertTrue(args.contains("--user-token"))
        XCTAssertEqual(args[args.firstIndex(of: "--user-token")! + 1], token)
        XCTAssertEqual(args[args.firstIndex(of: "--dns-base")! + 1], "https://dns.example.test")
        XCTAssertFalse(args.contains("--resolver-url"))
        XCTAssertFalse(args.contains("--filter"))
    }

    func testProfileArgumentsWithoutTokenKeepV02Behaviour() {
        let args = ProfileGenerator.arguments(
            script: URL(fileURLWithPath: "/x/make_profile.py"), platform: "macos",
            out: URL(fileURLWithPath: "/t/p"), escrow: URL(fileURLWithPath: "/t/e"),
            filter: .core, resolverURL: nil, blockApps: [], blockURLs: [])
        XCTAssertEqual(Array(args.suffix(2)), ["--filter", "core"])
        XCTAssertFalse(args.contains("--user-token"))
        XCTAssertFalse(args.contains("--dns-base"))
    }

    // MARK: Domain input

    func testDomainInputNormalise() {
        XCTAssertEqual(DomainInput.normalise("  https://Bad.Example/path?q=1 "), "bad.example")
        XCTAssertEqual(DomainInput.normalise("user@site.example:8443"), "site.example")
        XCTAssertEqual(DomainInput.normalise("*.site.example."), "site.example")
        XCTAssertEqual(DomainInput.normalise("bücher.de"), "bücher.de")   // server does IDNA
        XCTAssertNil(DomainInput.normalise(""))
        XCTAssertNil(DomainInput.normalise("localhost"))
        XCTAssertNil(DomainInput.normalise("192.168.0.1"))
        XCTAssertNil(DomainInput.normalise("2001:db8::1"))
        XCTAssertNil(DomainInput.normalise("a.*.example"))
        XCTAssertNil(DomainInput.normalise("two words.com"))
    }

    // MARK: Countdown

    func testCountdownFormatting() {
        XCTAssertEqual(Countdown.string(seconds: 72 * 3600), "72h 00m 00s")
        XCTAssertEqual(Countdown.string(seconds: 72 * 3600 - 1), "71h 59m 59s")
        XCTAssertEqual(Countdown.string(seconds: 61), "1m 01s")
        XCTAssertEqual(Countdown.string(seconds: 0), "now")
        XCTAssertEqual(Countdown.string(seconds: -5), "now")
        XCTAssertEqual(Countdown.string(seconds: 7 * 86_400 + 3 * 3600), "7d 3h")
    }

    func testCountdownCorrectsForServerClock() {
        let fetched = Date(timeIntervalSince1970: 5_000)   // local clock, unrelated to server's
        let later = fetched.addingTimeInterval(3600)
        XCTAssertEqual(Countdown.remaining(effectiveAt: 1_800_259_200, serverNow: 1_800_000_000,
                                           fetchedAt: fetched, now: later), 259_200 - 3600)
        XCTAssertEqual(Countdown.remaining(effectiveAt: 10, serverNow: 0, fetchedAt: fetched,
                                           now: fetched.addingTimeInterval(99)), 0)
    }

    // MARK: Server JSON

    func testDecodesServerRequestResult() throws {
        // Captured from server/pax_server (POST /v1/blocklist/remove).
        let json = #"""
        {"request": {"request_id": "5577e6099d004a84833e28226c047f1c", "action": "unblock", "domain": "bad.example", "display_domain": "bad.example", "status": "pending", "created_at": 1800259200, "effective_at": 1800518400, "seconds_remaining": 259200}, "list": {"now": 1800259200, "blocked": [{"domain": "bad.example", "display_domain": "bad.example", "added_at": 1800000000, "pending_removal": {"request_id": "5577e6099d004a84833e28226c047f1c", "action": "unblock", "domain": "bad.example", "display_domain": "bad.example", "status": "pending", "created_at": 1800259200, "effective_at": 1800518400, "seconds_remaining": 259200}}, {"domain": "xn--bcher-kva.de", "display_domain": "b\u00fccher.de", "added_at": 1800000000, "pending_removal": null}], "allowed": [{"domain": "reddit.com", "display_domain": "reddit.com", "added_at": 1800259200}], "pending": [{"request_id": "5577e6099d004a84833e28226c047f1c", "action": "unblock", "domain": "bad.example", "display_domain": "bad.example", "status": "pending", "created_at": 1800259200, "effective_at": 1800518400, "seconds_remaining": 259200}], "limits": {"max_blocked": 2000, "max_allowed": 500, "delay_seconds": 259200}}}
        """#
        let r = try JSONDecoder().decode(BlocklistRequestResult.self, from: Data(json.utf8))
        XCTAssertEqual(r.request.action, "unblock")
        XCTAssertEqual(r.list.blocked.count, 2)
        XCTAssertEqual(r.list.blocked[0].pending_removal?.seconds_remaining, 259_200)
        XCTAssertNil(r.list.blocked[1].pending_removal)
        XCTAssertEqual(r.list.blocked[1].display_domain, "bücher.de")
        XCTAssertEqual(r.list.allowed.map(\.domain), ["reddit.com"])
        XCTAssertEqual(r.list.limits.delay_seconds, 72 * 3600)
    }

    // MARK: Resources and token store

    func testResourceLocatorOrder() {
        let res = URL(fileURLWithPath: "/App/Pax.app/Contents/Resources")
        let env = ResourceLocator.locate(envKey: "PAX_X", bundled: "x.py", devPath: "../x.py",
                                         environment: ["PAX_X": "/chosen/x.py"], resourceDirectory: res,
                                         fileExists: { _ in true })
        XCTAssertEqual(env.path, "/chosen/x.py")
        let bundled = ResourceLocator.locate(envKey: "PAX_X", bundled: "x.py", devPath: "../x.py",
                                             environment: [:], resourceDirectory: res, fileExists: { _ in true })
        XCTAssertEqual(bundled.path, "/App/Pax.app/Contents/Resources/x.py")
        let dev = ResourceLocator.locate(envKey: "PAX_X", bundled: "x.py", devPath: "/repo/x.py",
                                         environment: [:], resourceDirectory: res, fileExists: { _ in false })
        XCTAssertEqual(dev.path, "/repo/x.py")
    }

    func testInMemoryTokenStore() throws {
        let store = InMemoryTokenStore()
        XCTAssertNil(store.load())
        try store.save("pax_abc")
        XCTAssertEqual(store.load(), "pax_abc")
        store.clear()
        XCTAssertNil(store.load())
    }
}
