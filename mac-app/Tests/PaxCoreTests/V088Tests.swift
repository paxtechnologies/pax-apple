// SPDX-License-Identifier: GPL-3.0-only
import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import PaxCore

/// v0.8.8: new iPhone/iPad set-ups point DNS at Pax's own filter by default.
final class V088Tests: XCTestCase {
    func testDefaultBaseIsPaxFilter() {
        XCTAssertEqual(PaxDNS.defaultBase, "https://dns.paxpeace.com")
        XCTAssertEqual(PaxDNS.setupBase(environment: [:], directCleanBrowsing: false), "https://dns.paxpeace.com")
    }

    func testDirectCleanBrowsingAndCoreKeepTheOldPath() {
        XCTAssertNil(PaxDNS.setupBase(environment: [:], directCleanBrowsing: true))
        XCTAssertNil(PaxDNS.setupBase(environment: [:], directCleanBrowsing: false, filter: .core))
    }

    func testEnvironmentOverrideWins() {
        XCTAssertEqual(PaxDNS.setupBase(environment: ["PAX_DNS_BASE": "https://dns.example.test"],
                                        directCleanBrowsing: true), "https://dns.example.test")
    }

    func testHealthURL() {
        XCTAssertEqual(PaxDNS.healthURL(base: "https://dns.paxpeace.com/")?.absoluteString,
                       "https://dns.paxpeace.com/health")
    }

    func testFilterSettingsDefaultToProtection() {
        let f = SetupConfiguration().filterSettings
        XCTAssertTrue(f.youtubeRestricted)   // v0.8.13: X / Bluesky media aren't settings any more
    }

    func testUnreachableFilterErrorCode() {
        let e = PaxError("PAX-DNS-012", technical: "https://dns.paxpeace.com")
        XCTAssertEqual(e.code, "PAX-DNS-012")
        XCTAssertTrue(e.info.message.contains("filter"))
    }

    func testProfileArgumentsUseTheTokenOnPaxFilter() {
        let args = ProfileGenerator.arguments(
            script: URL(fileURLWithPath: "/x/make_profile.py"), platform: "ios",
            out: URL(fileURLWithPath: "/t/p"), escrow: URL(fileURLWithPath: "/t/e"),
            filter: .family, resolverURL: nil, blockApps: [], blockURLs: ["https://example.org"],
            userToken: "Abc_def-GHIjklMNOpqrSTUvwx", dnsBase: PaxDNS.defaultBase, youtubeRestricted: true)
        XCTAssertTrue(args.contains("--user-token"))
        XCTAssertEqual(args[args.firstIndex(of: "--dns-base")! + 1], "https://dns.paxpeace.com")
        XCTAssertFalse(args.contains("--no-youtube-restricted"))   // the filter applies YouTube's choice
        XCTAssertTrue(args.contains("https://example.org"))         // the web filter stays a second layer
    }
}
