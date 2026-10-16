// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import XCTest
@testable import PaxCore

/// v0.7.0 "Import list" parser.
final class BulkSiteImportTests: XCTestCase {
    func testPlainDomainsUrlsAndHostsLines() {
        let text = """
        # my list
        ! adblock comment

        Example.com
        https://www.Reddit.com/r/all?x=1
        0.0.0.0 ads.example.net
        127.0.0.1 a.example.org b.example.org   # two on one line
        ||tracker.example.io^$third-party
        """
        let r = BulkSiteImport.parse(text)
        XCTAssertEqual(r.sites, ["example.com", "www.reddit.com", "ads.example.net", "a.example.org",
                                 "b.example.org", "tracker.example.io"])
        XCTAssertEqual(r.skipped, 0)
        XCTAssertEqual(r.duplicates, 0)
        XCTAssertFalse(r.capReached)
    }

    func testCsvAndDedupeAndAlreadyBlocked() {
        let text = "site,note\nexample.com,old\nEXAMPLE.com;dup\nnews.example.com\talso\nblocked.example\n"
        let r = BulkSiteImport.parse(text, alreadyBlocked: ["blocked.example"])
        XCTAssertEqual(r.sites, ["example.com", "news.example.com"])
        // "site", "note", "old", "dup", "also" aren't websites
        XCTAssertEqual(r.skipped, 5)
        XCTAssertEqual(r.duplicates, 2)
    }

    func testInvalidEntriesAreSkippedAndCounted() {
        let r = BulkSiteImport.parse("not a site\n192.168.1.1\nlocalhost\n0.0.0.0 localhost\nfoo..bar.com\n-bad-.com\nok.co.uk\n")
        XCTAssertEqual(r.sites, ["ok.co.uk"])
        // "not", "a", "site", "foo..bar.com", "-bad-.com"; the bare IP and localhost are ignored
        XCTAssertEqual(r.skipped, 5)
    }

    func testCapIsRespectedAndReported() {
        let text = (1...30).map { "site\($0).example.com" }.joined(separator: "\n")
        let r = BulkSiteImport.parse(text, cap: 10)
        XCTAssertEqual(r.sites.count, 10)
        XCTAssertEqual(r.overCap, 20)
        XCTAssertTrue(r.capReached)
        XCTAssertEqual(BulkSiteImport.parse(text, cap: 99_999).sites.count, 30)
    }

    func testHardCapIsMaxPerImport() {
        let text = (1...(BulkSiteImport.maxPerImport + 5)).map { "s\($0).example.com" }.joined(separator: "\n")
        let r = BulkSiteImport.parse(text, cap: .max)
        XCTAssertEqual(r.sites.count, BulkSiteImport.maxPerImport)
        XCTAssertEqual(r.overCap, 5)
    }

    func testWindowsLineEndingsAndBOM() {
        let r = BulkSiteImport.parse("\u{FEFF}one.example.com\r\ntwo.example.com\r\n")
        XCTAssertEqual(r.sites, ["one.example.com", "two.example.com"])
    }

    func testProfileLimitIsSane() {
        XCTAssertGreaterThan(BulkSiteImport.profileLimit, 50)
        XCTAssertLessThanOrEqual(BulkSiteImport.profileLimit, BulkSiteImport.maxPerImport)
    }
}
