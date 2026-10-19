// SPDX-License-Identifier: GPL-3.0-only
import XCTest

final class ProtectionCheckTests: XCTestCase {
    typealias L = ProtectionCheck.Lookup
    let pax: L = .addresses(["0.0.0.0", "::"])
    let open: L = .addresses(["104.18.36.146", "2606:4700::6812:2492"])
    let apple: L = .addresses(["2.18.101.47"])

    private func probes(_ l: L) -> [L] { Array(repeating: l, count: ProtectionCheck.probeNames.count) }

    // MARK: blocked-address recognition

    func testBlockedAddresses() {
        for a in ["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "::%en0", "64:ff9b::", "64:ff9b::0.0.0.0", "::ffff:0.0.0.0"] {
            XCTAssertTrue(ProtectionCheck.isBlockedAddress(a), a)
        }
    }

    func testRealAddressesAreNotBlocked() {
        for a in ["1.1.1.1", "127.0.0.1", "0.0.0.1", "10.0.0.0", "2606:4700::1111", "::1", "64:ff9b::101:101",
                  "146.112.61.106", "", "not an address"] {
            XCTAssertFalse(ProtectionCheck.isBlockedAddress(a), a)
        }
    }

    // MARK: classification

    func testAllProbesBlockedIsProtected() {
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: probes(pax)), .protected)
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: probes(.addresses(["0.0.0.0"]))), .protected)
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: probes(.addresses(["::"]))), .protected)
    }

    func testProtectedEvenIfControlFailed() {
        // Every probe proved the filter is answering.
        XCTAssertEqual(ProtectionCheck.classify(control: .failed, probes: probes(pax)), .protected)
    }

    func testPublicAnswersAreNotProtected() {
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: probes(open)), .notProtected)
    }

    func testOfflineIsCouldNotCheck() {
        XCTAssertEqual(ProtectionCheck.classify(control: .failed, probes: probes(.failed)), .couldNotCheck(.offline))
        XCTAssertEqual(ProtectionCheck.classify(control: .addresses([]), probes: probes(.failed)), .couldNotCheck(.offline))
        XCTAssertEqual(ProtectionCheck.classify(control: .failed, probes: probes(open)), .couldNotCheck(.offline))
    }

    func testMixedAnswersNeverClaimProtection() {
        var mixed = probes(pax); mixed[0] = open
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: mixed), .couldNotCheck(.unclear))
        var oneFailed = probes(pax); oneFailed[2] = .failed
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: oneFailed), .couldNotCheck(.unclear))
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: probes(.addresses(["0.0.0.0", "1.2.3.4"]))),
                       .couldNotCheck(.unclear))
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: probes(.addresses([]))), .couldNotCheck(.unclear))
        XCTAssertEqual(ProtectionCheck.classify(control: apple, probes: []), .couldNotCheck(.unclear))
    }

    func testControlBlockedIsNotCalledUnprotected() {
        // Probes open but the everyday name blocked: odd network, don't guess.
        XCTAssertEqual(ProtectionCheck.classify(control: pax, probes: probes(open)), .couldNotCheck(.unclear))
    }

    func testRunUsesAllProbeNamesAndControl() async {
        let seen = Seen()
        let outcome = await ProtectionCheck.run { name in
            await seen.add(name)
            return name == ProtectionCheck.controlName ? .addresses(["2.18.101.47"]) : .addresses(["0.0.0.0"])
        }
        XCTAssertEqual(outcome, .protected)
        let names = await seen.names
        XCTAssertEqual(names, Set(ProtectionCheck.probeNames + [ProtectionCheck.controlName]))
    }

    func testProbeNamesAreXAndBlueskyMedia() {
        // Pax's filter always blocks these (guard_config.ALWAYS_BLOCKED_MEDIA_NAMES).
        let always: Set = ["pbs.twimg.com", "video.twimg.com", "ton.twimg.com",
                           "cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app", "gifs.bsky.app"]
        XCTAssertTrue(Set(ProtectionCheck.probeNames).isSubset(of: always))
        XCTAssertGreaterThanOrEqual(ProtectionCheck.probeNames.count, 4)
    }

    // MARK: copy

    func testResultWords() {
        XCTAssertEqual(GuideCopy.resultTitle(.protected), "Protected by Pax")
        XCTAssertEqual(GuideCopy.resultTitle(.notProtected), "Not protected")
        XCTAssertEqual(GuideCopy.resultTitle(.couldNotCheck(.offline)), "Couldn't check (offline)")
        XCTAssertEqual(GuideCopy.resultTitle(.couldNotCheck(.unclear)), "Couldn't check")
    }

    func testStepsEndWithTheCheckAndAreNumbered() {
        for isPad in [false, true] {
            let steps = GuideCopy.steps(isPad: isPad)
            XCTAssertEqual(steps.map(\.id), Array(1...steps.count))
            XCTAssertEqual(steps.last?.title, "Check you're protected.")
            XCTAssertTrue(steps.contains { $0.title.contains("Find My back on") })
            XCTAssertTrue(steps.contains { $0.title.contains("Protect my \(isPad ? "iPad" : "iPhone")") })
        }
    }

    func testCopyRules() {
        for isPad in [false, true] {
            var words = [GuideCopy.tagline(isPad: isPad), GuideCopy.title(isPad: isPad), GuideCopy.subtitle,
                         GuideCopy.comingBody, GuideCopy.checkPrivacy]
            words += GuideCopy.needs(isPad: isPad) + GuideCopy.goodToKnow(isPad: isPad)
            words += GuideCopy.steps(isPad: isPad).flatMap { [$0.title, $0.detail ?? ""] }
            words += [ProtectionCheck.Outcome.protected, .notProtected, .couldNotCheck(.offline), .couldNotCheck(.unclear)]
                .map { GuideCopy.resultDetail($0, isPad: isPad) }
            for w in words {
                XCTAssertFalse(w.lowercased().contains("restricted"), w)
                XCTAssertFalse(w.lowercased().contains("porn"), w)
            }
            XCTAssertTrue(GuideCopy.tagline(isPad: isPad).contains("adult and explicit content"))
            XCTAssertTrue(GuideCopy.needs(isPad: isPad).contains { $0.contains("macOS 12 Monterey") })
            XCTAssertTrue(GuideCopy.goodToKnow(isPad: isPad).contains { $0.contains("someone you trust") })
            XCTAssertTrue(GuideCopy.goodToKnow(isPad: isPad).contains { $0.contains("erases the \(isPad ? "iPad" : "iPhone") and removes Pax") })
        }
        XCTAssertEqual(PaxLinks.privacy.absoluteString, "https://paxpeace.com/privacy")
    }

    func testMacDownloadLink() {
        XCTAssertEqual(PaxLinks.macDownload.absoluteString,
                       "https://github.com/paxtechnologies/pax-apple/releases/latest/download/Pax.dmg")
    }
}

private actor Seen {
    var names: Set<String> = []
    func add(_ n: String) { names.insert(n) }
}
