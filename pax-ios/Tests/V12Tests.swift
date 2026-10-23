// SPDX-License-Identifier: GPL-3.0-only
// 1.2 (23 Oct 2026): removing your own blocked sites through the server's turn-off wait, the
// child path on its own routes (server 0.8.32), a device already set up from a Mac, the DNS
// steps. Fail closed throughout.
import XCTest

final class SiteRemovalTests: XCTestCase {
    private func view(now: Int, _ blocked: [BlockedSiteInfo]) -> BlocklistViewInfo { BlocklistViewInfo(now: now, blocked: blocked) }
    private func waiting(_ d: String, until: Int, id: String = "r1") -> BlockedSiteInfo {
        BlockedSiteInfo(domain: d, pending_removal: BlocklistRequestInfo(request_id: id, action: "unblock", domain: d,
                                                                         status: "pending", effective_at: until,
                                                                         seconds_remaining: nil))
    }

    func testOnlyYourOwnSitesAndOneRequestAtATime() {
        var p = PaxPolicy()
        p.blockedDomains = ["reddit.com"]
        XCTAssertTrue(SiteRemoval.canRemove("reddit.com", policy: p))
        XCTAssertFalse(SiteRemoval.canRemove("example.com", policy: p))      // not added here: Pax's own lists never are
        p.pendingSiteRemovals = [PendingSiteRemoval(domain: "reddit.com", requestID: "r1", effectiveAt: 100)]
        XCTAssertFalse(SiteRemoval.canRemove("reddit.com", policy: p))
    }

    func testStillWaitingStaysBlocked() {
        let local = [PendingSiteRemoval(domain: "reddit.com", requestID: "r1", effectiveAt: 1_000)]
        let r = SiteRemoval.reconcile(local: local, blockedDomains: ["reddit.com"],
                                      server: view(now: 500, [waiting("reddit.com", until: 1_000)]))
        XCTAssertEqual(r.removeNow, [])
        XCTAssertEqual(r.pending, local)
    }

    func testComesOffOnlyAfterTheServersWait() {
        let local = [PendingSiteRemoval(domain: "reddit.com", requestID: "r1", effectiveAt: 1_000)]
        // The server no longer lists it and its clock is past the wait: off.
        let done = SiteRemoval.reconcile(local: local, blockedDomains: ["reddit.com", "x.com"], server: view(now: 1_001, []))
        XCTAssertEqual(done.removeNow, ["reddit.com"])
        XCTAssertEqual(done.pending, [])
        var p = PaxPolicy()
        p.blockedDomains = ["reddit.com", "x.com"]
        p.pendingSiteRemovals = local
        XCTAssertTrue(SiteRemoval.apply(done, to: &p))
        XCTAssertEqual(p.blockedDomains, ["x.com"])
        XCTAssertTrue(p.pendingSiteRemovals.isEmpty)
        // Gone from the server before its wait ended (by the SERVER's clock): stays blocked.
        let early = SiteRemoval.reconcile(local: local, blockedDomains: ["reddit.com"], server: view(now: 999, []))
        XCTAssertEqual(early.removeNow, [])
        XCTAssertEqual(early.pending, local)
    }

    func testNeverRemovedWithoutARequestFromThisDevice() {
        // A site on this device that the server doesn't list (adding it there failed) stays blocked.
        let r = SiteRemoval.reconcile(local: [], blockedDomains: ["reddit.com"], server: view(now: 9_999_999, []))
        XCTAssertEqual(r.removeNow, [])
    }

    func testCancelledElsewhereKeepsTheSite() {
        let local = [PendingSiteRemoval(domain: "reddit.com", requestID: "r1", effectiveAt: 1_000)]
        let r = SiteRemoval.reconcile(local: local, blockedDomains: ["reddit.com"],
                                      server: view(now: 2_000, [BlockedSiteInfo(domain: "reddit.com", pending_removal: nil)]))
        XCTAssertEqual(r.removeNow, [])
        XCTAssertEqual(r.pending, [])
    }

    func testARemovalStartedOnTheMacShowsHere() {
        let r = SiteRemoval.reconcile(local: [], blockedDomains: ["reddit.com"],
                                      server: view(now: 10, [waiting("reddit.com", until: 5_000, id: "mac")]))
        XCTAssertEqual(r.pending, [PendingSiteRemoval(domain: "reddit.com", requestID: "mac", effectiveAt: 5_000)])
    }

    func testDecodesTheServersAnswer() throws {
        // Captured from server/pax_server (POST /v1/blocklist/remove), as in the Mac app's tests.
        let json = #"{"request": {"request_id": "5577e6099d004a84833e28226c047f1c", "action": "unblock", "domain": "bad.example", "display_domain": "bad.example", "status": "pending", "created_at": 1800259200, "effective_at": 1800518400, "seconds_remaining": 259200}, "list": {"now": 1800259200, "blocked": [{"domain": "bad.example", "display_domain": "bad.example", "added_at": 1800000000, "pending_removal": {"request_id": "5577e6099d004a84833e28226c047f1c", "action": "unblock", "domain": "bad.example", "display_domain": "bad.example", "status": "pending", "created_at": 1800259200, "effective_at": 1800518400, "seconds_remaining": 259200}}], "allowed": [], "pending": [], "limits": {"max_blocked": 2000, "max_allowed": 500, "delay_seconds": 259200}}}"#
        let r = try JSONDecoder().decode(BlocklistRequestResult.self, from: Data(json.utf8))
        let p = try XCTUnwrap(SiteRemoval.record(from: r, domain: "bad.example"))
        XCTAssertEqual(p, PendingSiteRemoval(domain: "bad.example", requestID: "5577e6099d004a84833e28226c047f1c",
                                             effectiveAt: 1_800_518_400))
        XCTAssertEqual(SiteRemoval.remaining(p, serverOffset: 0, now: Date(timeIntervalSince1970: 1_800_259_200)), 259_200)
    }

    func testPendingRemovalsSurviveSavingAndOldDataReadsAsNone() throws {
        var p = PaxPolicy()
        p.isActive = true
        p.blockedDomains = ["reddit.com"]
        p.pendingSiteRemovals = [PendingSiteRemoval(domain: "reddit.com", requestID: "r1", effectiveAt: 42)]
        let back = PaxPolicy.decode(try JSONEncoder().encode(p))
        XCTAssertEqual(back, p)
        let old = PaxPolicy.decode(Data(#"{"isActive": true, "blockedDomains": ["a.com"]}"#.utf8))
        XCTAssertTrue(old.pendingSiteRemovals.isEmpty)
        XCTAssertFalse(old.macSetUp)
        XCTAssertEqual(old.blockedDomains, ["a.com"])
    }

    func testRemovalWordsSayTurnOffWait() {
        XCTAssertEqual(PaxCopy.sitesRemoving("3 days"), "Removing, available in 3 days")
        XCTAssertTrue(PaxCopy.sitesRemoveBody(waitDays: 7, trusted: true).contains("turn-off wait"))
        XCTAssertTrue(PaxCopy.sitesRemoveBody(waitDays: 7, trusted: true).contains("emailed first"))
        XCTAssertFalse(PaxCopy.sitesRemoveBody(waitDays: 7, trusted: false).contains("emailed"))
        XCTAssertTrue(PaxCopy.sitesFooter.contains("turn-off wait"))
    }
}

final class ChildSetupTests: XCTestCase {
    func testAnOldServerNeedsAnUpdateNeverTheParentsAccount() {
        XCTAssertEqual(ChildSetup.problem(status: 404, code: nil, starting: true), .needsUpdate)
        XCTAssertEqual(ChildSetup.problem(status: 404, code: nil, starting: false), .needsUpdate)
        XCTAssertEqual(ChildSetup.problem(status: 405, code: nil, starting: false), .needsUpdate)
        XCTAssertEqual(ChildSetup.message(.needsUpdate, isPad: false), PaxCopy.childNeedsUpdate)
        XCTAssertTrue(PaxCopy.childNeedsUpdate.contains("needs a Pax update"))
        XCTAssertTrue(PaxCopy.childNeedsUpdate.contains("nothing has been set up"))
    }

    func testCalmAnswers() {
        XCTAssertEqual(ChildSetup.problem(status: 429, code: "child_limit", starting: false), .childLimit)
        XCTAssertEqual(ChildSetup.problem(status: 429, code: "rate_limited", starting: true), .tooManyCodes)
        XCTAssertEqual(ChildSetup.problem(status: 403, code: "child_wait_fixed", starting: false), .waitFixed)
        XCTAssertEqual(ChildSetup.problem(status: 401, code: "unauthorized", starting: false), .wrongCode)
        XCTAssertEqual(ChildSetup.problem(status: 422, code: nil, starting: true), .invalidEmail)
        XCTAssertNil(ChildSetup.problem(status: 503, code: nil, starting: false))
        XCTAssertTrue(PaxCopy.childLimit.contains("Nothing new has been set up"))
        XCTAssertTrue(PaxCopy.childWaitFixed.contains("30 days"))
    }

    func testOnlyAChildTokenIsKept() {
        XCTAssertTrue(ChildSetup.keep(kind: "child"))
        XCTAssertFalse(ChildSetup.keep(kind: "adult"))
        XCTAssertFalse(ChildSetup.keep(kind: nil))           // a 0.8.31 answer has no kind
    }

    func testChildPathHasNoWelcomeBack() {
        XCTAssertEqual(SetupRules.path(child: true, existing: false), [.welcome, .childEmail, .childCode, .turningOn, .done])
        XCTAssertEqual(ChildSetup.deviceName(isPad: true), "iPad")
    }

    func testChildWaitsNeverOfferedBelowThirtyDays() {
        XCTAssertEqual(SetupRules.waitChoices(child: true), [30, 90, 180, 365])
        XCTAssertEqual(SetupRules.waitChoices(child: false), Pax.waitChoices)
    }
}

final class StrictSyncTests: XCTestCase {
    private let mac = StrictSync.AccountDevice(id: "d1", profileIdentifier: "org.paxpeace.pax.ios.1234-abcd", released: false)
    private let app = StrictSync.AccountDevice(id: "d2", profileIdentifier: "org.paxpeace.pax.appstore.5678", released: false)

    func testTellsMacSetUpsFromThisApp() {
        XCTAssertTrue(StrictSync.isMacSetUp(profileIdentifier: mac.profileIdentifier))
        XCTAssertFalse(StrictSync.isMacSetUp(profileIdentifier: app.profileIdentifier))
        XCTAssertFalse(StrictSync.isMacSetUp(profileIdentifier: "org.paxpeace.pax.macos.1234"))
        XCTAssertFalse(StrictSync.isMacSetUp(profileIdentifier: nil))
        var gone = mac; gone.released = true
        XCTAssertEqual(StrictSync.macDevices([mac, app, gone]), [mac])
    }

    func testFilteredHereOnlyWithoutOurOwnDNS() {
        XCTAssertEqual(StrictSync.filteredHere(probe: .protected, ownDNSConfigured: false), true)
        XCTAssertNil(StrictSync.filteredHere(probe: .protected, ownDNSConfigured: true))
        XCTAssertEqual(StrictSync.filteredHere(probe: .notProtected, ownDNSConfigured: false), false)
        XCTAssertNil(StrictSync.filteredHere(probe: .couldNotCheck(.offline), ownDNSConfigured: false))
    }

    func testJoinsTheMacSetUpOnTheSameAccount() {
        XCTAssertEqual(StrictSync.decide(filteredHere: true, accountDevices: [mac, app]), .joinMacSetUp(deviceID: "d1"))
        let mac2 = StrictSync.AccountDevice(id: "d3", profileIdentifier: "org.paxpeace.pax.ios.9", released: false)
        XCTAssertEqual(StrictSync.decide(filteredHere: true, accountDevices: [mac, mac2]), .joinMacSetUp(deviceID: nil))
    }

    func testAnotherAccountsMacSetUpIsNeverSetUpOver() {
        XCTAssertEqual(StrictSync.decide(filteredHere: true, accountDevices: []), .otherAccount)
        XCTAssertEqual(StrictSync.decide(filteredHere: true, accountDevices: [app]), .otherAccount)
    }

    func testInDoubtNothingIsAdded() {
        XCTAssertEqual(StrictSync.decide(filteredHere: nil, accountDevices: [mac]), .checkAgain)
        XCTAssertEqual(StrictSync.decide(filteredHere: nil, accountDevices: [app]), .normal)
        XCTAssertEqual(StrictSync.decide(filteredHere: false, accountDevices: [mac]), .normal)   // the Mac set-up is another device
    }

    func testChildPathRefusedOnAMacSetUp() {
        XCTAssertTrue(StrictSync.childRefused(filteredHere: true))
        XCTAssertFalse(StrictSync.childRefused(filteredHere: nil))
        XCTAssertFalse(StrictSync.childRefused(filteredHere: false))
    }

    func testJoiningNeverChangesTheWait() {
        let a = ExistingAccount(waitSeconds: 3 * 86_400, pendingWaitSeconds: nil, trustedEmail: "friend@example.com",
                                devices: [(name: "Sam's iPhone", platform: "ios", released: false)], child: false,
                                profiles: ["org.paxpeace.pax.ios.abc"], joiningMac: true)
        XCTAssertNil(a.lengthenTo)                           // nothing sent, not even a longer wait
        XCTAssertTrue(a.devices[0].fromMac)
        let lines = PaxCopy.welcomeBackLines(a).joined(separator: " ")
        XCTAssertTrue(lines.contains("Sam's iPhone (iPhone, set up from a Mac)"))
        XCTAssertTrue(lines.contains("friend@example.com"))
        XCTAssertFalse(lines.contains("lengthens"))
        XCTAssertEqual(SetupRules.after(TurnOnOutcome.macSetUp, child: false), .done)
    }

    func testHomeOnlyAddsOnAMacSetUp() {
        XCTAssertEqual(StrongerList.cards(macSetUp: true), [.trustedPerson, .turnOffWait])
        XCTAssertEqual(StrongerList.cards(macSetUp: false), StrongerList.order)
        XCTAssertFalse(StrongerList.cards(macSetUp: true).contains(.lockScreenTime))
        XCTAssertFalse(StrongerList.cards(macSetUp: true).contains(.encryptedDNS))
    }
}

final class DNSGuideTests: XCTestCase {
    func testStepsNameTheExactPath() {
        let old = PaxCopy.dnsGuideSteps(isPad: false, osMajor: 17).joined(separator: " ")
        let new = PaxCopy.dnsGuideSteps(isPad: false, osMajor: 18).joined(separator: " ")
        for s in [old, new] {
            XCTAssertTrue(s.contains("General"))
            XCTAssertTrue(s.contains("VPN & Device Management"))
            XCTAssertTrue(s.contains("VPN, DNS & Device Management"))
            XCTAssertTrue(s.contains("DNS, then choose Pax"))
        }
        XCTAssertTrue(new.contains("‹ Apps"))                  // iOS 18+: an app's page is under Apps
        XCTAssertFalse(old.contains("‹ Apps"))
        XCTAssertTrue(PaxCopy.dnsGuideSteps(isPad: true, osMajor: 26).joined().contains("iPads"))
    }
}
