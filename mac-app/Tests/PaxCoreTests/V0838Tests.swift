// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.38: phones brought back from the account say "Not confirmed" (not "Protected") until a
/// plugged-in phone is matched to them by its protection profile identifier, or they are
/// unambiguous. Nothing about protection, the turn-off wait or removal changes.
final class V0838Tests: XCTestCase {
    private let realPID = "org.paxpeace.pax.ios.1f2e3d4c-0000-4000-8000-00000000abcd"
    private let leftoverA = "org.paxpeace.pax.ios.99999999-0000-4000-8000-000000000001"
    private let leftoverB = "org.paxpeace.pax.ios.99999999-0000-4000-8000-000000000002"

    private func phone(_ id: String, _ name: String = "RDN", pid: String?, released: Bool = false,
                       at: Int = 100, platform: String = "ios") -> PhoneReconnect.ServerPhone {
        PhoneReconnect.ServerPhone(deviceID: id, name: name, platform: platform, profileIdentifier: pid,
                                   released: released, installedAt: at)
    }

    /// Ruben's account after the 0.8.36 retries: one real RDN and two set-ups that never installed.
    private var rubensAccount: [PhoneReconnect.ServerPhone] {
        [phone("real", pid: realPID, at: 100), phone("left-a", pid: leftoverA, at: 200),
         phone("left-b", pid: leftoverB, at: 300), phone("mac-1", "Ruben's Mac", pid: nil, platform: "mac")]
    }

    // MARK: the screenshot case

    func testThreeRestoredSameNamePhonesAreAllNotConfirmed() {
        for p in PhoneReconnect.phonesToRestore(server: rubensAccount, linkedDeviceIDs: [], hiddenDeviceIDs: []) {
            let unambiguous = PhoneConfirmation.isUnambiguous(deviceID: p.deviceID, account: rubensAccount,
                                                              checkingIn: true)
            XCTAssertFalse(unambiguous, p.deviceID)
            let confirmed = PhoneConfirmation.isConfirmed(restored: true, matchedOnPhone: false, notOnPhone: false,
                                                          unambiguous: unambiguous)
            XCTAssertFalse(confirmed)
            XCTAssertTrue(PhoneConfirmation.showsNotConfirmed(.protected, confirmed: confirmed))
        }
    }

    func testPluggingInTheRealPhoneConfirmsOnlyIt() {
        let inspection = PhoneReconnect.Inspection(supervised: true, paxSupervised: true, paxProfiles: [realPID])
        XCTAssertEqual(PhoneReconnect.match(inspection, phoneName: "RDN", server: rubensAccount),
                       .recognised(deviceID: "real", by: .profileIdentifier))
        let leftovers = PhoneReconnect.notOnThisPhone(recognised: "real", inspection: inspection, phoneName: "RDN",
                                                      server: rubensAccount)
        XCTAssertEqual(Set(leftovers), ["left-a", "left-b"])
        // The match: its real status shows as normal.
        let real = PhoneConfirmation.isConfirmed(restored: true, matchedOnPhone: true, notOnPhone: false, unambiguous: false)
        XCTAssertTrue(real)
        XCTAssertFalse(PhoneConfirmation.showsNotConfirmed(.protected, confirmed: real))
        XCTAssertFalse(PhoneConfirmation.showsNotConfirmed(.trial(until: 2_000_000_000), confirmed: real))
        // The leftovers stay "Not confirmed", whatever else is true.
        for unambiguous in [false, true] {
            let left = PhoneConfirmation.isConfirmed(restored: true, matchedOnPhone: false, notOnPhone: true,
                                                     unambiguous: unambiguous)
            XCTAssertFalse(left)
            XCTAssertTrue(PhoneConfirmation.showsNotConfirmed(.protected, confirmed: left))
        }
    }

    func testPhonesSetUpFromThisAppAreConfirmed() {
        XCTAssertTrue(PhoneConfirmation.isConfirmed(restored: false, matchedOnPhone: false, notOnPhone: false,
                                                    unambiguous: false))
    }

    // MARK: unambiguous

    func testOnlyPhoneOnTheAccountAndCheckingInIsUnambiguous() {
        let account = [phone("only", pid: realPID), phone("mac-1", "Mac", pid: nil, platform: "mac")]
        XCTAssertTrue(PhoneConfirmation.isUnambiguous(deviceID: "only", account: account, checkingIn: true))
        XCTAssertFalse(PhoneConfirmation.isUnambiguous(deviceID: "only", account: account, checkingIn: nil))
        XCTAssertFalse(PhoneConfirmation.isUnambiguous(deviceID: "only", account: account, checkingIn: false))
        XCTAssertFalse(PhoneConfirmation.isUnambiguous(deviceID: "other", account: account, checkingIn: true))
    }

    func testAUniqueNameIsNotEnoughWhenTheAccountHasOtherPhones() {
        // Checking in is shared by every phone on the account, so it can't vouch for one of two.
        let account = [phone("a", "RDN", pid: realPID), phone("b", "Kiara's iPhone", pid: leftoverA)]
        XCTAssertFalse(PhoneConfirmation.isUnambiguous(deviceID: "a", account: account, checkingIn: true))
        XCTAssertFalse(PhoneConfirmation.isUnambiguous(deviceID: "b", account: account, checkingIn: true))
    }

    func testReleasedMacsAndAppStoreRecordsDoNotCount() {
        let account = [phone("only", pid: realPID),
                       phone("old", pid: leftoverA, released: true),
                       phone("store", pid: "org.paxpeace.pax.appstore.abc"),
                       phone("mac-1", "Mac", pid: "org.paxpeace.pax.macos.x", platform: "macos")]
        XCTAssertTrue(PhoneConfirmation.isUnambiguous(deviceID: "only", account: account, checkingIn: true))
    }

    func testHiddenLeftoversStillCount() {
        // A leftover removed from the list on this Mac is still on the account and shares its DNS address.
        XCTAssertTrue(PhoneReconnect.phonesToRestore(server: rubensAccount, linkedDeviceIDs: [],
                                                     hiddenDeviceIDs: ["left-a", "left-b"]).map(\.deviceID) == ["real"])
        XCTAssertFalse(PhoneConfirmation.isUnambiguous(deviceID: "real", account: rubensAccount, checkingIn: true))
    }

    // MARK: never hides a server fact

    func testWaitTurnedOffAndQuietAlwaysShowAsTheyAre() {
        for st: PhoneStatus.State in [.turningOff(secondsLeft: 3600, notifying: false),
                                      .turningOff(secondsLeft: 0, notifying: true),
                                      .turnedOff, .notCheckingIn(lastSeen: "2026-11-19")] {
            XCTAssertFalse(PhoneConfirmation.showsNotConfirmed(st, confirmed: false), "\(st)")
            XCTAssertFalse(PhoneConfirmation.showsNotConfirmed(st, confirmed: true), "\(st)")
        }
    }

    func testOnlyAllIsWellGivesWay() {
        XCTAssertTrue(PhoneConfirmation.showsNotConfirmed(.protected, confirmed: false))
        XCTAssertTrue(PhoneConfirmation.showsNotConfirmed(.trial(until: 2_000_000_000), confirmed: false))
        XCTAssertTrue(PhoneConfirmation.showsNotConfirmed(nil, confirmed: false))
        XCTAssertFalse(PhoneConfirmation.showsNotConfirmed(nil, confirmed: true))
        XCTAssertFalse(PhoneConfirmation.showsNotConfirmed(.protected, confirmed: true))
    }

    // MARK: 0.8.37 records

    func testMatchesFrom0837CarryOver() {
        XCTAssertTrue(PhoneConfirmation.wasMatchedBefore(notOnPhone: false, sameNameSiblingsNotOnPhone: [true, true]))
        XCTAssertFalse(PhoneConfirmation.wasMatchedBefore(notOnPhone: false, sameNameSiblingsNotOnPhone: [false, false]))
        XCTAssertFalse(PhoneConfirmation.wasMatchedBefore(notOnPhone: false, sameNameSiblingsNotOnPhone: [true, false]))
        XCTAssertFalse(PhoneConfirmation.wasMatchedBefore(notOnPhone: false, sameNameSiblingsNotOnPhone: []))
        XCTAssertFalse(PhoneConfirmation.wasMatchedBefore(notOnPhone: true, sameNameSiblingsNotOnPhone: [true]))
    }

    // MARK: words

    func testWords() {
        XCTAssertEqual(PhoneConfirmation.headline, "Not confirmed")
        XCTAssertEqual(PhoneConfirmation.sidebarLabel, "Not confirmed")
        XCTAssertEqual(PhoneConfirmation.detailsValue, "Not confirmed")
        XCTAssertEqual(PhoneConfirmation.line(name: "RDN", isIPad: false),
                       "Pax hasn't matched RDN to an iPhone yet. Plug it in and choose Add iPhone or iPad to check. "
                           + "Nothing will be installed again.")
        XCTAssertTrue(PhoneConfirmation.line(name: "Kiara's iPad", isIPad: true).contains("to an iPad yet"))
        let all = [PhoneConfirmation.headline, PhoneConfirmation.line(name: "RDN", isIPad: false),
                   PhoneConfirmation.detailsValue].joined(separator: " ").lowercased()
        for word in ["unlock", "porn", "adult", "explicit", "error", "failed", "warning", "!"] {
            XCTAssertFalse(all.contains(word), word)
        }
        XCTAssertNotEqual(PhoneConfirmation.headline, PhoneStatus.headline(.protected))
    }
}
