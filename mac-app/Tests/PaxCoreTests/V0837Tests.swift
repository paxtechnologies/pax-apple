// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.37: after Pax for Mac is reinstalled, the account's iPhones and iPads come back from the
/// server, and a plugged-in phone Pax already protects is recognised (never installed again).
final class V0837Tests: XCTestCase {
    private let pid = "org.paxpeace.pax.ios.1f2e3d4c-0000-4000-8000-00000000abcd"
    private let orphanPID = "org.paxpeace.pax.ios.99999999-0000-4000-8000-000000000001"

    private func phone(_ id: String, _ name: String = "Ruben's iPhone", pid: String?, released: Bool = false,
                       at: Int = 100, platform: String = "ios") -> PhoneReconnect.ServerPhone {
        PhoneReconnect.ServerPhone(deviceID: id, name: name, platform: platform, profileIdentifier: pid,
                                   released: released, installedAt: at)
    }

    // MARK: what counts as Pax's phone profile

    func testPhoneProfilePrefixes() {
        XCTAssertTrue(PhoneReconnect.isPhoneProfile(pid))
        XCTAssertTrue(PhoneReconnect.isPhoneProfile("org.paxpeace.pax.ipados.abc"))
        XCTAssertTrue(PhoneReconnect.isPhoneProfile("ORG.PAXPEACE.PAX.IOS.ABC"))
        XCTAssertFalse(PhoneReconnect.isPhoneProfile("org.paxpeace.pax.appstore.abc"))   // App Store app
        XCTAssertFalse(PhoneReconnect.isPhoneProfile("org.paxpeace.pax.macos.abc"))
        XCTAssertFalse(PhoneReconnect.isPhoneProfile("com.example.wifi"))
        XCTAssertFalse(PhoneReconnect.isPhoneProfile(nil))
    }

    func testInspectionKeepsOnlyPaxProfiles() {
        let i = PhoneReconnect.Inspection(json: ["supervised": true, "organization": "Pax (self-managed)",
                                                 "pax_supervised": true,
                                                 "pax_profiles": [pid, "com.example.wifi"], "ios": "27.0.1"])
        XCTAssertTrue(i.supervised && i.paxSupervised && i.hasPaxProtection)
        XCTAssertEqual(i.paxProfiles, [pid])
        XCTAssertEqual(i.iosVersion, "27.0.1")
        XCTAssertFalse(PhoneReconnect.Inspection(json: ["supervised": true, "pax_profiles": []]).hasPaxProtection)
        XCTAssertFalse(PhoneReconnect.Inspection(json: [:]).supervised)
    }

    // MARK: 1 rebuilding the list from the account

    func testRestoreBringsBackTheAccountsUSBPhonesOnly() {
        let server = [
            phone("mac1", "Ruben's Mac", pid: "org.paxpeace.pax.macos.x", platform: "mac"),
            phone("off", pid: "org.paxpeace.pax.ios.off", released: true, at: 50),        // turned off
            phone("store", "iPad", pid: "org.paxpeace.pax.appstore.x", at: 60),            // App Store app
            phone("old", pid: nil, at: 70),                                                 // no identifier
            phone("ipad", "Kitchen iPad", pid: "org.paxpeace.pax.ipados.k", at: 300, platform: "ipados"),
            phone("real", pid: pid, at: 100),
        ]
        let out = PhoneReconnect.phonesToRestore(server: server, linkedDeviceIDs: [], hiddenDeviceIDs: [])
        XCTAssertEqual(out.map(\.deviceID), ["real", "ipad"])                 // oldest first
        XCTAssertTrue(out[1].isIPad)
        XCTAssertFalse(out[0].isIPad)
    }

    func testRestoreSkipsLinkedAndHidden() {
        let server = [phone("a", pid: pid, at: 1), phone("b", "B", pid: orphanPID, at: 2)]
        XCTAssertEqual(PhoneReconnect.phonesToRestore(server: server, linkedDeviceIDs: ["a"], hiddenDeviceIDs: [])
                        .map(\.deviceID), ["b"])
        XCTAssertEqual(PhoneReconnect.phonesToRestore(server: server, linkedDeviceIDs: [], hiddenDeviceIDs: ["b"])
                        .map(\.deviceID), ["a"])
        XCTAssertTrue(PhoneReconnect.phonesToRestore(server: server, linkedDeviceIDs: ["a"], hiddenDeviceIDs: ["b"]).isEmpty)
        XCTAssertEqual(PhoneReconnect.restoredRecordID("a"), "server:a")
    }

    func testServerPhoneFromDeviceStatus() throws {
        let json = """
        {"devices":[{"device_id":"d1","name":"Ruben's iPhone","platform":"ios","profile_identifier":"\(pid)",
          "installed_at":100,"grace_until":200,"in_grace_period":false,"released_at":null,"removal_request":null,
          "released":false},
         {"device_id":"d2","name":"Old","platform":"ios","installed_at":5,"grace_until":6,"in_grace_period":false,
          "released_at":7,"removal_request":null}]}
        """
        struct W: Decodable { let devices: [EscrowClient.DeviceStatus] }
        let list = try JSONDecoder().decode(W.self, from: Data(json.utf8)).devices
        XCTAssertEqual(list[0].profile_identifier, pid)
        XCTAssertNil(list[1].profile_identifier)                              // older server / pax-guard
        let p = list.map { PhoneReconnect.ServerPhone($0) }
        XCTAssertEqual(p[0], phone("d1", pid: pid, at: 100))
        XCTAssertTrue(p[1].released)
    }

    // MARK: 2 matching a plugged-in phone

    private var protectedPhone: PhoneReconnect.Inspection {
        PhoneReconnect.Inspection(supervised: true, organization: "Pax (self-managed)", paxSupervised: true,
                                  paxProfiles: [pid])
    }

    func testPhoneWithoutPaxCarriesOnWithSetUp() {
        let bare = PhoneReconnect.Inspection(supervised: false)
        XCTAssertEqual(PhoneReconnect.match(bare, phoneName: "x", server: nil), .notProtected)
        XCTAssertEqual(PhoneReconnect.match(bare, phoneName: "x", server: [phone("a", pid: pid)]), .notProtected)
        // Supervised by something else but no Pax profile: still not "protected by Pax".
        let other = PhoneReconnect.Inspection(supervised: true, organization: "Acme MDM")
        XCTAssertEqual(PhoneReconnect.match(other, phoneName: "x", server: []), .notProtected)
    }

    func testRecognisedByProfileIdentifier() {
        let server = [phone("mac", "Mac", pid: "org.paxpeace.pax.macos.m", platform: "mac"),
                      phone("real", pid: pid.uppercased(), at: 100),
                      phone("orphan", pid: orphanPID, at: 200)]            // newer, same name, not on the phone
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "Ruben's iPhone", server: server),
                       .recognised(deviceID: "real", by: .profileIdentifier))
        // Name doesn't matter when the identifier matches (the phone was renamed).
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "New name", server: server),
                       .recognised(deviceID: "real", by: .profileIdentifier))
        // A turned-off device still matches (its profile is still on the phone).
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "x", server: [phone("r", pid: pid, released: true)]),
                       .recognised(deviceID: "r", by: .profileIdentifier))
    }

    func testNotSignedInAsksForSignIn() {
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "x", server: nil), .needsSignIn)
    }

    func testAnotherAccountsPhoneIsNeverGuessedByName() {
        // Same name on this account, but its set-up isn't the one on the phone.
        let server = [phone("mine", pid: orphanPID)]
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "Ruben's iPhone", server: server), .otherAccount)
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "Ruben's iPhone", server: []), .otherAccount)
        // App Store app records have identifiers too, so the name never decides.
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "Ruben's iPhone",
                                            server: [phone("s", pid: "org.paxpeace.pax.appstore.1")]), .otherAccount)
    }

    func testNameIsOnlyTheLastResortAndNeverAGuessBetweenTwo() {
        // A server that sends no identifiers at all: exactly one unreleased phone with the name.
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "Ruben's iPhone",
                                            server: [phone("a", pid: nil), phone("b", "Other", pid: nil)]),
                       .recognised(deviceID: "a", by: .name))
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "Ruben's iPhone",
                                            server: [phone("a", pid: nil), phone("b", pid: nil)]), .otherAccount)
        XCTAssertEqual(PhoneReconnect.match(protectedPhone, phoneName: "Ruben's iPhone", server: [phone("a", "No", pid: nil)]),
                       .otherAccount)
    }

    func testSetUpsThatNeverFinishedAreFlagged() {
        let server = [phone("real", pid: pid, at: 100), phone("orphan", pid: orphanPID, at: 200),
                      phone("orphan2", pid: "org.paxpeace.pax.ios.2", at: 210),
                      phone("otherName", "Mum's iPhone", pid: "org.paxpeace.pax.ios.3"),
                      phone("offSame", pid: "org.paxpeace.pax.ios.4", released: true)]
        XCTAssertEqual(PhoneReconnect.notOnThisPhone(recognised: "real", inspection: protectedPhone,
                                                     phoneName: "Ruben's iPhone", server: server),
                       ["orphan", "orphan2"])
    }

    // MARK: words: calm, never the raw error

    func testWords() {
        XCTAssertEqual(PhoneReconnect.recognisedTitle(isIPad: false), "This iPhone is already protected by Pax")
        XCTAssertEqual(PhoneReconnect.recognisedTitle(isIPad: true), "This iPad is already protected by Pax")
        for line in [PhoneReconnect.recognisedLine, PhoneReconnect.signInLine, PhoneReconnect.otherAccountLine,
                     PhoneReconnect.otherAccountTitle(isIPad: false), PhoneReconnect.restoredAppsLine,
                     PhoneReconnect.notOnPhoneLine(name: "iPhone"), PhoneReconnect.duplicateNameLine(name: "iPhone")] {
            XCTAssertFalse(line.contains("PAX-"), line)
            XCTAssertFalse(line.lowercased().contains("supervis"), line)
            XCTAssertFalse(line.lowercased().contains("profile"), line)
            XCTAssertFalse(line.lowercased().contains("erase"), line)          // never offered for a protected phone
        }
        XCTAssertTrue(PhoneReconnect.signInLine.contains("protection stays on"))
        XCTAssertTrue(PhoneReconnect.otherAccountLine.contains("protection stays on"))
    }

    func testNewErrorCodesExist() {
        for code in ["PAX-IOS-013", "PAX-IOS-014", "PAX-IOS-015"] {
            XCTAssertTrue(PaxErrorCatalog.contains(code), code)
        }
        XCTAssertEqual(PaxError("PAX-IOS-015").info.message, "This iPhone is already protected by Pax.")
    }

    func testDMCRefusalIsMappedAndNeverShownRaw() {
        let raw = "ProfileError: The profile must be installed using a device management tool. (DMCFatalError)"
        XCTAssertTrue(PhoneReconnect.needsSupervisor(raw))
        XCTAssertFalse(PhoneReconnect.needsSupervisor("ConnectionError: locked"))
        // An older helper's raw text.
        let old = PaxErrorClassifier.classify(HelperFailure(code: "unexpected", message: raw))
        XCTAssertEqual(old.code, "PAX-IOS-013")
        XCTAssertFalse(old.technical.contains("DMCFatalError"))
        XCTAssertFalse(old.technical.contains("ProfileError"))
        // This version's helper.
        let new = PaxErrorClassifier.classify(HelperFailure(
            code: "needs_supervisor",
            message: "PAX-IOS-013: this iPhone is supervised by a set-up whose key this Mac doesn't hold"))
        XCTAssertEqual(new.code, "PAX-IOS-013")
        // Other helper failures keep their old code.
        XCTAssertEqual(PaxErrorClassifier.classify(HelperFailure(code: "unexpected", message: "boom")).code, "PAX-IOS-010")
    }

    // MARK: the already-protected path never stores a second password or installs again

    private func coordinator(_ runner: FakeHelperRunner) -> SetupCoordinator {
        let helper = PaxDeviceHelper(script: URL(fileURLWithPath: "/x/pax_device.py"),
                                     python: URL(fileURLWithPath: "/usr/bin/python3"),
                                     runner: runner, assumeAvailable: true)
        // Port 9 (discard): if anything reached the server the error would be a network one.
        return SetupCoordinator(devices: MockDeviceService(), keepData: KeepDataSupervisor(helper: helper),
                                identities: SupervisionIdentityStore(),
                                profiles: ProfileGenerator(script: URL(fileURLWithPath: "/nonexistent/make_profile.py")),
                                escrow: EscrowClient(baseURL: URL(string: "http://127.0.0.1:9/")!, token: "t"))
    }

    private let device = ConnectedDevice(ecid: "ECID1", udid: "UDID1", name: "Ruben's iPhone", deviceType: "iPhone17,1",
                                         firmwareVersion: "27.0.1", isSupervised: true)

    private func code(_ work: () async throws -> Void) async -> String? {
        do { try await work(); return nil } catch { return PaxErrorClassifier.classify(error).code }
    }

    func testInspectReadsThePhone() async throws {
        let runner = FakeHelperRunner()
        runner.replies["inspect"] = #"{"ok":true,"supervised":true,"organization":"Pax (self-managed)","pax_supervised":true,"pax_profiles":["\#(pid)"],"other_profiles":2,"ios":"27.0.1"}"#
        let i = try await coordinator(runner).inspectPhone(device)
        XCTAssertTrue(i.hasPaxProtection)
        XCTAssertEqual(runner.calls.first.map { Array($0.args.suffix(3)) }, ["inspect", "--udid", "UDID1"])
    }

    func testRefuseWhenPaxIsAlreadyOnThePhone() async {
        let runner = FakeHelperRunner()
        runner.replies["inspect"] = #"{"ok":true,"supervised":true,"pax_profiles":["\#(pid)"]}"#
        let c = coordinator(runner)
        let got = await code {
            try await c.refuseIfAlreadyProtected(device, status: SupervisionStatus(supervised: true,
                                                                                   hostCertificateRegistered: false),
                                                 supervisedBeforeSetUp: true)
        }
        XCTAssertEqual(got, "PAX-IOS-015")
    }

    func testRefuseWhenSupervisedByAnEarlierSetUp() async {
        let runner = FakeHelperRunner()
        runner.replies["inspect"] = #"{"ok":true,"supervised":true,"pax_profiles":[]}"#
        let c = coordinator(runner)
        let notOurs = SupervisionStatus(supervised: true, hostCertificateRegistered: false)
        let ours = SupervisionStatus(supervised: true, hostCertificateRegistered: true)
        let refused = await code { try await c.refuseIfAlreadyProtected(device, status: notOurs, supervisedBeforeSetUp: true) }
        XCTAssertEqual(refused, "PAX-IOS-013")
        // A phone this run supervised itself carries on as before (even without the host cert).
        let fresh = await code { try await c.refuseIfAlreadyProtected(device, status: notOurs, supervisedBeforeSetUp: false) }
        XCTAssertNil(fresh)
        let registered = await code { try await c.refuseIfAlreadyProtected(device, status: ours, supervisedBeforeSetUp: true) }
        XCTAssertNil(registered)
    }

    func testRefuseFailsClosedWhenThePhoneCantBeRead() async {
        let runner = FakeHelperRunner()        // no "inspect" reply -> helper error
        let c = coordinator(runner)
        let got = await code {
            try await c.refuseIfAlreadyProtected(device, status: SupervisionStatus(supervised: true,
                                                                                   hostCertificateRegistered: true),
                                                 supervisedBeforeSetUp: false)
        }
        XCTAssertNotNil(got)
    }

    func testLockAndEscrowStopsBeforeThePasswordOrAnInstall() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pax-v0837-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let key = dir.appendingPathComponent("k.der")
        try Data("not a real key".utf8).write(to: key)
        let identity = SupervisionIdentity(certificateURL: dir.appendingPathComponent("c.der"), privateKeyURL: key)
        let runner = FakeHelperRunner()
        runner.replies["status"] = #"{"ok":true,"supervised":true,"host_cert_registered":false}"#
        runner.replies["inspect"] = #"{"ok":true,"supervised":true,"pax_profiles":["\#(pid)"]}"#
        let c = coordinator(runner)
        var config = SetupConfiguration()
        config.mode = .keepData
        let got = await code {
            _ = try await c.lockAndEscrow(device, identity: identity, config: config, supervisedBeforeSetUp: true,
                                          progress: { _ in })
        }
        XCTAssertEqual(got, "PAX-IOS-015")
        let commands = runner.calls.map { $0.args.dropFirst().first ?? "" }
        XCTAssertEqual(commands, ["status", "inspect"])
        XCTAssertFalse(commands.contains("install-profile"))
        XCTAssertNil(c.lastEscrowed)                                   // nothing stored on the server
        XCTAssertFalse(FileManager.default.fileExists(atPath: key.path))   // this run's key still destroyed
        try? FileManager.default.removeItem(at: dir)
    }

    func testDemoHelperAnswersInspect() async throws {
        let helper = PaxDeviceHelper(script: URL(fileURLWithPath: "/x/pax_device.py"),
                                     python: URL(fileURLWithPath: "/usr/bin/python3"),
                                     runner: DemoHelperRunner(), assumeAvailable: true)
        let i = try await KeepDataSupervisor(helper: helper).inspect(udid: "00008110-DEMO")
        XCTAssertFalse(i.hasPaxProtection)
    }
}
