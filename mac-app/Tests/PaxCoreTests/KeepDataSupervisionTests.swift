// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// Replies with canned helper JSON per subcommand and records the arguments.
final class FakeHelperRunner: CommandRunner, @unchecked Sendable {
    var calls: [(args: [String], stdin: Data?)] = []
    var replies: [String: String] = [:]

    func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult {
        calls.append((arguments, stdin))
        let command = arguments.dropFirst().first ?? ""
        let out = replies[command] ?? #"{"ok":false,"code":"x","error":"no reply"}"#
        return CommandResult(exitCode: 0, stdout: Data(("{\"event\":{}}\n" + out).utf8), stderr: Data())
    }
}

final class KeepDataSupervisionTests: XCTestCase {
    func supervisor(_ runner: FakeHelperRunner) -> KeepDataSupervisor {
        KeepDataSupervisor(helper: PaxDeviceHelper(script: URL(fileURLWithPath: "/x/pax_device.py"),
                                                   python: URL(fileURLWithPath: "/usr/bin/python3"),
                                                   runner: runner, assumeAvailable: true))
    }

    func testVersionPlan() {
        XCTAssertEqual(KeepDataPlan.forVersion("17.0"), .allowed(.restoredSystem))
        XCTAssertEqual(KeepDataPlan.forVersion("26.6.2"), .allowed(.restoredSystem))
        XCTAssertEqual(KeepDataPlan.forVersion("27.0"), .allowed(.live))
        XCTAssertEqual(KeepDataPlan.forVersion("27.2"), .allowed(.live))
        XCTAssertEqual(KeepDataPlan.forVersion("16.7"), .refused(.tooOld))
        XCTAssertEqual(KeepDataPlan.forVersion("28.0"), .refused(.tooNew))
        XCTAssertEqual(KeepDataPlan.forVersion(nil), .refused(.unknown))
        XCTAssertEqual(KeepDataPlan.forVersion("27.x"), .refused(.unknown))
        XCTAssertEqual(KeepDataPlan.forVersion("0.1"), .refused(.unknown))
    }

    func testOnlyNotFoundAndLockedArePolled() {
        XCTAssertTrue(PhoneConnectState.notFound.pollAgain)
        XCTAssertTrue(PhoneConnectState.locked.pollAgain)
        XCTAssertFalse(PhoneConnectState.trustRequested.pollAgain)
        XCTAssertFalse(PhoneConnectState.denied.pollAgain)
    }

    func testPreflightParsing() async throws {
        let runner = FakeHelperRunner()
        runner.replies["preflight"] = #"{"ok":true,"mode":"live","blocking":[],"warnings":["w"],"ask_user_find_my":false,"facts":{"battery_level":70,"find_my_on":false}}"#
        let p = try await supervisor(runner).preflight(udid: "U", findMyConfirmedOff: true, backupConfirmed: true)
        XCTAssertEqual(p.method, .live)
        XCTAssertTrue(p.ok)
        XCTAssertEqual(p.batteryLevel, 70)
        XCTAssertEqual(runner.calls[0].args, ["/x/pax_device.py", "preflight", "--udid", "U",
                                              "--find-my-confirmed-off", "--backup-confirmed"])
    }

    func testSeedRestorePassesCertificateAndStrictFlag() async throws {
        let runner = FakeHelperRunner()
        runner.replies["seed-restore"] = #"{"ok":true,"mode":"live","next":"x"}"#
        let identity = SupervisionIdentity(certificateURL: URL(fileURLWithPath: "/id/c.der"),
                                           privateKeyURL: URL(fileURLWithPath: "/id/k.der"))
        let outcome = try await supervisor(runner).seedRestore(udid: "U", identity: identity, forbidPairing: true)
        XCTAssertEqual(outcome, SeedRestoreOutcome(method: .live, alreadySupervised: false))
        XCTAssertEqual(runner.calls[0].args, ["/x/pax_device.py", "seed-restore", "--udid", "U",
                                              "--org", "Pax (self-managed)", "--cert", "/id/c.der",
                                              "--forbid-pairing"])
        XCTAssertFalse(runner.calls[0].args.contains("/id/k.der"), "the key never goes to the restore")
    }

    func testHelperErrorSurfaces() async {
        let runner = FakeHelperRunner()
        runner.replies["seed-restore"] = #"{"ok":false,"code":"find_my_on","error":"Find My is on."}"#
        do {
            _ = try await supervisor(runner).seedRestore(udid: "U", identity: nil, forbidPairing: false)
            XCTFail("expected failure")
        } catch let f as HelperFailure {
            XCTAssertEqual(f.code, "find_my_on")
        } catch { XCTFail("\(error)") }
    }

    func testInstallProfileSendsBytesOnStdin() async throws {
        let runner = FakeHelperRunner()
        runner.replies["install-profile"] = #"{"ok":true,"installed":false,"method":"manual","pending_user":true}"#
        let identity = SupervisionIdentity(certificateURL: URL(fileURLWithPath: "/c"), privateKeyURL: URL(fileURLWithPath: "/k"))
        let outcome = try await supervisor(runner).installProfile(udid: "U", profile: Data("P".utf8),
                                                                   identity: identity, allowManual: true)
        XCTAssertEqual(outcome, .pendingUser)
        XCTAssertEqual(runner.calls[0].stdin, Data("P".utf8))
        XCTAssertTrue(runner.calls[0].args.contains("--allow-manual"))
    }

    func testProfileGeneratorDefaultsToFamilyFilter() {
        let args = ProfileGenerator.arguments(script: URL(fileURLWithPath: "/m.py"), platform: "ios",
                                              out: URL(fileURLWithPath: "/o"), escrow: URL(fileURLWithPath: "/e"),
                                              filter: .family, resolverURL: nil, blockApps: [], blockURLs: [])
        XCTAssertEqual(Array(args.suffix(2)), ["--filter", "family"])
        let custom = ProfileGenerator.arguments(script: URL(fileURLWithPath: "/m.py"), platform: "ios",
                                                out: URL(fileURLWithPath: "/o"), escrow: URL(fileURLWithPath: "/e"),
                                                filter: .core, resolverURL: "https://dns.example/q",
                                                blockApps: [], blockURLs: [])
        XCTAssertTrue(custom.contains("--resolver-url"))
        XCTAssertFalse(custom.contains("--filter"))
    }

    func testDefaultsAreKeepDataAndFamily() {
        let config = SetupConfiguration()
        XCTAssertEqual(config.mode, .keepData)
        XCTAssertEqual(config.dnsFilter, .family)
        XCTAssertFalse(config.forbidPairing)
    }
}
