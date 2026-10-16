// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// Records invocations and replies with canned cfgutil JSON.
final class FakeRunner: CommandRunner, @unchecked Sendable {
    var calls: [(args: [String], stdin: Data?)] = []
    var replies: [String: String] = [:]   // command -> stdout JSON
    var exitCode: Int32 = 0

    func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult {
        calls.append((arguments, stdin))
        let known = ["list", "get", "backup", "erase", "prepare", "restore-backup", "install-profile"]
        let command = arguments.first(where: { known.contains($0) }) ?? ""
        let out = replies[command] ?? #"{"Type":"CommandOutput","Command":"\#(command)","Output":{}}"#
        return CommandResult(exitCode: exitCode, stdout: Data(out.utf8), stderr: Data())
    }
}

final class CfgutilDeviceServiceTests: XCTestCase {
    /// Points at /bin/sh so isAvailable() is true; the FakeRunner never executes it.
    func makeService(_ runner: FakeRunner) -> CfgutilDeviceService {
        CfgutilDeviceService(cfgutil: URL(fileURLWithPath: "/bin/sh"), runner: runner)
    }

    func testIsSupervisedParsesGetOutput() async throws {
        let runner = FakeRunner()
        runner.replies["get"] = #"{"Type":"CommandOutput","Command":"get","Devices":["0xABC"],"Output":{"0xABC":{"isSupervised":true}}}"#
        let supervised = try await makeService(runner).isSupervised(ecid: "0xABC")
        XCTAssertTrue(supervised)
        XCTAssertEqual(runner.calls.first?.args, ["--format", "JSON", "-e", "0xABC", "get", "isSupervised"])
    }

    func testErrorTypeThrows() async {
        let runner = FakeRunner()
        runner.replies["erase"] = #"{"Type":"Error","Message":"Find My is on","FailureReason":"Activation Lock"}"#
        do {
            try await makeService(runner).erase(ecid: "0xABC")
            XCTFail("expected error")
        } catch let DeviceServiceError.commandFailed(command, message) {
            XCTAssertEqual(command, "erase")
            XCTAssertTrue(message.contains("Find My"))
        } catch {
            XCTFail("wrong error \(error)")
        }
    }

    func testPrepareArguments() async throws {
        let runner = FakeRunner()
        let identity = SupervisionIdentity(certificateURL: URL(fileURLWithPath: "/tmp/c.der"),
                                           privateKeyURL: URL(fileURLWithPath: "/tmp/k.der"))
        try await makeService(runner).prepareSupervised(ecid: "0x1", organization: SupervisingOrganization(),
                                                        identity: identity)
        let args = runner.calls[0].args
        XCTAssertTrue(args.contains("--supervised"))
        XCTAssertEqual(args[args.firstIndex(of: "--host-cert")! + 1], "/tmp/c.der")
        XCTAssertFalse(args.contains("--forbid-pairing"))
    }

    func testInstallProfilePipesStdinWithIdentity() async throws {
        let runner = FakeRunner()
        let identity = SupervisionIdentity(certificateURL: URL(fileURLWithPath: "/tmp/c.der"),
                                           privateKeyURL: URL(fileURLWithPath: "/tmp/k.der"))
        let data = Data("<plist/>".utf8)
        try await makeService(runner).installProfile(ecid: "0x1", profile: data, identity: identity)
        XCTAssertEqual(runner.calls[0].args,
                       ["--format", "JSON", "-e", "0x1", "-C", "/tmp/c.der", "-K", "/tmp/k.der",
                        "install-profile", "-"])
        XCTAssertEqual(runner.calls[0].stdin, data)
    }

    func testParseDevicesDefensively() {
        let json: [String: Any] = ["Output": [
            "0xB": ["name": "Alex's iPhone", "deviceType": "iPhone16,1", "UDID": "0000-B"],
            "0xA": ["deviceType": "iPad14,1"],
        ]]
        let devices = CfgutilDeviceService.parseDevices(from: json)
        XCTAssertEqual(devices.count, 2)
        XCTAssertEqual(devices.first(where: { $0.ecid == "0xB" })?.udid, "0000-B")
    }

    func testMajorOSVersion() {
        let d = ConnectedDevice(ecid: "1", udid: nil, name: "x", deviceType: "iPhone",
                                firmwareVersion: "27.0.1")
        XCTAssertEqual(d.majorOSVersion, 27)
    }

    func testKeepDataRefusesIOS28() {
        // v0.2: the refusing Quick stub is gone; Keep my data refuses iOS 28+ instead.
        XCTAssertNil(KeepDataPlan.forVersion("28.0").method)
        XCTAssertEqual(KeepDataPlan.forVersion("27.0.1").method, .live)
    }
}
