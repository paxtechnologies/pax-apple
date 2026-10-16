// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// Records the executable and arguments of every call.
final class RecordingRunner: CommandRunner, @unchecked Sendable {
    var executables: [URL] = []
    var arguments: [[String]] = []
    var reply = #"{"ok":true,"devices":[]}"#

    func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult {
        executables.append(executable)
        self.arguments.append(arguments)
        return CommandResult(exitCode: 0, stdout: Data(reply.utf8), stderr: Data())
    }
}

/// v0.8.6: the iPhone helper runs on the Python bundled in Pax.app; no install step.
final class V086Tests: XCTestCase {
    let resources = URL(fileURLWithPath: "/Applications/Pax.app/Contents/Resources")
    let support = URL(fileURLWithPath: "/Users/u/Library/Application Support")
    var bundled: String { resources.appendingPathComponent("device/python/bin/python3.12").path }
    var venv: String { support.appendingPathComponent("Pax/venv/bin/python3").path }

    func resolve(env: [String: String] = [:], executables: Set<String>) -> BundledHelper {
        BundledHelper.resolve(environment: env, resourceDirectory: resources, applicationSupport: support,
                              isExecutable: { executables.contains($0) })
    }

    func testBundledPythonIsTheDefault() {
        let r = resolve(executables: [bundled, venv, "/usr/bin/python3"])
        XCTAssertEqual(r.python.path, bundled)
        XCTAssertEqual(r.arguments, ["-I", "-B"])
        XCTAssertTrue(r.isBundled)
        XCTAssertEqual(r.profilePython.path, bundled)
    }

    func testPaxPythonOverrideWins() {
        let r = resolve(env: ["PAX_PYTHON": "/opt/dev/python3"], executables: [bundled])
        XCTAssertEqual(r.python.path, "/opt/dev/python3")
        XCTAssertEqual(r.arguments, [])
        XCTAssertFalse(r.isBundled)
        XCTAssertEqual(r.profilePython.path, "/usr/bin/python3")
    }

    func testEmptyOverrideIsIgnored() {
        XCTAssertEqual(resolve(env: ["PAX_PYTHON": ""], executables: [bundled]).python.path, bundled)
    }

    func testDeveloperVenvThenSystemPythonWithoutABundle() {
        XCTAssertEqual(resolve(executables: [venv]).python.path, venv)
        let none = resolve(executables: [])
        XCTAssertEqual(none.python.path, "/usr/bin/python3")
        XCTAssertFalse(none.isBundled)
        let noResources = BundledHelper.resolve(environment: [:], resourceDirectory: nil, applicationSupport: nil,
                                                isExecutable: { _ in true })
        XCTAssertEqual(noResources.python.path, "/usr/bin/python3")
    }

    func testRelativePathMatchesTheBundleLayout() {
        XCTAssertEqual(BundledHelper.relativePython, "device/python/bin/python3.12")
    }

    func testHelperCallsPutInterpreterFlagsBeforeTheScript() async throws {
        let runner = RecordingRunner()
        let interpreter = resolve(executables: [bundled])
        let helper = PaxDeviceHelper(script: resources.appendingPathComponent("device/pax_device.py"),
                                     interpreter: interpreter, runner: runner)
        _ = try await helper.call("list")
        _ = try await helper.call("status", udid: "U", extra: ["--cert", "/c.der"])
        XCTAssertEqual(runner.executables.map(\.path), [bundled, bundled])
        XCTAssertEqual(runner.arguments[0], ["-I", "-B", resources.path + "/device/pax_device.py", "list"])
        XCTAssertEqual(runner.arguments[1], ["-I", "-B", resources.path + "/device/pax_device.py",
                                             "status", "--udid", "U", "--cert", "/c.der"])
    }

    func testDeveloperHelperHasNoExtraFlags() {
        let helper = PaxDeviceHelper(script: URL(fileURLWithPath: "/x/pax_device.py"),
                                     python: URL(fileURLWithPath: "/usr/bin/python3"))
        XCTAssertEqual(helper.commandLine("list"), ["/x/pax_device.py", "list"])
    }

    func testProfileGeneratorRunsOnTheBundledPythonIsolated() async throws {
        let runner = RecordingRunner()
        runner.reply = ""
        let gen = ProfileGenerator(script: URL(fileURLWithPath: "/R/profile/make_profile.py"),
                                   interpreter: resolve(executables: [bundled]), runner: runner)
        XCTAssertEqual(gen.python.path, bundled)
        XCTAssertEqual(gen.interpreterArguments, ["-I", "-B"])
        _ = try? await gen.generate()   // no output file here; only the command line matters
        XCTAssertEqual(runner.executables.first?.path, bundled)
        XCTAssertEqual(Array(runner.arguments.first?.prefix(3) ?? []), ["-I", "-B", "/R/profile/make_profile.py"])
        let dev = ProfileGenerator(script: URL(fileURLWithPath: "/R/profile/make_profile.py"),
                                   interpreter: resolve(env: ["PAX_PYTHON": "/opt/p"], executables: []), runner: runner)
        XCTAssertEqual(dev.python.path, "/usr/bin/python3")
        XCTAssertEqual(dev.interpreterArguments, [])
    }

    func testMissingHelperMessageNoLongerMentionsATerminalScript() {
        let info = PaxErrorClassifier.classify(SetupError.helperMissing)
        XCTAssertEqual(info.code, "PAX-IOS-005")
        XCTAssertFalse(info.info.action.contains("install-helper"))
        XCTAssertFalse(info.info.message.contains("install-helper"))
        XCTAssertFalse((SetupError.helperMissing.errorDescription ?? "").contains("README"))
    }
}
