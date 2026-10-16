// SPDX-License-Identifier: GPL-3.0-only
import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import PaxCore

/// Records every command (plain and root) in one ordered log and answers from a
/// script, so the tests can check the ORDER of the lockdown and its rollback.
final class LockdownWorld: @unchecked Sendable {
    let lock = NSLock()
    var log: [String] = []
    var admins = ["root", "alex"]
    var userPassword = "user pass 'quote\""
    var paxadminPassword: String?
    var fileVault = true
    var failAt: String?           // substring of a command that should fail
    var profileInstalled = false
    var tokenEnabled = true
    var leftoverPaxadmin = false  // a non-admin paxadmin record from an earlier try
    var addUserSilentlyFails = false
    var safe: String?             // v0.8.0: what the local safe holds
    var safeLies = false
    var enrollment = "Enrolled via DEP: No\nMDM enrollment: No\n"
    var stickyAdmins: Set<String> = []   // v0.8.10: dseditgroup -d "works" but they stay admins

    func record(_ who: String, _ exe: String, _ args: [String]) {
        lock.lock(); defer { lock.unlock() }
        log.append("\(who) \(([exe] + args).joined(separator: " "))")
    }

    func answer(_ exe: String, _ args: [String], as who: String) -> CommandResult {
        let line = ([exe] + args).joined(separator: " ")
        func ok(_ out: String = "") -> CommandResult { CommandResult(exitCode: 0, stdout: Data(out.utf8), stderr: Data()) }
        func fail(_ out: String = "failed") -> CommandResult { CommandResult(exitCode: 1, stdout: Data(), stderr: Data(out.utf8)) }
        if let f = failAt, line.contains(f) { return fail("simulated failure: \(f)") }
        lock.lock(); defer { lock.unlock() }
        switch (exe, args.first ?? "") {
        case ("/usr/bin/dscl", "."):
            if args.count >= 4, args[1] == "-authonly" {
                if args[2] == "alex" { return args[3] == userPassword ? ok() : fail() }
                if args[2] == "paxadmin" { return args[3] == paxadminPassword ? ok() : fail() }
            }
            if args.count >= 3, args[1] == "-read", args[2] == "/Users/paxadmin" {
                return (admins.contains("paxadmin") || leftoverPaxadmin) ? ok("UniqueID: 502\n")
                    : CommandResult(exitCode: 56, stdout: Data(), stderr: Data("eDSRecordNotFound".utf8))
            }
            if args.count >= 3, args[1] == "-delete", args[2] == "/Users/paxadmin" {
                leftoverPaxadmin = false
                admins.removeAll { $0 == "paxadmin" }
                return ok()
            }
            if args.count >= 2, args[1] == "-read" {
                return ok("GroupMembership: " + admins.joined(separator: " ") + "\n")
            }
            return ok()
        case ("/usr/bin/fdesetup", _):
            return ok(fileVault ? "FileVault is On.\n" : "FileVault is Off.\n")
        case ("/usr/sbin/sysadminctl", _):
            if args.contains("-addUser") {
                if leftoverPaxadmin || addUserSilentlyFails { return ok() }  // exits 0, does nothing
                paxadminPassword = args[args.firstIndex(of: "-password")! + 1]
                admins.append("paxadmin")
            } else if args.contains("-deleteUser") {
                admins.removeAll { $0 == "paxadmin" }
                paxadminPassword = nil
            } else if args.contains("-secureTokenStatus") {
                return CommandResult(exitCode: 0, stdout: Data(),
                                     stderr: Data("Secure token is \(tokenEnabled ? "ENABLED" : "DISABLED") for user paxadmin".utf8))
            }
            return ok()
        case ("/usr/sbin/dseditgroup", _):
            let user = args[args.firstIndex(of: "-m") ?? args.firstIndex(of: "-a") ?? args.firstIndex(of: "-d")! + 0]
            if args.contains("checkmember") {
                let u = args[args.firstIndex(of: "-m")! + 1]
                return ok(admins.contains(u) ? "yes \(u) is a member of admin\n" : "no \(u) is NOT a member of admin\n")
            }
            if let i = args.firstIndex(of: "-d"), !stickyAdmins.contains(args[i + 1]) {
                admins.removeAll { $0 == args[i + 1] }
            }
            if let i = args.firstIndex(of: "-a"), !admins.contains(args[i + 1]) { admins.append(args[i + 1]) }
            _ = user
            return ok()
        case ("/usr/bin/profiles", "show"):
            return ok(profileInstalled ? "profileIdentifier: org.paxpeace.pax.macos-selflock.test\n" : "")
        case ("/usr/bin/profiles", "status"):
            return ok(enrollment)
        case ("/usr/bin/profiles", "remove"):
            profileInstalled = false
            return ok()
        default:
            return ok()
        }
    }
}

struct WorldPlainRunner: CommandRunner {
    let world: LockdownWorld
    func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult {
        world.record("user", executable.path, arguments)
        return world.answer(executable.path, arguments, as: "user")
    }
}

struct WorldRootRunner: PrivilegedRunner {
    let world: LockdownWorld
    let who: String
    let password: String
    func runAsRoot(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult {
        world.record("root(\(who))", executable, arguments)
        // Credentials only work for a current administrator with the right password.
        let valid: Bool = {
            world.lock.lock(); defer { world.lock.unlock() }
            if who == "alex" { return world.admins.contains("alex") && password == world.userPassword }
            if who == "paxadmin" { return world.admins.contains("paxadmin") && password == world.paxadminPassword }
            return false
        }()
        guard valid else { return CommandResult(exitCode: 1, stdout: Data(), stderr: Data("not authorised".utf8)) }
        return world.answer(executable, arguments, as: "root")
    }
}

/// Fake Pax server for the escrow steps.
final class FakeEscrowProtocol: URLProtocol {
    nonisolated(unsafe) static var fail = false
    nonisolated(unsafe) static var storedPassword: String?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let path = request.url?.path ?? ""
        var status = 200
        var body = "{}"
        if Self.fail {
            status = 503; body = #"{"error":"down","message":"server down"}"#
        } else if path == "/v1/devices" && request.httpMethod == "POST" {
            status = 201
            var data = request.httpBody
            if data == nil, let stream = request.httpBodyStream {
                stream.open(); var buf = [UInt8](repeating: 0, count: 4096)
                let n = stream.read(&buf, maxLength: buf.count); stream.close()
                data = Data(buf.prefix(max(0, n)))
            }
            if let d = data, let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                Self.storedPassword = obj["removal_password"] as? String
            }
            body = #"{"device_id":"dev1","installed_at":1,"grace_until":2}"#
        } else if path.hasSuffix("/guard-token") {
            status = 201; body = #"{"guard_token":"gtoken"}"#
        } else if path == "/v1/devices/dev1" {
            body = #"{"device_id":"dev1","name":"Mac","platform":"mac","installed_at":1,"grace_until":2,"in_grace_period":true,"released_at":null,"removal_request":null}"#
        }
        let resp = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class MacLockdownTests: XCTestCase {
    let paths = MacLockdownPaths(guardSource: URL(fileURLWithPath: "/R/guard"),
                                 guardInstallScript: URL(fileURLWithPath: "/R/guard/pax-guard-install.sh"),
                                 configFile: URL(fileURLWithPath: "/tmp/p/config.json"),
                                 profileFile: URL(fileURLWithPath: "/tmp/p/Pax.mobileconfig"))

    func makeLockdown(_ world: LockdownWorld, allowExtraAdmins: Bool = false) -> MacLockdown {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [FakeEscrowProtocol.self]
        FakeEscrowProtocol.fail = false
        FakeEscrowProtocol.storedPassword = nil
        let escrow = EscrowClient(baseURL: URL(string: "http://pax.test/")!, token: "acct",
                                  session: URLSession(configuration: cfg))
        return MacLockdown(userName: "alex", escrow: escrow, plain: WorldPlainRunner(world: world),
                           allowExtraAdmins: allowExtraAdmins,
                           makeRoot: { user, pw in WorldRootRunner(world: world, who: user, password: pw) },
                           verifyRetryDelayNanos: 1_000_000)
    }

    func protect(_ l: MacLockdown, _ world: LockdownWorld, approve: Bool = true) async throws -> MacLockdownOutcome {
        try await l.protectThisMac(
            password: world.userPassword, deviceName: "Alex's MacBook Pro", paths: paths,
            profileIdentifier: "org.paxpeace.pax.macos-selflock.test",
            writeConfig: { _, _ in },
            waitForProfileApproval: {
                if approve { world.lock.lock(); world.profileInstalled = true; world.lock.unlock() }
                return approve
            },
            progress: { _ in })
    }

    func index(_ world: LockdownWorld, _ needle: String) -> Int? {
        world.log.firstIndex { $0.contains(needle) }
    }

    // MARK: Happy path and ordering

    func testHappyPathOrderIsSafe() async throws {
        let world = LockdownWorld()
        let outcome = try await protect(makeLockdown(world), world)
        XCTAssertEqual(outcome.deviceID, "dev1")
        XCTAssertTrue(outcome.userDemoted)
        XCTAssertEqual(world.admins.filter { $0 != "root" }, ["paxadmin"])

        let create = index(world, "-addUser paxadmin")!
        let token = index(world, "-secureTokenOn paxadmin")!
        let verify = index(world, "-authonly paxadmin")!
        let profile = index(world, "/usr/bin/open /tmp/p/Pax.mobileconfig")!
        let guardInstall = index(world, "pax-guard-install.sh")!
        let demote = index(world, "-o edit -d alex")!
        let check = world.log.lastIndex { $0.contains("checkmember -m alex") }!
        XCTAssertLessThan(create, token)
        XCTAssertLessThan(token, verify)
        XCTAssertLessThan(verify, profile)
        XCTAssertLessThan(profile, guardInstall)
        XCTAssertLessThan(guardInstall, demote)
        XCTAssertLessThan(demote, check)
        // The escrowed password is the one that verified.
        XCTAssertEqual(FakeEscrowProtocol.storedPassword, world.paxadminPassword)
        XCTAssertEqual(world.paxadminPassword?.count, 32)
        // paxadmin is hidden.
        XCTAssertNotNil(index(world, "-create /Users/paxadmin IsHidden 1"))
        // The demotion ran as root with the user's own (still admin) credentials.
        XCTAssertTrue(world.log[demote].hasPrefix("root(alex)"))
    }

    func testCreateAdminRunsWithUsersCredentialsAndAdminFlag() async throws {
        let world = LockdownWorld()
        _ = try await protect(makeLockdown(world), world)
        let line = world.log[index(world, "-addUser paxadmin")!]
        XCTAssertTrue(line.hasPrefix("root(alex) /usr/sbin/sysadminctl -addUser paxadmin"))
        XCTAssertTrue(line.contains(" -admin -adminUser alex -adminPassword "))
    }

    // MARK: Preflight

    func testWrongPasswordChangesNothing() async {
        let world = LockdownWorld()
        let l = makeLockdown(world)
        do {
            _ = try await l.protectThisMac(password: "nope", deviceName: "M", paths: paths,
                                           profileIdentifier: "x", writeConfig: { _, _ in },
                                           waitForProfileApproval: { true }, progress: { _ in })
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(error as? MacLockdownError, .wrongPassword)
        }
        XCTAssertNil(index(world, "sysadminctl"))
        XCTAssertNil(index(world, "dseditgroup -o edit"))
    }

    func testOtherAdminBlocksSetUp() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "spare"]
        let pre = try await makeLockdown(world).preflight(password: world.userPassword)
        XCTAssertFalse(pre.ok)
        XCTAssertTrue(pre.problems.joined().contains("spare"))
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {
            guard case .preflightFailed = error as? MacLockdownError else { return XCTFail("\(error)") }
        }
        XCTAssertNil(index(world, "-addUser"))
    }

    func testTestModeAllowsOtherAdminWithWarning() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc"]
        let pre = try await makeLockdown(world, allowExtraAdmins: true).preflight(password: world.userPassword)
        XCTAssertTrue(pre.ok)
        XCTAssertTrue(pre.warnings.joined().contains("rmsvc"))
        XCTAssertFalse(pre.problems.joined().contains("rmsvc"))
    }

    func testTestModeStillBlocksExistingPaxadmin() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc", "paxadmin"]
        let pre = try await makeLockdown(world, allowExtraAdmins: true).preflight(password: world.userPassword)
        XCTAssertFalse(pre.ok)
    }

    func testExistingPaxadminBlocksSetUp() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "paxadmin"]
        let pre = try await makeLockdown(world).preflight(password: world.userPassword)
        XCTAssertTrue(pre.paxadminExists)
        XCTAssertFalse(pre.ok)
    }

    func testNonAdminUserBlocked() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "someoneelse"]
        let pre = try await makeLockdown(world).preflight(password: world.userPassword)
        XCTAssertFalse(pre.userIsAdmin)
        XCTAssertFalse(pre.ok)
    }

    func testFileVaultWarnings() async throws {
        let world = LockdownWorld()
        var pre = try await makeLockdown(world).preflight(password: world.userPassword)
        XCTAssertTrue(pre.fileVaultOn)
        XCTAssertTrue(pre.warnings[0].contains("recovery key"))
        world.fileVault = false
        pre = try await makeLockdown(world).preflight(password: world.userPassword)
        XCTAssertFalse(pre.fileVaultOn)
        XCTAssertTrue(pre.ok)  // a warning, not a blocker
    }

    func testAdminParsing() {
        XCTAssertEqual(MacLockdownParse.adminUsers("GroupMembership: root alex _mbsetupuser paxadmin\n"),
                       ["alex", "paxadmin"])
        XCTAssertEqual(MacLockdownParse.adminUsers("No such key: GroupMembership"), [])
        XCTAssertTrue(MacLockdownParse.isMemberYes("yes alex is a member of admin"))
        XCTAssertFalse(MacLockdownParse.isMemberYes("no alex is NOT a member of admin"))
        XCTAssertTrue(MacLockdownParse.isMemberNo("no alex is NOT a member of admin"))
        XCTAssertFalse(MacLockdownParse.isMemberNo(""))
        XCTAssertFalse(MacLockdownParse.isMemberNo("yes alex is a member of admin"))
        XCTAssertTrue(MacLockdownParse.secureTokenEnabled("2026-10-14 sysadminctl[1:2] Secure token is ENABLED for user paxadmin"))
        XCTAssertFalse(MacLockdownParse.secureTokenEnabled("Secure token is DISABLED for user paxadmin"))
    }

    // MARK: Rollback

    func assertRolledBack(_ world: LockdownWorld, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(world.admins.contains("alex"), "user must stay admin", file: file, line: line)
        XCTAssertFalse(world.admins.contains("paxadmin"), "paxadmin must be deleted", file: file, line: line)
    }

    func testSecureTokenFailureWithFileVaultRollsBack() async {
        let world = LockdownWorld()
        world.tokenEnabled = false
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {
            guard case .rolledBack(let step, _) = error as? MacLockdownError else { return XCTFail("\(error)") }
            XCTAssertEqual(step, .secureToken)
        }
        assertRolledBack(world)
        XCTAssertNil(index(world, "-o edit -d alex"))
        XCTAssertNotNil(index(world, "-deleteUser paxadmin -adminUser alex"))
    }

    func testNoSecureTokenIsFineWithFileVaultOff() async throws {
        let world = LockdownWorld()
        world.tokenEnabled = false
        world.fileVault = false
        let outcome = try await protect(makeLockdown(world), world)
        XCTAssertTrue(outcome.userDemoted)
    }

    func testVerifyFailureRollsBackBeforeEscrow() async {
        let world = LockdownWorld()
        world.failAt = "-authonly paxadmin"
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {}
        assertRolledBack(world)
        XCTAssertNil(FakeEscrowProtocol.storedPassword, "nothing escrowed if the password didn't verify")
    }

    func testLeftoverPaxadminRecordIsClearedBeforeCreating() async throws {
        let world = LockdownWorld()
        world.leftoverPaxadmin = true
        let outcome = try await protect(makeLockdown(world), world)
        XCTAssertTrue(outcome.userDemoted)
        let clean = index(world, "-delete /Users/paxadmin")!
        let create = index(world, "-addUser paxadmin")!
        XCTAssertLessThan(clean, create)
        XCTAssertEqual(FakeEscrowProtocol.storedPassword, world.paxadminPassword)
    }

    func testSilentAddUserFailureIsCaughtAtCreate() async {
        let world = LockdownWorld()
        world.addUserSilentlyFails = true
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {
            guard case .rolledBack(let step, _) = error as? MacLockdownError else { return XCTFail("\(error)") }
            XCTAssertEqual(step, .createAdmin)
        }
        XCTAssertNil(FakeEscrowProtocol.storedPassword)
        assertRolledBack(world)
    }

    func testEscrowFailureRollsBackAndNeverDemotes() async {
        let world = LockdownWorld()
        let l = makeLockdown(world)
        FakeEscrowProtocol.fail = true
        do {
            _ = try await l.protectThisMac(password: world.userPassword, deviceName: "M", paths: paths,
                                           profileIdentifier: "org.paxpeace.pax.macos-selflock.test",
                                           writeConfig: { _, _ in }, waitForProfileApproval: { true },
                                           progress: { _ in })
            XCTFail("should throw")
        } catch {
            guard case .rolledBack(let step, _) = error as? MacLockdownError else { return XCTFail("\(error)") }
            XCTAssertEqual(step, .escrow)
        }
        FakeEscrowProtocol.fail = false
        assertRolledBack(world)
        XCTAssertNil(index(world, "/usr/bin/open"))
        XCTAssertNil(index(world, "-o edit -d alex"))
    }

    func testProfileNotApprovedRollsBack() async {
        let world = LockdownWorld()
        do { _ = try await protect(makeLockdown(world), world, approve: false); XCTFail("should throw") } catch {}
        assertRolledBack(world)
        XCTAssertNotNil(index(world, "profiles remove -identifier org.paxpeace.pax.macos-selflock.test"))
        XCTAssertNil(index(world, "pax-guard-install.sh"))
    }

    func testGuardInstallFailureRemovesProfileAndAdmin() async {
        let world = LockdownWorld()
        world.failAt = "pax-guard-install.sh"
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {
            guard case .rolledBack(let step, _) = error as? MacLockdownError else { return XCTFail("\(error)") }
            XCTAssertEqual(step, .installGuard)
        }
        assertRolledBack(world)
        XCTAssertFalse(world.profileInstalled)
        XCTAssertNil(index(world, "-o edit -d alex"))
    }

    func testDemotionFailureKeepsUserAdmin() async {
        let world = LockdownWorld()
        world.failAt = "-o edit -d alex"
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {}
        assertRolledBack(world)
        XCTAssertNotNil(index(world, "pax-uninstall-emergency.sh --user alex"))
    }

    func testFailureAfterDemotionRepromotesWithPaxadminFirst() async {
        let world = LockdownWorld()
        world.failAt = "checkmember -m alex admin"  // the post-demotion check fails
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {}
        // Re-promotion used paxadmin (alex was no longer an admin) and came before
        // paxadmin was deleted.
        let promote = world.log.firstIndex { $0.hasPrefix("root(paxadmin)") && $0.contains("-o edit -a alex") }
        let delete = world.log.lastIndex { $0.contains("-deleteUser paxadmin") }
        XCTAssertNotNil(promote)
        XCTAssertNotNil(delete)
        XCTAssertLessThan(promote!, delete!)
        assertRolledBack(world)
    }

    // MARK: Removal

    func testRemovePaxPromotesFirstThenRemovesThenDeletes() async throws {
        let world = LockdownWorld()
        let l = makeLockdown(world)
        _ = try await protect(l, world)
        world.log.removeAll()
        let done = try await l.removePax(paxAdminPassword: world.paxadminPassword!, paths: paths,
                                         profileIdentifier: "org.paxpeace.pax.macos-selflock.test")
        XCTAssertEqual(done.count, 3)
        let promote = index(world, "-o edit -a alex")!
        let uninstall = index(world, "/Library/PaxGuard/bin/pax-uninstall-emergency.sh --user alex")!
        let delete = index(world, "-deleteUser paxadmin")!
        XCTAssertLessThan(promote, uninstall)
        XCTAssertLessThan(uninstall, delete)
        XCTAssertTrue(world.log[promote].hasPrefix("root(paxadmin)"))
        assertRolledBack(world)
    }

    func testRemovePaxWithWrongPasswordChangesNothing() async throws {
        let world = LockdownWorld()
        let l = makeLockdown(world)
        _ = try await protect(l, world)
        do {
            _ = try await l.removePax(paxAdminPassword: "wrong", paths: paths, profileIdentifier: "x")
            XCTFail("should throw")
        } catch {}
        XCTAssertFalse(world.admins.contains("alex"))
        XCTAssertTrue(world.admins.contains("paxadmin"))
    }

    // MARK: Pure helpers

    func testPasswordGenerator() {
        let a = generateAdminPassword()
        let b = generateAdminPassword()
        XCTAssertEqual(a.count, 32)
        XCTAssertNotEqual(a, b)
        let allowed = Set("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        XCTAssertTrue(a.allSatisfy { allowed.contains($0) })
        XCTAssertFalse(a.contains("l") || a.contains("0") || a.contains("O") || a.contains("1"))
    }

    func testAppleScriptQuotingCannotBreakOut() {
        let script = OSAScriptPrivilegedRunner.appleScript(
            executable: "/usr/sbin/sysadminctl", arguments: ["-adminPassword", "a'b\"c\\d; rm -rf /"],
            user: "alex", password: "p\"w")
        XCTAssertTrue(script.hasPrefix("do shell script \""))
        XCTAssertTrue(script.hasSuffix("with administrator privileges"))
        XCTAssertTrue(script.contains("'a'\\\\''b\\\"c\\\\d; rm -rf /'"))
        XCTAssertTrue(script.contains("password \"p\\\"w\""))
        XCTAssertEqual(OSAScriptPrivilegedRunner.shellQuote("it's"), "'it'\\''s'")
    }

    func testOSAScriptRunnerSendsScriptOnStdinNotArgs() async throws {
        final class Capture: CommandRunner, @unchecked Sendable {
            var args: [String] = []
            var stdin: Data?
            func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult {
                args = arguments; self.stdin = stdin
                return CommandResult(exitCode: 0, stdout: Data(), stderr: Data())
            }
        }
        let cap = Capture()
        let r = OSAScriptPrivilegedRunner(user: "alex", password: "secret-pw", runner: cap)
        _ = try await r.runAsRoot("/usr/bin/true", [], stdin: nil)
        XCTAssertEqual(cap.args, ["-"])
        XCTAssertFalse(cap.args.joined().contains("secret-pw"))
        XCTAssertTrue(String(decoding: cap.stdin ?? Data(), as: UTF8.self).contains("secret-pw"))
    }

    func testGuardConfigJSON() throws {
        let c = GuardConfigFile(server_url: "http://127.0.0.1:8080/", guard_token: "g",
                                profile_identifier: "org.paxpeace.pax.macos-selflock.x", user: "alex",
                                resolver_host: GuardConfigFile.resolverHost(from: "https://doh.cleanbrowsing.org/doh/family-filter/"))
        let obj = try JSONSerialization.jsonObject(with: c.json()) as? [String: Any]
        XCTAssertEqual(obj?["resolver_host"] as? String, "doh.cleanbrowsing.org")
        XCTAssertEqual(obj?["adblock_default"] as? Bool, true)
        // v0.8.13: no X / Bluesky media keys (always blocked; pax-guard ignores old ones).
        XCTAssertNil(obj?["x_media_default"])
        XCTAssertNil(obj?["bluesky_media_default"])
        XCTAssertEqual(Set(obj?.keys.map { $0 } ?? []),
                       ["server_url", "guard_token", "profile_identifier", "user", "resolver_host",
                        "adblock_default",
                        // v0.8.0
                        "escrow_mode", "dns_mode", "rotate_recovery_key", "firmware_password", "mdm_managed",
                        "testing_allow_extra_admins",
                        // v0.8.6
                        "youtube_restricted_default"])
        XCTAssertEqual(obj?["dns_mode"] as? String, "local")
    }

    func testSelfLockProfileArguments() {
        let script = URL(fileURLWithPath: "/R/profile/make_profile.py")
        let out = URL(fileURLWithPath: "/tmp/p/Pax.mobileconfig")
        XCTAssertEqual(ProfileGenerator.selfLockArguments(script: script, out: out, filter: .family),
                       ["/R/profile/make_profile.py", "--self-lock", "--out", "/tmp/p/Pax.mobileconfig",
                        "--filter", "family"])
        XCTAssertEqual(ProfileGenerator.selfLockArguments(script: script, out: out, filter: .family,
                                                          userToken: "tok", dnsBase: "https://d.example",
                                                          blockURLs: ["reddit.com"], adblock: false),
                       ["/R/profile/make_profile.py", "--self-lock", "--out", "/tmp/p/Pax.mobileconfig",
                        "--user-token", "tok", "--dns-base", "https://d.example",
                        "--block-url", "reddit.com", "--no-adblock"])
        // v0.6: Pax Max (image blur) is opt-in.
        XCTAssertEqual(ProfileGenerator.selfLockArguments(script: script, out: out, filter: .family,
                                                          imageBlur: true).last, "--image-blur")
    }

    // MARK: v0.8.0 local escrow

    func makeLocalLockdown(_ world: LockdownWorld, wait: Int = 24 * 3600) -> MacLockdown {
        let escrow = EscrowClient(baseURL: URL(string: "http://pax.test/")!, token: nil)
        return MacLockdown(userName: "alex", escrow: escrow, plain: WorldPlainRunner(world: world),
                           makeRoot: { user, pw in LocalSafeRunner(world: world, who: user, password: pw) },
                           verifyRetryDelayNanos: 1_000_000, escrowMode: .local, localWaitSeconds: wait)
    }

    func localPaths() -> MacLockdownPaths {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pax-lockdown-\(UUID().uuidString)")
        return MacLockdownPaths(guardSource: URL(fileURLWithPath: "/R/guard"),
                                guardInstallScript: URL(fileURLWithPath: "/R/guard/pax-guard-install.sh"),
                                configFile: dir.appendingPathComponent("config.json"),
                                profileFile: dir.appendingPathComponent("Pax.mobileconfig"))
    }

    func testLocalEscrowStoresKeyOnThisMacNoServer() async throws {
        let world = LockdownWorld()
        let p = localPaths()
        let outcome = try await makeLocalLockdown(world).protectThisMac(
            password: world.userPassword, deviceName: "Mac", paths: p,
            profileIdentifier: "org.paxpeace.pax.macos-selflock.test", writeConfig: { _, token in
                XCTAssertEqual(token, "")            // no guard token: pax-guard holds the key itself
            },
            waitForProfileApproval: { world.lock.lock(); world.profileInstalled = true; world.lock.unlock(); return true },
            progress: { _ in })
        XCTAssertEqual(outcome.deviceID, "local")
        let deposit = index(world, "local_escrow.py deposit")!
        let line = world.log[deposit]
        XCTAssertTrue(line.hasPrefix("root(alex) /usr/bin/python3 -I /R/guard/local_escrow.py deposit --secret-file "))
        XCTAssertTrue(line.contains("--wait-seconds 86400 --reset"))
        XCTAssertFalse(line.contains(world.paxadminPassword ?? "never"))       // never in argv
        XCTAssertEqual(world.safe, world.paxadminPassword)
        XCTAssertLessThan(index(world, "-authonly paxadmin")!, deposit)
        XCTAssertLessThan(deposit, index(world, "/usr/bin/open")!)
        // the secret file is gone afterwards
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: p.configFile.deletingLastPathComponent().appendingPathComponent("pax-escrow-secret").path))
    }

    func testLocalEscrowBadReceiptRollsBackAndEmptiesSafe() async {
        let world = LockdownWorld()
        world.safeLies = true
        do {
            _ = try await makeLocalLockdown(world).protectThisMac(
                password: world.userPassword, deviceName: "Mac", paths: localPaths(), profileIdentifier: "x",
                writeConfig: { _, _ in }, waitForProfileApproval: { true }, progress: { _ in })
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-ESCROW-003")
        }
        XCTAssertNotNil(index(world, "/bin/rm -rf /Library/PaxGuard/escrow"))
        XCTAssertNil(index(world, "-o edit -d alex"))                         // never demoted
        XCTAssertFalse(world.admins.contains("paxadmin"))
    }

    func testMDMEnrolledIsAWarningAndKeyRotationNoticeOnlyWhenLocal() async throws {
        let world = LockdownWorld()
        var pre = try await makeLocalLockdown(world).preflight(password: world.userPassword)
        XCTAssertTrue(pre.warnings[0].contains("new recovery key"))
        XCTAssertFalse(pre.mdmEnrolled)
        world.enrollment = "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n"
        pre = try await makeLocalLockdown(world).preflight(password: world.userPassword)
        XCTAssertTrue(pre.ok && pre.mdmEnrolled)
        XCTAssertTrue(pre.warnings.joined().contains("managed by an organisation"))
        XCTAssertTrue(pre.warnings[0].contains("Save your FileVault recovery key"))   // not rotated when managed
        XCTAssertTrue(MacLockdownParse.mdmEnrolled("Enrolled via DEP: Yes\nMDM enrollment: Yes"))
        XCTAssertFalse(MacLockdownParse.mdmEnrolled("Enrolled via DEP: No\nMDM enrollment: No"))
    }
}

/// Root runner that also plays pax-guard's local safe.
struct LocalSafeRunner: PrivilegedRunner {
    let world: LockdownWorld
    let who: String
    let password: String
    func runAsRoot(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult {
        if arguments.count > 2, arguments[1].hasSuffix("local_escrow.py"), arguments[2] == "deposit" {
            world.record("root(\(who))", executable, arguments)
            let file = arguments[arguments.firstIndex(of: "--secret-file")! + 1]
            let secret = (try? String(contentsOfFile: file, encoding: .utf8)) ?? ""
            world.lock.lock(); defer { world.lock.unlock() }
            world.safe = secret
            let sha = world.safeLies ? String(repeating: "0", count: 64) : SHA256Hex.hash(Data(secret.utf8))
            return CommandResult(exitCode: 0, stdout: Data("{\"stored\": \"paxadmin\", \"sha256\": \"\(sha)\"}\n".utf8),
                                 stderr: Data())
        }
        return try await WorldRootRunner(world: world, who: who, password: password)
            .runAsRoot(executable, arguments, stdin: stdin)
    }
}
