// SPDX-License-Identifier: GPL-3.0-only
import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import PaxCore

/// v0.8.10: other administrator accounts (such as a rented Mac's rmsvc) no longer
/// stop Protect this Mac. Preflight lists them, the user agrees once ("Also make
/// these standard accounts", on by default), and Pax makes them standard as root,
/// verified, after pax-guard is running and before the user's own account. Any
/// failure rolls everything back, them included. Test mode is unchanged.
final class V0810Tests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("pax-v0810-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    var paths: MacLockdownPaths {
        MacLockdownPaths(guardSource: URL(fileURLWithPath: "/R/guard"),
                         guardInstallScript: URL(fileURLWithPath: "/R/guard/pax-guard-install.sh"),
                         configFile: dir.appendingPathComponent("config.json"),
                         profileFile: URL(fileURLWithPath: "/tmp/p/Pax.mobileconfig"))
    }

    func lockdown(_ world: LockdownWorld, allowExtraAdmins: Bool = false) -> MacLockdown {
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

    func protect(_ l: MacLockdown, _ world: LockdownWorld, others: [String]) async throws -> MacLockdownOutcome {
        let p = paths
        return try await l.protectThisMac(
            password: world.userPassword, deviceName: "Rented Mac", paths: p,
            profileIdentifier: "org.paxpeace.pax.macos-selflock.test",
            standardAccounts: others,
            writeConfig: { path, _ in
                try Data(#"{"user":"alex","mdm_managed":true}"#.utf8).write(to: URL(fileURLWithPath: path))
            },
            waitForProfileApproval: {
                world.lock.lock(); world.profileInstalled = true; world.lock.unlock()
                return true
            },
            progress: { _ in })
    }

    func index(_ world: LockdownWorld, _ needle: String) -> Int? { world.log.firstIndex { $0.contains(needle) } }

    // MARK: Preflight

    func testPreflightListsOtherAdminsAndOnlyBlocksWithoutTheOK() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc"]
        let agreed = try await lockdown(world).preflight(password: world.userPassword, demoteOtherAdmins: true)
        XCTAssertTrue(agreed.ok)
        XCTAssertEqual(agreed.otherAdmins, ["rmsvc"])
        let declined = try await lockdown(world).preflight(password: world.userPassword)
        XCTAssertFalse(declined.ok)
        XCTAssertEqual(declined.otherAdmins, ["rmsvc"])
        XCTAssertEqual(PaxErrorClassifier.preflightCode(problems: declined.problems), "PAX-MAC-003")
        XCTAssertFalse(declined.problems.joined().contains("System Settings"))
        XCTAssertFalse(declined.problems.joined().contains("Terminal"))
        // Preflight only looks.
        XCTAssertNil(index(world, "dseditgroup -o edit"))
    }

    func testUnsafeNameStillBlocks() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "-weird"]
        let pre = try await lockdown(world).preflight(password: world.userPassword, demoteOtherAdmins: true)
        XCTAssertFalse(pre.ok)
        XCTAssertEqual(PaxErrorClassifier.preflightCode(problems: pre.problems), "PAX-MAC-003")
        XCTAssertTrue(MacLockdownParse.isSafeShortName("rmsvc"))
        XCTAssertTrue(MacLockdownParse.isSafeShortName("john.smith-2"))
        for bad in ["-weird", "_svc", "a b", "", "x;y", "é", String(repeating: "a", count: 65)] {
            XCTAssertFalse(MacLockdownParse.isSafeShortName(bad), bad)
        }
    }

    func testManagedMacKeepsAnInfoLineAndIsNotSpecialCased() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc"]
        world.enrollment = "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n"
        let pre = try await lockdown(world).preflight(password: world.userPassword, demoteOtherAdmins: true)
        XCTAssertTrue(pre.ok && pre.mdmEnrolled)
        XCTAssertEqual(pre.otherAdmins, ["rmsvc"])   // listed and made standard like any other
        XCTAssertTrue(pre.warnings.joined().contains("management server could still"))
    }

    func testTestModeUnchanged() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc"]
        let pre = try await lockdown(world, allowExtraAdmins: true).preflight(password: world.userPassword,
                                                                            demoteOtherAdmins: true)
        XCTAssertTrue(pre.ok)
        XCTAssertEqual(pre.otherAdmins, [])
        XCTAssertTrue(pre.warnings.joined().contains("Test mode: rmsvc"))
        _ = try await protect(lockdown(world, allowExtraAdmins: true), world, others: [])
        XCTAssertTrue(world.admins.contains("rmsvc"))
        XCTAssertNil(index(world, "-d rmsvc"))
    }

    // MARK: Set-up

    func testOtherAdminsMadeStandardAfterGuardBeforeUser() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc", "spare"]
        let outcome = try await protect(lockdown(world), world, others: ["rmsvc", "spare"])
        XCTAssertTrue(outcome.userDemoted)
        XCTAssertEqual(world.admins.filter { $0 != "root" }, ["paxadmin"])
        let guardInstall = index(world, "pax-guard-install.sh")!
        let rm = index(world, "-o edit -d rmsvc -t user admin")!
        let sp = index(world, "-o edit -d spare -t user admin")!
        let rmCheck = index(world, "checkmember -m rmsvc")!
        let user = index(world, "-o edit -d alex")!
        XCTAssertLessThan(guardInstall, rm)
        XCTAssertLessThan(rm, rmCheck)
        XCTAssertLessThan(sp, user)
        XCTAssertTrue(world.log[rm].hasPrefix("root(alex)"))
        // Recorded for pax-guard (keeps them standard) and its uninstaller (restores them).
        let cfg = try JSONSerialization.jsonObject(with: Data(contentsOf: paths.configFile)) as? [String: Any]
        XCTAssertEqual(cfg?["demoted_admins"] as? [String], ["rmsvc", "spare"])
        XCTAssertEqual(cfg?["mdm_managed"] as? Bool, true)   // the app's keys are kept
        let perms = try FileManager.default.attributesOfItem(atPath: paths.configFile.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }

    func testFailedOtherDemotionRollsEverythingBack() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc", "spare"]
        world.failAt = "-d spare"
        do {
            _ = try await protect(lockdown(world), world, others: ["rmsvc", "spare"])
            XCTFail("should throw")
        } catch let MacLockdownError.rolledBack(step, why) {
            XCTAssertEqual(step, .demoteOthers)
            XCTAssertTrue(why.contains("spare"))
            XCTAssertEqual(PaxErrorClassifier.classify(MacLockdownError.rolledBack(step, why)).code, "PAX-MAC-003")
        }
        XCTAssertEqual(Set(world.admins), ["root", "alex", "rmsvc", "spare"])   // nobody left demoted
        XCTAssertNil(index(world, "-o edit -d alex"))                         // user never touched
        XCTAssertNotNil(index(world, "-o edit -a rmsvc"))
        XCTAssertFalse(world.profileInstalled)
    }

    func testOtherStillAdminAfterDemotionFailsClosed() async throws {
        // dseditgroup "succeeds" but the account is still an admin: never fail open.
        let world = LockdownWorld()
        world.stickyAdmins = ["rmsvc"]
        world.admins = ["root", "alex", "rmsvc"]
        do {
            _ = try await protect(lockdown(world), world, others: ["rmsvc"])
            XCTFail("should throw")
        } catch let MacLockdownError.rolledBack(step, _) {
            XCTAssertEqual(step, .demoteOthers)
        }
        XCTAssertTrue(world.admins.contains("alex"))
        XCTAssertFalse(world.admins.contains("paxadmin"))
    }

    func testUserDemotionFailureAlsoRestoresOthers() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc"]
        world.failAt = "-d alex"
        do { _ = try await protect(lockdown(world), world, others: ["rmsvc"]); XCTFail("should throw") } catch {}
        XCTAssertEqual(Set(world.admins), ["root", "alex", "rmsvc"])
    }

    func testAdminThatAppearedAfterTheCheckBlocksBeforeAnyChange() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "rmsvc", "newone"]
        do {
            _ = try await protect(lockdown(world), world, others: ["rmsvc"])
            XCTFail("should throw")
        } catch let MacLockdownError.preflightFailed(problems) {
            XCTAssertTrue(problems.joined().contains("newone"))
            XCTAssertEqual(PaxErrorClassifier.preflightCode(problems: problems), "PAX-MAC-003")
        }
        XCTAssertNil(index(world, "-addUser"))
        XCTAssertNil(index(world, "dseditgroup -o edit"))
    }

    func testNoOtherAdminsKeepsConfigAndStepsAsBefore() async throws {
        let world = LockdownWorld()
        _ = try await protect(lockdown(world), world, others: [])
        let cfg = try JSONSerialization.jsonObject(with: Data(contentsOf: paths.configFile)) as? [String: Any]
        XCTAssertNil(cfg?["demoted_admins"])
        let c = GuardConfigFile(server_url: "s", guard_token: "", profile_identifier: "p", user: "alex",
                                resolver_host: "h")
        let obj = try JSONSerialization.jsonObject(with: c.json()) as? [String: Any]
        XCTAssertNil(obj?["demoted_admins"])
    }

    func testErrorWording() {
        let e = MacLockdownError.otherAdminFailed("rmsvc", "eDSPermissionError")
        XCTAssertTrue(e.errorDescription!.contains("rmsvc"))
        XCTAssertEqual(PaxErrorClassifier.classify(e).code, "PAX-MAC-003")
        let info = PaxErrorCatalog.info("PAX-MAC-003")
        XCTAssertTrue(info.action.contains("Also make these standard accounts"))
        XCTAssertFalse(info.action.contains("System Settings"))
    }
}
