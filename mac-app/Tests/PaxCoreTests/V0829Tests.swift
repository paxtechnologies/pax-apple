// SPDX-License-Identifier: GPL-3.0-only
import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import PaxCore

/// v0.8.29: removing Pax and setting it up again. macOS (seen on 26.6) can keep the
/// paxadmin record: `sysadminctl -deleteUser` only takes it out of the admin group and
/// still exits 0, and `dscl . -delete` fails. Set-up used to stop with PAX-MAC-010.
/// Now removal tries every route in one root shell, set-up deletes a leftover or
/// reuses it with a new password, and anything that still fails says why.
final class V0829Tests: XCTestCase {
    let paths = MacLockdownPaths(guardSource: URL(fileURLWithPath: "/R/guard"),
                                 guardInstallScript: URL(fileURLWithPath: "/R/guard/pax-guard-install.sh"),
                                 configFile: URL(fileURLWithPath: "/tmp/p/config.json"),
                                 profileFile: URL(fileURLWithPath: "/tmp/p/Pax.mobileconfig"))
    let ident = "org.paxpeace.pax.macos-selflock.test"

    func makeLockdown(_ world: LockdownWorld) -> MacLockdown {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [FakeEscrowProtocol.self]
        FakeEscrowProtocol.fail = false
        FakeEscrowProtocol.storedPassword = nil
        let escrow = EscrowClient(baseURL: URL(string: "http://pax.test/")!, token: "acct",
                                  session: URLSession(configuration: cfg))
        return MacLockdown(userName: "alex", escrow: escrow, plain: WorldPlainRunner(world: world),
                           makeRoot: { user, pw in WorldRootRunner(world: world, who: user, password: pw) },
                           verifyRetryDelayNanos: 1_000_000)
    }

    func protect(_ l: MacLockdown, _ world: LockdownWorld) async throws -> MacLockdownOutcome {
        try await l.protectThisMac(
            password: world.userPassword, deviceName: "Alex's Mac", paths: paths, profileIdentifier: ident,
            writeConfig: { _, _ in },
            waitForProfileApproval: { world.lock.lock(); world.profileInstalled = true; world.lock.unlock(); return true },
            progress: { _ in })
    }

    func index(_ world: LockdownWorld, _ needle: String) -> Int? { world.log.firstIndex { $0.contains(needle) } }
    func recordExists(_ world: LockdownWorld) -> Bool { world.admins.contains("paxadmin") || world.leftoverPaxadmin }

    /// The reported Mac: a non-admin paxadmin macOS won't delete, left by an earlier removal.
    func reportedMac() -> LockdownWorld {
        let world = LockdownWorld()
        world.leftoverPaxadmin = true
        world.undeletablePaxadmin = true
        return world
    }

    // MARK: Set-up over a leftover

    func testUndeletableLeftoverIsReusedWithANewPassword() async throws {
        let world = reportedMac()
        let outcome = try await protect(makeLockdown(world), world)
        XCTAssertTrue(outcome.userDemoted)
        XCTAssertEqual(world.admins.filter { $0 != "root" }, ["paxadmin"])
        // Delete was tried first, then the password reset with the user's credentials.
        let delete = index(world, "-deleteUser paxadmin -adminUser alex")!
        let reset = index(world, "-resetPasswordFor paxadmin -newPassword ")!
        XCTAssertLessThan(delete, reset)
        XCTAssertTrue(world.log[reset].hasPrefix("root(alex)"))
        XCTAssertTrue(world.log[reset].hasSuffix("-adminUser alex -adminPassword \(world.userPassword)"))
        XCTAssertNil(index(world, "-addUser paxadmin"), "a reused account isn't created again")
        // Made an administrator, hidden, then the usual token / verify / escrow steps.
        let promote = index(world, "-o edit -a paxadmin -t user admin")!
        let hide = index(world, "-create /Users/paxadmin IsHidden 1")!
        let token = index(world, "-secureTokenOn paxadmin")!
        XCTAssertLessThan(reset, promote)
        XCTAssertLessThan(promote, hide)
        XCTAssertLessThan(hide, token)
        XCTAssertEqual(world.paxadminPassword?.count, 32)
        XCTAssertEqual(FakeEscrowProtocol.storedPassword, world.paxadminPassword)
    }

    func testResetThatSilentlyDoesNothingFallsBackToDsclPasswd() async throws {
        let world = reportedMac()
        world.resetPasswordFails = true
        _ = try await protect(makeLockdown(world), world)
        let reset = index(world, "-resetPasswordFor paxadmin")!
        let direct = index(world, "-passwd /Users/paxadmin")!
        XCTAssertLessThan(reset, direct)
        XCTAssertEqual(FakeEscrowProtocol.storedPassword, world.paxadminPassword)
    }

    func testReusedLeftoverRollsBackToAStandardAccountAndUserKeepsAdmin() async {
        let world = reportedMac()
        world.failAt = "pax-guard-install.sh"
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {
            guard case .rolledBack(let step, _) = error as? MacLockdownError else { return XCTFail("\(error)") }
            XCTAssertEqual(step, .installGuard)
        }
        XCTAssertTrue(world.admins.contains("alex"), "the user must stay an administrator")
        XCTAssertFalse(world.admins.contains("paxadmin"), "the leftover must not keep admin rights")
        XCTAssertTrue(recordExists(world), "macOS still keeps it (as before the set-up)")
        XCTAssertFalse(world.profileInstalled)
    }

    func testOldAdminPaxadminNoLongerBlocksAndIsDeleted() async throws {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "paxadmin"]
        world.paxadminPassword = "an old released password"
        let outcome = try await protect(makeLockdown(world), world)
        XCTAssertTrue(outcome.userDemoted)
        XCTAssertNotNil(index(world, "-addUser paxadmin"), "deletable, so it's created fresh")
        XCTAssertEqual(FakeEscrowProtocol.storedPassword, world.paxadminPassword)
        XCTAssertNotEqual(world.paxadminPassword, "an old released password")
    }

    func testOldAdminPaxadminThatWontGoIsReusedAndRollbackTakesAdminAway() async {
        let world = LockdownWorld()
        world.admins = ["root", "alex", "paxadmin"]
        world.undeletablePaxadmin = true
        world.failAt = "-o edit -d alex"
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {}
        XCTAssertTrue(world.admins.contains("alex"))
        XCTAssertFalse(world.admins.contains("paxadmin"))
    }

    func testNeitherDeletableNorReusableStopsWithMAC004AndTheReasons() async {
        let world = reportedMac()
        world.resetPasswordFails = true
        world.dsclPasswdFails = true
        do { _ = try await protect(makeLockdown(world), world); XCTFail("should throw") } catch {
            guard case .rolledBack(let step, let why) = error as? MacLockdownError else { return XCTFail("\(error)") }
            XCTAssertEqual(step, .createAdmin)
            XCTAssertTrue(why.contains("PAX-MAC-004"))
            XCTAssertTrue(why.contains("sysadminctl -deleteUser: exit 0"))
            XCTAssertTrue(why.contains("dscl -delete: exit 1 (<main> delete status: eDSPermissionError)"))
            XCTAssertTrue(why.contains("sysadminctl -deleteUser paxadmin -adminUser alex -adminPassword -"))
            XCTAssertFalse(why.contains(world.userPassword), "no password in the details")
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-MAC-004")
        }
        XCTAssertNil(FakeEscrowProtocol.storedPassword)
        XCTAssertTrue(world.admins.contains("alex"))
        XCTAssertFalse(world.admins.contains("paxadmin"))
        XCTAssertNil(index(world, "-o edit -d alex"))
    }

    func testDirectoryLagAfterDeleteIsWaitedOut() async throws {
        let world = LockdownWorld()
        world.leftoverPaxadmin = true
        world.lingeringReads = 2
        _ = try await protect(makeLockdown(world), world)
        XCTAssertNil(index(world, "-resetPasswordFor"), "the record went; it only looked present for a moment")
        XCTAssertNotNil(index(world, "-addUser paxadmin"))
    }

    // MARK: Removal

    func testRemovalRunsEveryDeleteRouteInOneRootShell() async throws {
        let world = LockdownWorld()
        let l = makeLockdown(world)
        _ = try await protect(l, world)
        world.log.removeAll()
        let done = try await l.removePax(paxAdminPassword: world.paxadminPassword!, paths: paths, profileIdentifier: ident)
        XCTAssertEqual(done.last, "Pax's administrator account deleted")
        let shell = world.log.first { $0.hasPrefix("root(paxadmin) /bin/sh -c") }!
        XCTAssertTrue(shell.contains("/usr/sbin/sysadminctl -deleteUser paxadmin"))
        XCTAssertTrue(shell.contains("/usr/bin/dscl . -delete /Users/paxadmin"))
        XCTAssertFalse(recordExists(world))
        XCTAssertTrue(world.admins.contains("alex"))
    }

    func testRemovalWhenMacOSKeepsPaxadminThenSetUpAgainWorks() async throws {
        let world = LockdownWorld()
        let first = makeLockdown(world)
        _ = try await protect(first, world)
        let released = world.paxadminPassword!
        world.undeletablePaxadmin = true
        let done = try await first.removePax(paxAdminPassword: released, paths: paths, profileIdentifier: ident)
        XCTAssertTrue(done.contains { $0.contains("took away its admin rights") })
        XCTAssertFalse(done.joined().contains(released), "no password in the log")
        XCTAssertTrue(world.admins.contains("alex"))
        XCTAssertFalse(world.admins.contains("paxadmin"))
        XCTAssertTrue(recordExists(world))
        // The report: Pax removed, installed again, Protect this Mac.
        world.log.removeAll()
        let outcome = try await protect(makeLockdown(world), world)
        XCTAssertTrue(outcome.userDemoted)
        XCTAssertNotNil(index(world, "-resetPasswordFor paxadmin"))
        XCTAssertEqual(FakeEscrowProtocol.storedPassword, world.paxadminPassword)
        XCTAssertNotEqual(world.paxadminPassword, released)
    }

    func testRemovalKeepsPaxadminUnlessTheUserIsProvenAdmin() async throws {
        let world = LockdownWorld()
        let l = makeLockdown(world)
        _ = try await protect(l, world)
        world.failAt = "checkmember -m alex admin"
        do {
            _ = try await l.removePax(paxAdminPassword: world.paxadminPassword!, paths: paths, profileIdentifier: ident)
            XCTFail("should throw")
        } catch {}
        XCTAssertTrue(world.admins.contains("paxadmin"), "never delete the only other way in")
        XCTAssertNil(index(world, "/bin/sh -c"))
        XCTAssertNil(index(world, "pax-uninstall-emergency.sh"))
    }

    func testOneShellScriptCarriesNoPassword() {
        let (exe, args) = MacLockdownCommands.deletePaxAdminInOneShell()
        XCTAssertEqual(exe, "/bin/sh")
        XCTAssertEqual(args.first, "-c")
        XCTAssertFalse(args[1].contains("-adminPassword"))
        XCTAssertTrue(args[1].hasSuffix("echo \"record gone\"; fi"))
    }
}
