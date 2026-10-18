// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// "Protect this Mac" (v0.4): turn the everyday account into a Standard user and
/// put the only administrator password in Pax's escrow, behind the wait timer.
///
/// The order is the whole safety story, so it lives here and is unit-tested with
/// a mock command runner (`MacLockdownTests`):
///
///   1. preflight  — FileVault state, there is exactly one admin and it is this
///                   user, the current password works, backup reminder
///   2. create     — hidden `paxadmin` with a random 32-character password
///   3. token      — SecureToken for paxadmin (so FileVault and updates still work)
///   4. verify     — `dscl . -authonly paxadmin <password>` must succeed
///   5. escrow     — send the password to the Pax server and read the device back
///   6. install    — profile + pax-guard (both verified)
///   7. others     — v0.8.10: any other administrators the user agreed to make
///                   standard ("Also make these standard accounts"), each verified
///   8. demote     — only now does the everyday account become Standard, verified
///
/// If any step fails, `rollback` undoes what was done (deletes paxadmin, removes
/// the daemon and the profile) and the user keeps their admin rights. The user is
/// never left with no administrator, and nothing is locked before the password
/// the server holds is known to work.
public enum MacLockdownStep: String, Sendable, CaseIterable {
    case preflight, createAdmin, secureToken, verifyAdmin, escrow, installProfile,
         installGuard, demoteOthers, demoteUser, verifyDemotion, done
}

public struct MacLockdownProgress: Sendable, Equatable {
    public let step: MacLockdownStep
    public let message: String
    public let finished: Bool
}

public enum MacLockdownError: Error, LocalizedError, Equatable {
    case preflightFailed([String])
    case wrongPassword
    case createAdminFailed(String)
    case secureTokenFailed(String)
    case verifyAdminFailed(String)
    case escrowFailed(String)
    case profileInstallFailed(String)
    case guardInstallFailed(String)
    case demotionFailed(String)
    /// v0.8.10: another administrator couldn't be made standard (or didn't stay so).
    case otherAdminFailed(String, String)
    case stillAdmin
    case rolledBack(MacLockdownStep, String)

    public var errorDescription: String? {
        switch self {
        case .preflightFailed(let problems):
            return "Pax can't protect this Mac yet:\n• " + problems.joined(separator: "\n• ")
        case .wrongPassword:
            return "That isn't the password for this account. Pax has changed nothing."
        case .createAdminFailed(let m): return "Pax couldn't create its administrator account: \(m)"
        case .secureTokenFailed(let m):
            return "Pax couldn't give its administrator a SecureToken, which FileVault needs: \(m)"
        case .verifyAdminFailed(let m):
            return "The new administrator password didn't work when Pax checked it. Nothing was locked."
                + (m.isEmpty ? "" : " (\(m))")
        case .escrowFailed(let m): return "Pax couldn't store the key safely: \(m)"
        case .profileInstallFailed(let m): return "The Pax profile didn't install: \(m)"
        case .guardInstallFailed(let m): return "The Pax background guard didn't install: \(m)"
        case .demotionFailed(let m): return "Pax couldn't make your account a standard user: \(m)"
        case .otherAdminFailed(let user, let m):
            return "Pax couldn't make the other administrator account \(user) a standard account"
                + (m.isEmpty ? "." : ": \(m)")
        case .stillAdmin: return "Your account is still an administrator, so Pax hasn't locked anything."
        case .rolledBack(let step, let why):
            return "Pax stopped at \(step.rawValue) and undid everything: \(why). "
                + "Your account is still an administrator."
        }
    }
}

/// What the preflight found. `ok` means Pax may continue.
public struct MacPreflight: Sendable, Equatable {
    public let userName: String
    public let fileVaultOn: Bool
    public let admins: [String]
    public let userIsAdmin: Bool
    public let paxadminExists: Bool
    public let passwordVerified: Bool
    public let problems: [String]
    public let warnings: [String]
    /// v0.8.0: `profiles status -type enrollment` shows another organisation's MDM.
    public var mdmEnrolled: Bool = false
    /// v0.8.10: other administrators (not this user, not paxadmin). With the user's
    /// OK ("Also make these standard accounts") Pax makes them standard too.
    public var otherAdmins: [String] = []

    public var ok: Bool { problems.isEmpty }
}

public let paxAdminUser = "paxadmin"
public let paxAdminRealName = "Pax Administrator"

/// Random password for paxadmin: 32 characters from an alphabet without
/// look-alikes, so it can be typed from the screen when it's released.
/// 32 × log2(57) ≈ 186 bits.
public func generateAdminPassword(length: Int = 32) -> String {
    let alphabet = Array("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
    let limit = 256 - (256 % alphabet.count)   // rejection sampling: no modulo bias
    var out = ""
    out.reserveCapacity(length)
    while out.count < length {
        for byte in secureRandomBytes(64) where Int(byte) < limit && out.count < length {
            out.append(alphabet[Int(byte) % alphabet.count])
        }
    }
    return out
}

/// Cryptographically secure bytes from the kernel (/dev/urandom; Foundation-only
/// so the tests run on Linux too). Falls back to the system CSPRNG.
func secureRandomBytes(_ count: Int) -> [UInt8] {
    if let fh = FileHandle(forReadingAtPath: "/dev/urandom") {
        defer { try? fh.close() }
        if let data = try? fh.read(upToCount: count), data.count == count { return [UInt8](data) }
    }
    var g = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: 0...255, using: &g) }
}

/// Runs a command as root. Tests use a mock.
public protocol PrivilegedRunner: Sendable {
    /// `arguments` are passed to the tool as separate, quoted words (never a raw shell string).
    func runAsRoot(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult
}

/// Root via AppleScript's `do shell script … user name … password … with
/// administrator privileges`, with credentials Pax already holds (the user's
/// own password during set-up, paxadmin's released password at removal), so
/// macOS doesn't prompt once per step. The script goes to osascript on stdin,
/// so the password is never in a process's arguments (`ps`). Note: the
/// sysadminctl calls themselves still take passwords as arguments for the
/// second they run; see README "Risks".
public struct OSAScriptPrivilegedRunner: PrivilegedRunner {
    public let runner: CommandRunner
    public let user: String
    public let password: String

    public init(user: String, password: String, runner: CommandRunner = ProcessRunner()) {
        self.user = user
        self.password = password
        self.runner = runner
    }

    /// Quoting for the shell that `do shell script` uses: single-quote every
    /// word and escape embedded quotes, so a password or path can't break out.
    public static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// AppleScript string literal.
    public static func appleScriptString(_ value: String) -> String {
        "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    public static func appleScript(executable: String, arguments: [String], user: String, password: String) -> String {
        let command = ([executable] + arguments).map(shellQuote).joined(separator: " ") + " 2>&1"
        return "do shell script \(appleScriptString(command)) user name \(appleScriptString(user)) "
            + "password \(appleScriptString(password)) with administrator privileges"
    }

    public func runAsRoot(_ executable: String, _ arguments: [String], stdin: String?) async throws -> CommandResult {
        let script = Self.appleScript(executable: executable, arguments: arguments, user: user, password: password)
        return try await runner.run(URL(fileURLWithPath: "/usr/bin/osascript"), arguments: ["-"],
                                    stdin: Data(script.utf8))
    }
}

/// Everything the lockdown runs, as argument lists, so the tests can pin them.
public enum MacLockdownCommands {
    public static let dscl = "/usr/bin/dscl"
    public static let dseditgroup = "/usr/sbin/dseditgroup"
    public static let sysadminctl = "/usr/sbin/sysadminctl"
    public static let fdesetup = "/usr/bin/fdesetup"
    public static let profiles = "/usr/bin/profiles"
    public static let installedUninstaller = "/Library/PaxGuard/bin/pax-uninstall-emergency.sh"

    public static func authOnly(user: String, password: String) -> (String, [String]) {
        (dscl, [".", "-authonly", user, password])
    }

    public static func adminMembers() -> (String, [String]) {
        (dscl, [".", "-read", "/Groups/admin", "GroupMembership"])
    }

    public static func isMember(user: String) -> (String, [String]) {
        (dseditgroup, ["-o", "checkmember", "-m", user, "admin"])
    }

    public static func fileVaultStatus() -> (String, [String]) { (fdesetup, ["status"]) }

    public static func createPaxAdmin(password: String, adminUser: String, adminPassword: String) -> (String, [String]) {
        (sysadminctl, ["-addUser", paxAdminUser, "-fullName", paxAdminRealName,
                       "-password", password, "-admin",
                       "-adminUser", adminUser, "-adminPassword", adminPassword])
    }

    /// Exit 0 when a paxadmin user record exists (admin or not).
    public static func readPaxAdminRecord() -> (String, [String]) {
        (dscl, [".", "-read", "/Users/\(paxAdminUser)", "UniqueID"])
    }

    /// Last resort when `sysadminctl -deleteUser` leaves the record behind
    /// (it can exit 0 without deleting anything).
    public static func deletePaxAdminRecord() -> (String, [String]) {
        (dscl, [".", "-delete", "/Users/\(paxAdminUser)"])
    }

    public static func removePaxAdminHome() -> (String, [String]) {
        ("/bin/rm", ["-rf", "/Users/\(paxAdminUser)"])
    }

    public static func hidePaxAdmin() -> (String, [String]) {
        (dscl, [".", "-create", "/Users/\(paxAdminUser)", "IsHidden", "1"])
    }

    public static func secureTokenOn(password: String, adminUser: String, adminPassword: String) -> (String, [String]) {
        (sysadminctl, ["-secureTokenOn", paxAdminUser, "-password", password,
                       "-adminUser", adminUser, "-adminPassword", adminPassword])
    }

    public static func secureTokenStatus() -> (String, [String]) {
        (sysadminctl, ["-secureTokenStatus", paxAdminUser])
    }

    /// Deleting a SecureToken user can need another token holder's credentials.
    public static func deletePaxAdmin(adminUser: String? = nil, adminPassword: String? = nil) -> (String, [String]) {
        var args = ["-deleteUser", paxAdminUser]
        if let adminUser, let adminPassword { args += ["-adminUser", adminUser, "-adminPassword", adminPassword] }
        return (sysadminctl, args)
    }

    public static func demote(user: String) -> (String, [String]) {
        (dseditgroup, ["-o", "edit", "-d", user, "-t", "user", "admin"])
    }

    public static func promote(user: String) -> (String, [String]) {
        (dseditgroup, ["-o", "edit", "-a", user, "-t", "user", "admin"])
    }

    /// macOS 11+ won't install a profile from the command line: opening the
    /// file hands it to System Settings, where the user approves it (as an admin).
    public static func openProfile(path: String) -> (String, [String]) {
        ("/usr/bin/open", [path])
    }

    public static func openDeviceManagementSettings(
        _ place: SystemSettingsPlace = .current) -> (String, [String]) {
        ("/usr/bin/open", [place.profilesPaneURL])   // v0.8.20: Monterey's pane differs
    }

    public static func listProfiles() -> (String, [String]) {
        (profiles, ["show", "-type", "configuration"])
    }

    public static func removeProfile(identifier: String) -> (String, [String]) {
        (profiles, ["remove", "-identifier", identifier])
    }

    public static func installGuard(script: String, source: String, config: String, profile: String) -> (String, [String]) {
        ("/bin/bash", [script, "--src", source, "--config", config, "--profile", profile])
    }

    /// v0.8.0 local escrow: root stores paxadmin's password in pax-guard's safe
    /// (/Library/PaxGuard/escrow, root 0700), reading it from a 0600 file it then deletes.
    /// v0.8.6: on the Python inside Pax.app (`Resources/device/python`, `-I -B`, so nothing
    /// is written into the signed app), so set-up needs no Command Line Tools; a build
    /// without it (`swift run` from the repo) uses /usr/bin/python3 as before.
    public static func localEscrowDeposit(guardSource: String, secretFile: String, waitSeconds: Int,
                                          supportRelease: Bool = VerifiedSupportRelease.setUpDefault,
                                          trial: Bool = TrialDay.setUpDefault,
                                          isExecutable: (String) -> Bool = {
                                              FileManager.default.isExecutableFile(atPath: $0) }) -> (String, [String]) {
        let bundled = URL(fileURLWithPath: guardSource).deletingLastPathComponent()
            .appendingPathComponent(BundledHelper.relativePython).path
        let (python, flags) = isExecutable(bundled) ? (bundled, ["-I", "-B"]) : ("/usr/bin/python3", ["-I"])
        return (python, flags + [guardSource + "/local_escrow.py", "deposit", "--secret-file", secretFile,
                                 // v0.8.15: the set-up choice for verified support release.
                                 "--support-release", supportRelease ? "on" : "off",
                                 // v0.8.18: ask for a trial day (pax-guard grants it only on this Mac's first day).
                                 "--trial", trial ? "on" : "off",
                                 "--wait-seconds", String(waitSeconds), "--reset"])
    }

    public static func removeLocalEscrow() -> (String, [String]) {
        ("/bin/rm", ["-rf", "/Library/PaxGuard/escrow"])
    }

    /// v0.8.0: is another organisation managing this Mac?
    public static func enrollmentStatus() -> (String, [String]) {
        (profiles, ["status", "-type", "enrollment"])
    }

    public static func uninstallGuard(script: String, user: String) -> (String, [String]) {
        ("/bin/bash", [script, "--user", user])
    }
}

/// Parsers (pure, unit-tested).
public enum MacLockdownParse {
    /// `dscl . -read /Groups/admin GroupMembership` →
    /// "GroupMembership: root alex paxadmin". Accounts below are service accounts.
    static let systemAccounts: Set<String> = ["root", "_mbsetupuser", "daemon", "nobody"]

    public static func adminUsers(_ output: String) -> [String] {
        guard let range = output.range(of: "GroupMembership:") else { return [] }
        return output[range.upperBound...]
            .split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" })
            .map(String.init)
            .filter { !systemAccounts.contains($0) && !$0.hasPrefix("_") }
    }

    /// `fdesetup status` → "FileVault is On." / "FileVault is Off."
    public static func fileVaultOn(_ output: String) -> Bool {
        output.lowercased().contains("filevault is on")
    }

    /// `sysadminctl -secureTokenStatus paxadmin` writes to stderr:
    /// "… Secure token is ENABLED for user paxadmin".
    public static func secureTokenEnabled(_ output: String) -> Bool {
        output.uppercased().contains("SECURE TOKEN IS ENABLED")
    }

    /// `dseditgroup -o checkmember` prints "yes alex is a member of admin" or
    /// "no alex is NOT a member of admin" (its exit status is not a yes/no).
    public static func isMemberYes(_ output: String) -> Bool {
        output.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("yes")
    }

    /// `profiles status -type enrollment`: "MDM enrollment: Yes (User Approved)" or
    /// "Enrolled via DEP: Yes" means another organisation manages the Mac.
    public static func mdmEnrolled(_ output: String) -> Bool {
        for line in output.split(whereSeparator: \.isNewline) {
            let l = line.lowercased().trimmingCharacters(in: .whitespaces)
            if (l.hasPrefix("mdm enrollment:") || l.hasPrefix("enrolled via dep:")),
               l.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces).hasPrefix("yes") == true {
                return true
            }
        }
        return false
    }

    /// v0.8.10: a short name Pax will pass to dseditgroup (letters, digits, . _ -;
    /// not starting with "-" or "_"). Anything else blocks instead of being changed.
    public static func isSafeShortName(_ name: String) -> Bool {
        guard let first = name.unicodeScalars.first, name.count <= 64,
              CharacterSet.alphanumerics.contains(first), first.isASCII else { return false }
        return name.unicodeScalars.allSatisfy {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "._-".unicodeScalars.contains($0))
        }
    }

    public static func isMemberNo(_ output: String) -> Bool {
        let t = output.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return t.hasPrefix("no ") && t.contains("not a member")
    }
}

/// Paths the app hands the lockdown (bundled resources and temp files).
public struct MacLockdownPaths: Sendable {
    public let guardSource: URL        // Pax.app/Contents/Resources/guard
    public let guardInstallScript: URL // …/guard/scripts/pax-guard-install.sh
    public let configFile: URL         // JSON written 0600 in a private temp dir
    public let profileFile: URL        // generated .mobileconfig

    public init(guardSource: URL, guardInstallScript: URL, configFile: URL, profileFile: URL) {
        self.guardSource = guardSource
        self.guardInstallScript = guardInstallScript
        self.configFile = configFile
        self.profileFile = profileFile
    }
}

public struct MacLockdownOutcome: Sendable, Equatable {
    public let deviceID: String
    public let profileIdentifier: String
    public let userDemoted: Bool
}

public actor MacLockdown {
    let plain: CommandRunner
    var escrow: EscrowClient
    let userName: String
    /// Makes the root runner from a password (the user's during set-up,
    /// paxadmin's at removal). Injected so the tests can record every command.
    let makeRoot: @Sendable (_ user: String, _ password: String) -> PrivilegedRunner
    /// Testing only (`defaults write org.paxmobile.pax pax.testing.allowExtraAdmins -bool true`):
    /// lets Pax set up on a Mac with another admin, such as a rented cloud Mac's
    /// provider account. The wait means nothing then, so it's a warning, not a pass.
    let allowExtraAdmins: Bool
    private var root: PrivilegedRunner?
    private var userPassword: String?
    /// v0.8.0: where the key goes (local pax-guard safe by default in the app).
    let escrowMode: MacEscrowMode
    let localWaitSeconds: Int
    /// The local mode keeps the FileVault recovery key behind the wait too.
    let rotateRecoveryKey: Bool
    /// v0.8.15: the set-up choice "Allow verified support release" (on by default).
    let supportRelease: Bool
    /// v0.8.18: a new set-up asks for a trial day (whoever holds the key decides).
    let trialDay: Bool

    /// Steps already done, newest first, so rollback can undo them in order.
    private var completed: [MacLockdownStep] = []
    /// v0.8.10: the other administrators this set-up is making standard.
    private var pendingOthers: [String] = []
    private var demotedOthers: [String] = []

    public init(userName: String, escrow: EscrowClient, plain: CommandRunner = ProcessRunner(),
                allowExtraAdmins: Bool = false,
                makeRoot: @escaping @Sendable (String, String) -> PrivilegedRunner = { user, password in
                    OSAScriptPrivilegedRunner(user: user, password: password)
                },
                verifyRetryDelayNanos: UInt64 = 1_500_000_000,
                escrowMode: MacEscrowMode = .server, localWaitSeconds: Int = 72 * 3600,
                rotateRecoveryKey: Bool = true, supportRelease: Bool = VerifiedSupportRelease.setUpDefault,
                trialDay: Bool = TrialDay.setUpDefault) {
        self.supportRelease = supportRelease
        self.trialDay = trialDay
        self.escrowMode = escrowMode
        self.localWaitSeconds = localWaitSeconds
        self.rotateRecoveryKey = rotateRecoveryKey
        self.verifyRetryDelayNanos = verifyRetryDelayNanos
        self.userName = userName
        self.escrow = escrow
        self.plain = plain
        self.makeRoot = makeRoot
        self.allowExtraAdmins = allowExtraAdmins
    }

    private func asRoot(_ cmd: (String, [String])) async throws -> CommandResult {
        guard let root else { throw MacLockdownError.createAdminFailed("not authorised") }
        return try await root.runAsRoot(cmd.0, cmd.1, stdin: nil)
    }

    /// Delay between password checks (shortened in the tests).
    let verifyRetryDelayNanos: UInt64

    func paxAdminRecordExists() async throws -> Bool {
        let cmd = MacLockdownCommands.readPaxAdminRecord()
        return try await plain.run(URL(fileURLWithPath: cmd.0), arguments: cmd.1, stdin: nil).exitCode == 0
    }

    /// sysadminctl first (cleans up properly), then the raw record and home folder.
    func deletePaxAdminFully() async throws {
        let del = MacLockdownCommands.deletePaxAdmin(adminUser: userName, adminPassword: userPassword ?? "")
        _ = try await asRoot(del)
        if try await paxAdminRecordExists() {
            _ = try await asRoot(MacLockdownCommands.deletePaxAdminRecord())
        }
        _ = try await asRoot(MacLockdownCommands.removePaxAdminHome())
    }

    // MARK: Preflight

    /// `demoteOtherAdmins`: the user has agreed (the default on the set-up screen) to
    /// make any other administrators standard accounts. Without it they still block.
    public func preflight(password: String, demoteOtherAdmins: Bool = false) async throws -> MacPreflight {
        var problems: [String] = []
        var warnings: [String] = []

        let auth = MacLockdownCommands.authOnly(user: userName, password: password)
        let authResult = try await plain.run(URL(fileURLWithPath: auth.0), arguments: auth.1, stdin: nil)
        let passwordOK = authResult.exitCode == 0
        if !passwordOK {
            problems.append("That isn't the password for \(userName). Pax needs it to set this up.")
        }

        let adminsCmd = MacLockdownCommands.adminMembers()
        let adminsOut = try await plain.run(URL(fileURLWithPath: adminsCmd.0), arguments: adminsCmd.1, stdin: nil)
        let admins = MacLockdownParse.adminUsers(adminsOut.stdoutString)
        let userIsAdmin = admins.contains(userName)
        if !userIsAdmin {
            problems.append("\(userName) isn't an administrator, so Pax can't set this up from here.")
        }
        let others = admins.filter { $0 != userName && $0 != paxAdminUser }
        var toDemote: [String] = []
        if !others.isEmpty && allowExtraAdmins {
            warnings.append("Test mode: \(others.joined(separator: ", ")) is also an administrator and can "
                            + "undo Pax at any time, so the turn-off wait isn't real on this Mac. Everything else works.")
        } else if !others.isEmpty {
            // v0.8.10: Pax makes them standard itself (with the user's OK), never via
            // System Settings or Terminal. Names it can't pass safely still block.
            let unsafe = others.filter { !MacLockdownParse.isSafeShortName($0) }
            if !unsafe.isEmpty {
                problems.append("There are other administrator accounts Pax can't change safely "
                                + "(\(unsafe.joined(separator: ", "))). Pax would not be the only way back in, "
                                + "so the turn-off wait wouldn't mean anything.")
            } else if !demoteOtherAdmins {
                problems.append("There are other administrator accounts (\(others.joined(separator: ", "))). "
                                + "Pax would not be the only way back in, so the turn-off wait wouldn't mean anything. "
                                + "Leave \"Also make these standard accounts\" on and Pax will do it for you.")
            }
            toDemote = others
        }
        let paxadminExists = admins.contains(paxAdminUser)
        if paxadminExists {
            problems.append("A \(paxAdminUser) account already exists. Remove Pax properly first.")
        }

        let fvCmd = MacLockdownCommands.fileVaultStatus()
        let fvOut = try await plain.run(URL(fileURLWithPath: fvCmd.0), arguments: fvCmd.1, stdin: nil)
        let fileVault = MacLockdownParse.fileVaultOn(fvOut.stdoutString + fvOut.stderrString)
        let enrollCmd = MacLockdownCommands.enrollmentStatus()
        let enrollOut = try await plain.run(URL(fileURLWithPath: enrollCmd.0), arguments: enrollCmd.1, stdin: nil)
        let managed = MacLockdownParse.mdmEnrolled(enrollOut.stdoutString + enrollOut.stderrString)
        let keyRotates = fileVault && escrowMode == .local && rotateRecoveryKey && !managed && !allowExtraAdmins
        if fileVault && keyRotates {
            warnings.append("FileVault is on. Pax will give it a new recovery key and keep it behind your "
                            + "wait, so the old key stops working. Your login password still unlocks the Mac.")
        } else if fileVault {
            warnings.append("FileVault is on. Save your FileVault recovery key somewhere outside this "
                            + "Mac before you continue: it's your way back in if anything goes wrong.")
        } else {
            warnings.append("FileVault is off. Anyone who can start this Mac in Recovery can undo Pax. "
                            + "Turning FileVault on (and keeping the recovery key safe) makes Pax real.")
        }
        if managed {
            warnings.append("This Mac is managed by an organisation. Pax still protects it, but leaves its "
                            + "recovery key and startup settings alone, and its management server could "
                            + "still change accounts or undo Pax.")
        }
        warnings.append("Make a Time Machine backup first, or make sure your files are in iCloud.")

        var pre = MacPreflight(userName: userName, fileVaultOn: fileVault, admins: admins,
                               userIsAdmin: userIsAdmin, paxadminExists: paxadminExists,
                               passwordVerified: passwordOK, problems: problems, warnings: warnings)
        pre.mdmEnrolled = managed
        pre.otherAdmins = toDemote
        return pre
    }

    // MARK: Lockdown

    /// `waitForProfileApproval` is called after Pax opens the profile: the UI
    /// shows how to approve it in System Settings and returns when the user says
    /// they have (Pax then checks). Return false to give up (everything is undone).
    public func protectThisMac(password: String, deviceName: String, paths: MacLockdownPaths,
                               profileIdentifier: String,
                               standardAccounts: [String] = [],
                               writeConfig: @Sendable (String, String) throws -> Void,
                               waitForProfileApproval: @Sendable () async -> Bool,
                               progress: @escaping @Sendable (MacLockdownProgress) -> Void)
    async throws -> MacLockdownOutcome {
        completed = []
        pendingOthers = standardAccounts
        demotedOthers = []
        root = makeRoot(userName, password)
        userPassword = password
        defer { root = nil; userPassword = nil }
        var adminPassword = generateAdminPassword()
        defer { adminPassword = String(repeating: "x", count: adminPassword.count) }

        func report(_ step: MacLockdownStep, _ message: String, finished: Bool = false) {
            progress(MacLockdownProgress(step: step, message: message, finished: finished))
        }

        report(.preflight, "Checking this Mac")
        let pre = try await preflight(password: password, demoteOtherAdmins: !standardAccounts.isEmpty)
        guard pre.passwordVerified else { throw MacLockdownError.wrongPassword }
        guard pre.ok else { throw MacLockdownError.preflightFailed(pre.problems) }
        // v0.8.10: only accounts the user saw and agreed to. One that became an
        // administrator after the check blocks (nothing has changed yet).
        let others = pre.otherAdmins
        let unagreed = others.filter { !standardAccounts.contains($0) }
        guard unagreed.isEmpty else {
            throw MacLockdownError.preflightFailed([
                "There are other administrator accounts (\(unagreed.joined(separator: ", "))) that weren't "
                + "there a moment ago. Check this Mac again so you can see them first."])
        }
        report(.preflight, "Checks passed", finished: true)

        do {
            // 1. Hidden admin account. A leftover paxadmin record from an earlier
            // attempt (not an admin, or preflight would have stopped) makes
            // sysadminctl -addUser do nothing while still exiting 0, so the new
            // password never lands. Clear it first.
            report(.createAdmin, "Creating Pax's administrator account")
            if try await paxAdminRecordExists() {
                report(.createAdmin, "Removing a leftover Pax administrator account from an earlier try")
                try await deletePaxAdminFully()
                if try await paxAdminRecordExists() {
                    throw MacLockdownError.createAdminFailed(
                        "an old \(paxAdminUser) account is still on this Mac. Delete it in "
                        + "\(SystemSettingsPlace.current.usersPath) (or run: sudo dscl . -delete /Users/\(paxAdminUser)) and try again.")
                }
            }
            let create = MacLockdownCommands.createPaxAdmin(password: adminPassword,
                                                            adminUser: userName, adminPassword: password)
            let created = try await asRoot(create)
            guard created.exitCode == 0 else {
                throw MacLockdownError.createAdminFailed(created.combinedTail)
            }
            // sysadminctl can exit 0 without creating anything.
            guard try await paxAdminRecordExists() else {
                throw MacLockdownError.createAdminFailed(created.combinedTail.isEmpty
                    ? "macOS didn't create the account" : created.combinedTail)
            }
            completed.append(.createAdmin)
            let hide = MacLockdownCommands.hidePaxAdmin()
            _ = try await asRoot(hide)
            report(.createAdmin, "Administrator account created", finished: true)

            // 2. SecureToken, so FileVault and updates keep working.
            report(.secureToken, "Giving it a SecureToken (FileVault)")
            let token = MacLockdownCommands.secureTokenOn(password: adminPassword,
                                                          adminUser: userName, adminPassword: password)
            let tokenResult = try await asRoot(token)
            let status = MacLockdownCommands.secureTokenStatus()
            let statusResult = try await asRoot(status)
            let hasToken = MacLockdownParse.secureTokenEnabled(statusResult.combined)
            if !hasToken {
                if pre.fileVaultOn {
                    throw MacLockdownError.secureTokenFailed(tokenResult.combinedTail)
                }
                report(.secureToken, "No SecureToken (FileVault is off, so nothing depends on it)",
                       finished: true)
            } else {
                completed.append(.secureToken)
                report(.secureToken, "SecureToken enabled", finished: true)
            }

            // 3. The password must actually work before anything is locked.
            report(.verifyAdmin, "Checking the new password works")
            // Directory services can take a moment to accept a brand-new password.
            let verify = MacLockdownCommands.authOnly(user: paxAdminUser, password: adminPassword)
            var verified = try await plain.run(URL(fileURLWithPath: verify.0), arguments: verify.1, stdin: nil)
            var tries = 1
            while verified.exitCode != 0 && tries < 3 {
                try? await Task.sleep(nanoseconds: verifyRetryDelayNanos)
                verified = try await plain.run(URL(fileURLWithPath: verify.0), arguments: verify.1, stdin: nil)
                tries += 1
            }
            guard verified.exitCode == 0 else {
                throw MacLockdownError.verifyAdminFailed(verified.combinedTail)
            }
            completed.append(.verifyAdmin)
            report(.verifyAdmin, "Password works", finished: true)

            // 4. Escrow. Local (v0.8.0): pax-guard's root-only safe on this Mac, checked
            // by its receipt. Server: send it and read the device back.
            let deviceID: String
            let guardToken: String
            if escrowMode == .local {
                report(.escrow, "Locking the key in this Mac's safe")
                let secretURL = paths.configFile.deletingLastPathComponent()
                    .appendingPathComponent("pax-escrow-secret")
                do {
                    try FileManager.default.createDirectory(at: secretURL.deletingLastPathComponent(),
                                                            withIntermediateDirectories: true,
                                                            attributes: [.posixPermissions: 0o700])
                    _ = FileManager.default.createFile(atPath: secretURL.path, contents: nil,
                                                   attributes: [.posixPermissions: 0o600])
                    try Data(adminPassword.utf8).write(to: secretURL)
                } catch {
                    throw MacLockdownError.escrowFailed("couldn't prepare the key: \(error.localizedDescription)")
                }
                defer { try? FileManager.default.removeItem(at: secretURL) }
                let deposit = MacLockdownCommands.localEscrowDeposit(guardSource: paths.guardSource.path,
                                                                     secretFile: secretURL.path,
                                                                     waitSeconds: localWaitSeconds,
                                                                     supportRelease: supportRelease,
                                                                     trial: trialDay)
                let stored = try await asRoot(deposit)
                completed.append(.escrow)       // rollback empties the safe from here on
                guard stored.exitCode == 0, LocalEscrowReceipt.matches(stored.combined, password: adminPassword) else {
                    throw MacLockdownError.escrowFailed(stored.combinedTail.isEmpty
                        ? "the safe didn't confirm the key" : stored.combinedTail)
                }
                deviceID = "local"
                guardToken = ""
                report(.escrow, "Locked in this Mac's safe", finished: true)
            } else {
                report(.escrow, "Storing the password with the Pax server")
                let device: EscrowClient.Device
                do {
                    device = try await escrow.registerDevice(name: deviceName, platform: "mac",
                                                             profileIdentifier: profileIdentifier,
                                                             removalPassword: adminPassword,
                                                             supportRelease: supportRelease,
                                                             trial: trialDay,
                                                             hardwareID: trialDay ? TrialDay.thisMacHardwareID() : nil)
                } catch {
                    throw MacLockdownError.escrowFailed(error.localizedDescription)
                }
                do {
                    guardToken = try await escrow.guardToken(deviceID: device.device_id).guard_token
                    let stored = try await escrow.device(id: device.device_id)
                    guard stored.device_id == device.device_id else {
                        throw MacLockdownError.escrowFailed("the server didn't confirm the device")
                    }
                } catch let e as MacLockdownError {
                    throw e
                } catch {
                    throw MacLockdownError.escrowFailed(error.localizedDescription)
                }
                deviceID = device.device_id
                completed.append(.escrow)
                report(.escrow, "Stored and confirmed", finished: true)
            }

            // 5. Profile, then pax-guard.
            report(.installProfile, "Opening the Pax profile: approve it in \(SystemSettingsPlace.current.appName)")
            let open = MacLockdownCommands.openProfile(path: paths.profileFile.path)
            _ = try await plain.run(URL(fileURLWithPath: open.0), arguments: open.1, stdin: nil)
            let settings = MacLockdownCommands.openDeviceManagementSettings()
            _ = try await plain.run(URL(fileURLWithPath: settings.0), arguments: settings.1, stdin: nil)
            // From here the profile may be installed even if we stop, so rollback removes it.
            completed.append(.installProfile)
            var installed = false
            for _ in 0..<3 where !installed {
                guard await waitForProfileApproval() else {
                    throw MacLockdownError.profileInstallFailed("you stopped before approving it")
                }
                let listed = try await asRoot(MacLockdownCommands.listProfiles())
                installed = listed.combined.contains(profileIdentifier)
            }
            guard installed else {
                throw MacLockdownError.profileInstallFailed("the profile isn't showing as installed")
            }
            report(.installProfile, "Profile installed", finished: true)

            report(.installGuard, "Installing the Pax background guard")
            try writeConfig(paths.configFile.path, guardToken)
            let guardCmd = MacLockdownCommands.installGuard(script: paths.guardInstallScript.path,
                                                            source: paths.guardSource.path,
                                                            config: paths.configFile.path,
                                                            profile: paths.profileFile.path)
            if !others.isEmpty {
                // pax-guard keeps these standard, and a proper removal (or a rollback,
                // through the uninstaller) makes exactly these administrators again.
                try Self.recordStandardAccounts(others, inConfig: paths.configFile.path)
            }
            let guardResult = try await asRoot(guardCmd)
            guard guardResult.exitCode == 0 else {
                throw MacLockdownError.guardInstallFailed(guardResult.combinedTail)
            }
            completed.append(.installGuard)
            report(.installGuard, "Guard running", finished: true)

            // 6. v0.8.10: the other administrators the user agreed to, as root with
            // the user's (still admin) password, each verified. Any failure rolls back.
            if !others.isEmpty {
                report(.demoteOthers, "Making \(others.joined(separator: ", ")) standard")
                completed.append(.demoteOthers)   // rollback restores them from here on
                for other in others {
                    let res = try await asRoot(MacLockdownCommands.demote(user: other))
                    guard res.exitCode == 0 else {
                        throw MacLockdownError.otherAdminFailed(other, res.combinedTail)
                    }
                    let chk = MacLockdownCommands.isMember(user: other)
                    let out = try await plain.run(URL(fileURLWithPath: chk.0), arguments: chk.1, stdin: nil)
                    guard MacLockdownParse.isMemberNo(out.stdoutString) else {
                        throw MacLockdownError.otherAdminFailed(other, "it is still an administrator")
                    }
                }
                demotedOthers = others
                report(.demoteOthers, "\(others.joined(separator: ", ")) "
                       + (others.count == 1 ? "is a standard account" : "are standard accounts"), finished: true)
            }

            // 7. Only now: demote.
            report(.demoteUser, "Making \(userName) a standard user")
            let demote = MacLockdownCommands.demote(user: userName)
            let demoted = try await asRoot(demote)
            guard demoted.exitCode == 0 else {
                throw MacLockdownError.demotionFailed(demoted.combinedTail)
            }
            completed.append(.demoteUser)

            let check = MacLockdownCommands.isMember(user: userName)
            let checked = try await plain.run(URL(fileURLWithPath: check.0), arguments: check.1, stdin: nil)
            // Positive proof only: "no <user> is NOT a member". A failed or empty
            // check is not proof of anything, so it counts as still-admin (rollback).
            guard MacLockdownParse.isMemberNo(checked.stdoutString) else {
                throw MacLockdownError.stillAdmin
            }
            completed.append(.verifyDemotion)
            report(.verifyDemotion, "\(userName) is a standard user", finished: true)
            report(.done, "This Mac is protected", finished: true)
            return MacLockdownOutcome(deviceID: deviceID,
                                      profileIdentifier: profileIdentifier, userDemoted: true)
        } catch {
            var failedAt = MacLockdown.next(after: completed.last)
            // Local escrow marks .escrow done before checking the receipt (so the
            // rollback empties the safe); a bad receipt still failed at .escrow.
            if case MacLockdownError.escrowFailed = error { failedAt = .escrow }
            // v0.8.10: likewise .demoteOthers is marked before the accounts change.
            if case MacLockdownError.otherAdminFailed = error { failedAt = .demoteOthers }
            await rollback(paths: paths, profileIdentifier: profileIdentifier, paxAdminPassword: adminPassword)
            if let known = error as? MacLockdownError {
                throw MacLockdownError.rolledBack(failedAt, known.errorDescription ?? "\(known)")
            }
            throw MacLockdownError.rolledBack(failedAt, error.localizedDescription)
        }
    }

    static func next(after step: MacLockdownStep?) -> MacLockdownStep {
        guard let step, let i = MacLockdownStep.allCases.firstIndex(of: step),
              i + 1 < MacLockdownStep.allCases.count else { return .createAdmin }
        return MacLockdownStep.allCases[i + 1]
    }

    /// Steps done so far (for tests and diagnostics).
    public func completedSteps() -> [MacLockdownStep] { completed }

    /// Undo, newest step first. Best effort: every step is safe to repeat, and
    /// re-promoting the user comes first so they can never be locked out.
    public func rollback(paths: MacLockdownPaths, profileIdentifier: String,
                         paxAdminPassword: String? = nil) async {
        guard let root else { completed = []; return }
        for step in completed.reversed() {
            switch step {
            case .demoteUser:
                // The user is no longer an admin, so their password can't re-promote
                // them: paxadmin (verified working before anything was locked) does.
                let promote = MacLockdownCommands.promote(user: userName)
                if let paxAdminPassword {
                    let adminRoot = makeRoot(paxAdminUser, paxAdminPassword)
                    _ = try? await adminRoot.runAsRoot(promote.0, promote.1, stdin: nil)
                }
            case .demoteOthers:
                // v0.8.10: made administrators again. pax-guard is still running here and
                // would make them standard again, so this repeats after it's removed.
                await restoreOthers(paxAdminPassword: paxAdminPassword)
            case .installGuard:
                // The installer puts the uninstaller in place before it changes anything.
                let un = MacLockdownCommands.uninstallGuard(script: MacLockdownCommands.installedUninstaller,
                                                            user: userName)
                _ = try? await root.runAsRoot(un.0, un.1, stdin: nil)
                if completed.contains(.demoteOthers) { await restoreOthers(paxAdminPassword: paxAdminPassword) }
            case .installProfile:
                let rm = MacLockdownCommands.removeProfile(identifier: profileIdentifier)
                _ = try? await root.runAsRoot(rm.0, rm.1, stdin: nil)
            case .escrow where escrowMode == .local:
                // Nothing is locked any more, so the safe on this Mac is emptied too.
                let rm = MacLockdownCommands.removeLocalEscrow()
                _ = try? await root.runAsRoot(rm.0, rm.1, stdin: nil)
            case .createAdmin, .secureToken:
                let del = MacLockdownCommands.deletePaxAdmin(adminUser: userName, adminPassword: userPassword)
                _ = try? await root.runAsRoot(del.0, del.1, stdin: nil)
                if (try? await paxAdminRecordExists()) == true {
                    let rec = MacLockdownCommands.deletePaxAdminRecord()
                    _ = try? await root.runAsRoot(rec.0, rec.1, stdin: nil)
                    let home = MacLockdownCommands.removePaxAdminHome()
                    _ = try? await root.runAsRoot(home.0, home.1, stdin: nil)
                }
            default:
                continue
            }
        }
        // Escrow is deliberately left alone: a password the server holds for a
        // Mac that is no longer locked is harmless, and deleting it would need
        // a path that could also delete a live one.
        completed = []
        pendingOthers = []
        demotedOthers = []
    }

    /// v0.8.10 rollback: the other administrators back in the admin group. paxadmin
    /// first (it exists until the end of the rollback), then the user's own password.
    private func restoreOthers(paxAdminPassword: String?) async {
        for other in pendingOthers {
            let promote = MacLockdownCommands.promote(user: other)
            var done = false
            if let paxAdminPassword {
                let adminRoot = makeRoot(paxAdminUser, paxAdminPassword)
                done = (try? await adminRoot.runAsRoot(promote.0, promote.1, stdin: nil))?.exitCode == 0
            }
            if !done, let root { _ = try? await root.runAsRoot(promote.0, promote.1, stdin: nil) }
        }
    }

    /// v0.8.10: adds `demoted_admins` to the config the app wrote (0600, keys sorted),
    /// so pax-guard keeps them standard and its uninstaller makes them admins again.
    static func recordStandardAccounts(_ names: [String], inConfig path: String) throws {
        let url = URL(fileURLWithPath: path)
        var obj: [String: Any] = [:]
        if let data = try? Data(contentsOf: url),
           let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any] { obj = parsed }
        obj["demoted_admins"] = names
        let data = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }

    /// Remove Pax after the wait: the released paxadmin password re-promotes the
    /// user, removes the guard and the profile, and deletes paxadmin.
    public func removePax(paxAdminPassword: String, paths: MacLockdownPaths, profileIdentifier: String)
    async throws -> [String] {
        var done: [String] = []
        let runner = makeRoot(paxAdminUser, paxAdminPassword)
        let promote = MacLockdownCommands.promote(user: userName)
        let promoted = try await runner.runAsRoot(promote.0, promote.1, stdin: nil)
        guard promoted.exitCode == 0 else {
            throw MacLockdownError.demotionFailed(promoted.combinedTail)
        }
        done.append("\(userName) is an administrator again")

        let un = MacLockdownCommands.uninstallGuard(
            script: MacLockdownCommands.installedUninstaller, user: userName)
        let unResult = try await runner.runAsRoot(un.0, un.1, stdin: nil)
        done.append(unResult.exitCode == 0 ? "Pax guard and profile removed"
                                           : "Guard removal reported: \(unResult.combinedTail)")
        let del = MacLockdownCommands.deletePaxAdmin()
        let deleted = try await runner.runAsRoot(del.0, del.1, stdin: nil)
        done.append(deleted.exitCode == 0 ? "Pax's administrator account deleted"
                                          : "Delete \(paxAdminUser) in \(SystemSettingsPlace.current.usersPath)")
        return done
    }
}

extension CommandResult {
    var combined: String { stdoutString + stderrString }
    /// Last line of output, for an error message that fits on screen.
    var combinedTail: String {
        let text = combined.trimmingCharacters(in: .whitespacesAndNewlines)
        return String(text.suffix(300))
    }
}

// MARK: - Escrow additions for the Mac

extension EscrowClient {
    public struct GuardToken: Decodable, Sendable {
        public let guard_token: String
    }

    public struct DeviceStatus: Decodable, Sendable {
        public let device_id: String
        public let name: String
        public let platform: String
        public let installed_at: Int
        public let grace_until: Int
        public let in_grace_period: Bool
        public let released_at: Int?
        public let removal_request: RemovalRequest?
        /// v0.8.15: Details › Support ID (nil from an older server or pax-guard).
        public let support_id: String?
        /// v0.8.15: "Allow verified support release" (nil from an older server or pax-guard).
        public let support_release: SupportReleaseState?
        /// v0.8.16: the device's turn-off wait in seconds, for "Turn-off wait: 7 days"
        /// (pax-guard has always sent it; the server from 0.8.16; nil from older ones).
        public let wait_seconds: Int?
        /// v0.8.18: the trial day (nil: none, or an older server or pax-guard).
        public let trial: TrialState?
        /// v0.8.21: the emergency release cooling-off in seconds (nil from an older
        /// server or pax-guard; the app then says the default, 24 hours).
        public let emergency_cooloff_seconds: Int?
        /// v0.8.26: whether the password was released, by any route (nil from an older
        /// server or pax-guard; `released_at` says the same).
        public let released: Bool?
        /// v0.8.26 (iPhone/iPad): the last UTC day ("2026-10-15") the account's Pax DNS
        /// address was used, and whether it is still checking in (false: 48 hours or more
        /// with no traffic; nil: unknown or an older server).
        public let last_seen: String?
        public let checking_in: Bool?

        /// v0.8.18: {"active", "until", "ended_at"}. `active` is as of when it was read;
        /// the app also checks `until` against the clock for its countdown.
        public struct TrialState: Decodable, Sendable, Equatable {
            public let active: Bool
            public let until: Int
            public let ended_at: Int?

            public init(active: Bool, until: Int, ended_at: Int? = nil) {
                self.active = active
                self.until = until
                self.ended_at = ended_at
            }
        }

        public struct SupportReleaseState: Decodable, Sendable {
            public let allowed: Bool
            public let pending_on_at: Int?
            public let telling_partner: Bool?
        }

        public struct RemovalRequest: Decodable, Sendable {
            public let request_id: String
            public let kind: String
            public let status: String
            public let unlock_at: Int
            public let seconds_remaining: Int
            public let can_reveal: Bool
        }
    }

    public struct Released: Decodable, Sendable {
        public let device_id: String
        public let removal_password: String
    }

    public func guardToken(deviceID: String) async throws -> GuardToken {
        try await send("POST", "v1/devices/\(deviceID)/guard-token")
    }

    public func device(id: String) async throws -> DeviceStatus {
        try await send("GET", "v1/devices/\(id)")
    }

    public func devices() async throws -> [DeviceStatus] {
        struct Wrapper: Decodable { let devices: [DeviceStatus] }
        let w: Wrapper = try await send("GET", "v1/devices")
        return w.devices
    }

    public struct Retired: Decodable, Sendable {
        public let device_id: String
        public let retired: Bool
    }

    /// v0.8.26 "Remove from list" for a device Pax is already off on: the account forgets
    /// it. The server refuses (409) any device whose password wasn't released.
    public func retireDevice(deviceID: String) async throws -> Retired {
        try await send("POST", "v1/devices/\(deviceID)/retire")
    }

    public func requestRemoval(deviceID: String) async throws -> DeviceStatus {
        try await send("POST", "v1/devices/\(deviceID)/removal-request")
    }

    public func cancelRemoval(deviceID: String) async throws -> DeviceStatus {
        try await send("POST", "v1/devices/\(deviceID)/removal-request/cancel")
    }

    public func confirmRemoval(deviceID: String) async throws -> Released {
        try await send("POST", "v1/devices/\(deviceID)/removal-request/confirm", body: ["confirm": true])
    }

    public struct AccountSummary: Decodable, Sendable {
        public let email: String
        public let wait_seconds: Int
        public let adblock: Bool?
    }

    public func accountSummary() async throws -> AccountSummary {
        try await send("GET", "v1/accounts/me")
    }

    /// v0.8.18 "Start my wait now": ends the device's trial day early.
    public func endTrial(deviceID: String) async throws -> DeviceStatus {
        try await send("POST", "v1/devices/\(deviceID)/trial/end")
    }

    /// v0.8.15 "Allow verified support release": off at once; on after the wait, partner told first.
    public func setSupportRelease(deviceID: String, allowed: Bool) async throws -> DeviceStatus {
        try await send("PUT", "v1/devices/\(deviceID)/support-release", body: ["allowed": allowed])
    }

    /// v0.8.15: a one-time code from Pax support for this device. The server emails the
    /// partner first, then releases the password at once.
    public func redeemSupportCode(deviceID: String, code: String) async throws -> Released {
        try await send("POST", "v1/devices/\(deviceID)/support-release/redeem",
                       body: ["code": VerifiedSupportRelease.cleaned(code)])
    }

    /// Rate-limited emergency release (short cooling-off; partner told).
    public func emergencyRelease(deviceID: String, reason: String) async throws {
        let _: [String: AnyDecodable] = try await send("POST", "v1/devices/\(deviceID)/emergency",
                                                       body: ["reason": reason])
    }

    /// Ad/tracker blocking on self-locked Macs (immediate both ways).
    public func setAdblock(_ enabled: Bool) async throws {
        let _: [String: AnyDecodable] = try await send("PUT", "v1/accounts/me/adblock",
                                                       body: ["enabled": enabled])
    }
}

/// The JSON pax-guard reads (written 0600, then installed root-only).
public struct GuardConfigFile: Codable, Sendable {
    public var server_url: String
    public var guard_token: String
    public var profile_identifier: String
    public var user: String
    public var resolver_host: String
    public var adblock_default: Bool
    // v0.8.13: x_media_default / bluesky_media_default are gone: pictures and video on
    // X and Bluesky are always blocked, and pax-guard ignores the keys in older configs.
    /// v0.8.0: "local" (pax-guard holds the key) or "server".
    public var escrow_mode: String
    /// v0.8.0: "local" (127.0.0.1 forwarder) or "profile" (v0.7 DoH profile).
    public var dns_mode: String
    public var rotate_recovery_key: Bool
    public var firmware_password: Bool
    public var mdm_managed: Bool
    public var testing_allow_extra_admins: Bool
    /// v0.8.6: YouTube Restricted Mode chosen at set-up (on by default); Settings changes it later.
    public var youtube_restricted_default: Bool
    /// v0.8.10: other administrators made standard at set-up (MacLockdown fills it in).
    public var demoted_admins: [String]? = nil
    /// v0.8.12: Pax Max can be switched after set-up (the profile installs Pax Image
    /// Blur in Firefox either way) and the set-up choice. nil (left out): before 0.8.12.
    public var pax_max_switchable: Bool? = nil
    public var pax_max_default: Bool? = nil

    public init(server_url: String, guard_token: String, profile_identifier: String,
                user: String, resolver_host: String, adblock_default: Bool = true,
                escrow_mode: String = "server", dns_mode: String = "local",
                rotate_recovery_key: Bool = true, firmware_password: Bool = true,
                mdm_managed: Bool = false, testing_allow_extra_admins: Bool = false,
                youtube_restricted_default: Bool = true,
                pax_max_switchable: Bool? = nil, pax_max_default: Bool? = nil) {
        self.youtube_restricted_default = youtube_restricted_default
        self.pax_max_switchable = pax_max_switchable
        self.pax_max_default = pax_max_default
        self.escrow_mode = escrow_mode
        self.dns_mode = dns_mode
        self.rotate_recovery_key = rotate_recovery_key
        self.firmware_password = firmware_password
        self.mdm_managed = mdm_managed
        self.testing_allow_extra_admins = testing_allow_extra_admins
        self.server_url = server_url
        self.guard_token = guard_token
        self.profile_identifier = profile_identifier
        self.user = user
        self.resolver_host = resolver_host
        self.adblock_default = adblock_default
    }

    public func json() throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return try enc.encode(self)
    }

    /// The DoH URL's host, which pax-guard must never block or firewall.
    public static func resolverHost(from dohURL: String) -> String {
        URLComponents(string: dohURL)?.host ?? "doh.cleanbrowsing.org"
    }
}
