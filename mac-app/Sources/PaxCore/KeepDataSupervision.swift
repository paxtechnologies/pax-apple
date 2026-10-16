// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// "Keep my data": supervise an iPhone that is already set up, WITHOUT erasing it.
///
/// iOS 17-26 (`.restoredSystem`): restore a tiny backup that holds only
///   CloudConfigurationDetails.plist (IsSupervised = true, plus Setup Assistant
///   "done" preferences) with system files, then restart the phone.
/// iOS 27.x (`.live`): Apple's iOS 27 deployment notes say backups no longer carry
///   supervision status, so the restored plist alone does nothing. Instead: restore
///   the same tiny backup WITHOUT system files (skip apps, remove, reboot; on iOS 27
///   restoring system files lost photos and signed out the Apple Account in testing), the
///   phone reboots into Setup Assistant, Pax re-pairs, and sends
///   `SetCloudConfiguration` to `com.apple.mobile.MCInstall` while the phone is still
///   in Setup ("Restore Completed" screen: don't tap Continue yet).
/// iOS 28+, older than 17, or unreadable: refused; Pax falls back to Clean set-up.
///
/// Method documented by attention awareness
/// (attentionawareness.com/blog/supervise-iphone-ios-27-without-erasing), tested
/// there on one iPhone SE (2nd gen) running iOS 27.2. Pax re-implements it (see
/// THIRD_PARTY_NOTICES.md); the USB work is done by `device/pax_device.py` with
/// pymobiledevice3, on the Python that Pax.app bundles (v0.8.6, see `BundledHelper`).
///
/// NOT TESTED ON HARDWARE in Pax. Always verify supervision afterwards; Pax only
/// escrows the password and installs the locked profile once it is confirmed.
public enum KeepDataMethod: String, Sendable, Equatable {
    case restoredSystem = "restored"
    case live = "live"
}

public enum KeepDataRefusal: String, Sendable, Equatable {
    case tooOld = "too_old"
    case tooNew = "too_new"
    case unknown = "unknown"
}

public enum KeepDataPlan: Sendable, Equatable {
    case allowed(KeepDataMethod)
    case refused(KeepDataRefusal)

    public static let oldestMajor = 17
    public static let newestMajor = 27
    public static let firstLiveMajor = 27

    /// Same rule as `device/seed.py plan_for_version` (both gates run: the app's
    /// and the helper's, which re-reads the phone right before the restore).
    public static func forVersion(_ version: String?) -> KeepDataPlan {
        guard let major = majorVersion(version) else { return .refused(.unknown) }
        if major < oldestMajor { return .refused(.tooOld) }
        if major > newestMajor { return .refused(.tooNew) }
        return .allowed(major >= firstLiveMajor ? .live : .restoredSystem)
    }

    /// First number of a dotted version. Every part must be ASCII digits; a version
    /// that doesn't read is never taken for an older one.
    public static func majorVersion(_ version: String?) -> Int? {
        guard let version else { return nil }
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard !parts.isEmpty,
              parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0.isASCII && $0.isNumber } }),
              let major = Int(parts[0]), major > 0 else { return nil }
        return major
    }

    public var method: KeepDataMethod? {
        if case .allowed(let m) = self { return m }
        return nil
    }

    public var explanation: String {
        switch self {
        case .allowed(.restoredSystem):
            return "Supervises your iPhone in place with a tiny settings restore and a restart. "
                + "Your apps, photos and Apple Account stay."
        case .allowed(.live):
            return "iOS 27: a tiny settings restore, a restart into Setup, then Pax supervises the "
                + "iPhone while it waits on \"Restore Completed\". Your apps, photos and Apple Account stay."
        case .refused(.tooOld):
            return "Keep my data needs iOS \(Self.oldestMajor) or later. Update the iPhone, or use Clean set-up."
        case .refused(.tooNew):
            return "Keep my data hasn't been tested on iOS \(Self.newestMajor + 1) or later. Apple may have "
                + "changed how this works, so Pax won't risk your data. Use Clean set-up."
        case .refused(.unknown):
            return "Pax couldn't read this iPhone's iOS version, so Keep my data is off. Use Clean set-up."
        }
    }
}

// MARK: - Helper results

public struct KeepDataPreflight: Sendable, Equatable {
    public var method: KeepDataMethod?
    public var ok: Bool
    public var blocking: [String]
    public var warnings: [String]
    public var askUserFindMy: Bool
    public var batteryLevel: Int?
    public var findMyOn: Bool?

    public init(method: KeepDataMethod?, ok: Bool, blocking: [String], warnings: [String],
                askUserFindMy: Bool, batteryLevel: Int? = nil, findMyOn: Bool? = nil) {
        self.method = method; self.ok = ok; self.blocking = blocking; self.warnings = warnings
        self.askUserFindMy = askUserFindMy; self.batteryLevel = batteryLevel; self.findMyOn = findMyOn
    }

    init(json: [String: Any]) {
        let facts = json["facts"] as? [String: Any] ?? [:]
        self.init(method: (json["mode"] as? String).flatMap(KeepDataMethod.init(rawValue:)),
                  ok: json["ok"] as? Bool ?? false,
                  blocking: json["blocking"] as? [String] ?? [],
                  warnings: json["warnings"] as? [String] ?? [],
                  askUserFindMy: json["ask_user_find_my"] as? Bool ?? false,
                  batteryLevel: facts["battery_level"] as? Int,
                  findMyOn: facts["find_my_on"] as? Bool)
    }
}

/// What one `connect` call found after the restart.
public enum PhoneConnectState: String, Sendable, Equatable {
    case paired
    case trustRequested = "trust_requested"
    case locked
    case notFound = "not_found"
    case denied

    /// Safe to call `connect` again on a timer. Never after a Trust prompt was shown:
    /// a Pair sent while the user types the passcode cancels the dialog.
    public var pollAgain: Bool { self == .notFound || self == .locked }

    public var instruction: String {
        switch self {
        case .paired: return "Connected."
        case .trustRequested: return "Tap Trust on the iPhone and enter your passcode, then click \"I tapped Trust\"."
        case .locked: return "Unlock the iPhone (press Home or swipe up, then enter your passcode)."
        case .notFound: return "Waiting for the iPhone to come back. Keep the cable plugged in."
        case .denied: return "The iPhone said Don't Trust. Unplug it, plug it back in, unlock it and tap Trust."
        }
    }
}

public struct SupervisionStatus: Sendable, Equatable {
    public var supervised: Bool
    public var hostCertificateRegistered: Bool
    public var findMyOn: Bool?
    public var allowPairing: Bool?

    public init(supervised: Bool, hostCertificateRegistered: Bool, findMyOn: Bool? = nil, allowPairing: Bool? = nil) {
        self.supervised = supervised
        self.hostCertificateRegistered = hostCertificateRegistered
        self.findMyOn = findMyOn
        self.allowPairing = allowPairing
    }
}

public enum ProfileInstallOutcome: Sendable, Equatable {
    /// Installed silently with the supervision identity.
    case silent
    /// Sent to the phone as a download; the user taps Install in Settings.
    case pendingUser
}

public struct SeedRestoreOutcome: Sendable, Equatable {
    public var method: KeepDataMethod
    public var alreadySupervised: Bool
}

public struct HelperFailure: Error, LocalizedError, Equatable {
    public let code: String
    public let message: String
    public var errorDescription: String? { message }
}

// MARK: - Helper client

/// The Python that runs the device helper (v0.8.6).
///
/// Pax.app carries its own interpreter, `Contents/Resources/device/python/bin/python3.12`
/// (python-build-standalone CPython, universal2, with pymobiledevice3), so the iPhone
/// set-up needs nothing installed on the Mac. Order:
///   1. `PAX_PYTHON` (developers),
///   2. the bundled interpreter, run with `-I -B` (isolated from the user's PYTHON*
///      variables and site-packages; never writes .pyc files into the signed app),
///   3. the pre-0.8.6 developer venv `~/Library/Application Support/Pax/venv` (`swift run`
///      from the repo, where there is no bundle),
///   4. /usr/bin/python3.
public struct BundledHelper: Sendable, Equatable {
    public static let relativePython = "device/python/bin/python3.12"
    public static let bundledArguments = ["-I", "-B"]

    public let python: URL
    public let arguments: [String]
    public let isBundled: Bool

    public static func resolve(environment: [String: String] = ProcessInfo.processInfo.environment,
                               resourceDirectory: URL? = Bundle.main.resourceURL,
                               applicationSupport: URL? = FileManager.default.urls(
                                   for: .applicationSupportDirectory, in: .userDomainMask).first,
                               isExecutable: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) })
        -> BundledHelper {
        if let chosen = environment["PAX_PYTHON"], !chosen.isEmpty {
            return BundledHelper(python: URL(fileURLWithPath: chosen), arguments: [], isBundled: false)
        }
        if let res = resourceDirectory {
            let bundled = res.appendingPathComponent(relativePython)
            if isExecutable(bundled.path) {
                return BundledHelper(python: bundled, arguments: bundledArguments, isBundled: true)
            }
        }
        if let base = applicationSupport {
            let venv = base.appendingPathComponent("Pax/venv/bin/python3")
            if isExecutable(venv.path) { return BundledHelper(python: venv, arguments: [], isBundled: false) }
        }
        return BundledHelper(python: URL(fileURLWithPath: "/usr/bin/python3"), arguments: [], isBundled: false)
    }

    /// The Python for the iPhone profile generator (stdlib only): the bundled one when
    /// Pax.app has it, so a Mac without the Command Line Tools never sees their
    /// install prompt; otherwise /usr/bin/python3 as before.
    public var profilePython: URL { isBundled ? python : URL(fileURLWithPath: "/usr/bin/python3") }
}

/// Runs `device/pax_device.py` and reads the JSON object on its last stdout line.
public struct PaxDeviceHelper: Sendable {
    public let python: URL
    public let script: URL
    /// Interpreter flags before the script (`-I -B` for the bundled Python).
    public let interpreterArguments: [String]
    public let runner: CommandRunner
    /// Demo mode: the runner is canned, so don't look for files.
    public let assumeAvailable: Bool

    public init(script: URL, python: URL, interpreterArguments: [String] = [],
                runner: CommandRunner = ProcessRunner(), assumeAvailable: Bool = false) {
        self.script = script
        self.python = python
        self.interpreterArguments = interpreterArguments
        self.runner = runner
        self.assumeAvailable = assumeAvailable
    }

    public init(script: URL, interpreter: BundledHelper, runner: CommandRunner = ProcessRunner()) {
        self.init(script: script, python: interpreter.python, interpreterArguments: interpreter.arguments,
                  runner: runner)
    }

    /// The interpreter `BundledHelper.resolve` picks (kept for callers from before v0.8.6).
    public static func defaultPython(environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        BundledHelper.resolve(environment: environment).python
    }

    public func isAvailable() -> Bool {
        assumeAvailable || FileManager.default.fileExists(atPath: script.path)
            && FileManager.default.isExecutableFile(atPath: python.path)
    }

    /// Everything after the interpreter: flags, the script, the subcommand.
    public func commandLine(_ command: String, udid: String? = nil, extra: [String] = []) -> [String] {
        interpreterArguments + [script.path] + Self.arguments(command, udid: udid, extra: extra)
    }

    public static func arguments(_ command: String, udid: String?, extra: [String] = []) -> [String] {
        var args = [command]
        if let udid { args += ["--udid", udid] }
        return args + extra
    }

    public func call(_ command: String, udid: String? = nil, extra: [String] = [],
                     stdin: Data? = nil) async throws -> [String: Any] {
        let result = try await runner.run(python, arguments: commandLine(command, udid: udid, extra: extra),
                                          stdin: stdin)
        guard let json = Self.lastJSONObject(result.stdout) else {
            let err = result.stderrString.trimmingCharacters(in: .whitespacesAndNewlines)
            throw HelperFailure(code: "no_output",
                                message: "The Pax device helper gave no answer. \(err.suffix(300))")
        }
        guard json["ok"] as? Bool == true else {
            throw HelperFailure(code: json["code"] as? String ?? "error",
                                message: json["error"] as? String ?? "The Pax device helper failed.")
        }
        return json
    }

    /// Progress lines are {"event": ...}; the result is the last line with "ok".
    static func lastJSONObject(_ data: Data) -> [String: Any]? {
        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(whereSeparator: \.isNewline).reversed() {
            if let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
               obj["ok"] != nil {
                return obj
            }
        }
        return nil
    }
}

/// The Keep-my-data steps, one helper call each, so the UI can stop between them
/// and tell the user what to do on the phone.
public struct KeepDataSupervisor: Sendable {
    public let helper: PaxDeviceHelper
    public let organization: String

    public init(helper: PaxDeviceHelper, organization: String = "Pax (self-managed)") {
        self.helper = helper
        self.organization = organization
    }

    public func listDevices() async throws -> [ConnectedDevice] {
        let json = try await helper.call("list")
        let list = json["devices"] as? [[String: Any]] ?? []
        return list.compactMap { d in
            guard let udid = d["udid"] as? String else { return nil }
            // No cfgutil here, so no ECID: the UDID doubles as the identifier.
            return ConnectedDevice(ecid: udid, udid: udid, name: d["name"] as? String ?? "iPhone",
                                   deviceType: d["product_type"] as? String ?? "iPhone",
                                   firmwareVersion: d["ios"] as? String,
                                   isSupervised: d["supervised"] as? Bool)
        }
    }

    public func preflight(udid: String, findMyConfirmedOff: Bool, backupConfirmed: Bool) async throws -> KeepDataPreflight {
        var extra: [String] = []
        if findMyConfirmedOff { extra.append("--find-my-confirmed-off") }
        if backupConfirmed { extra.append("--backup-confirmed") }
        return KeepDataPreflight(json: try await helper.call("preflight", udid: udid, extra: extra))
    }

    /// Full local backup (MobileBackup2, through the helper) into `directory`, verified finished.
    public func backup(udid: String, directory: URL) async throws -> URL {
        let json = try await helper.call("backup", udid: udid, extra: ["--dir", directory.path])
        guard json["verified"] as? Bool == true, let path = json["backup"] as? String else {
            throw HelperFailure(code: "backup_incomplete", message: "The backup didn't finish.")
        }
        return URL(fileURLWithPath: path)
    }

    static func identityArguments(_ identity: SupervisionIdentity?, organization: String, forbidPairing: Bool) -> [String] {
        var extra = ["--org", organization]
        if let identity { extra += ["--cert", identity.certificateURL.path] }
        if forbidPairing { extra.append("--forbid-pairing") }
        return extra
    }

    public func seedRestore(udid: String, identity: SupervisionIdentity?, forbidPairing: Bool) async throws -> SeedRestoreOutcome {
        let json = try await helper.call("seed-restore", udid: udid,
                                         extra: Self.identityArguments(identity, organization: organization,
                                                                       forbidPairing: forbidPairing))
        guard let method = (json["mode"] as? String).flatMap(KeepDataMethod.init(rawValue:)) else {
            throw HelperFailure(code: "unexpected", message: "The helper didn't say which method it used.")
        }
        return SeedRestoreOutcome(method: method, alreadySupervised: json["already_supervised"] as? Bool ?? false)
    }

    public func connect(udid: String) async throws -> PhoneConnectState {
        let json = try await helper.call("connect", udid: udid)
        return (json["state"] as? String).flatMap(PhoneConnectState.init(rawValue:)) ?? .notFound
    }

    public func liveConfigure(udid: String, identity: SupervisionIdentity?, forbidPairing: Bool,
                              timeout: Int = 90) async throws -> SupervisionStatus {
        let extra = Self.identityArguments(identity, organization: organization, forbidPairing: forbidPairing)
            + ["--timeout", String(timeout)]
        let json = try await helper.call("live-configure", udid: udid, extra: extra)
        return SupervisionStatus(supervised: json["supervised"] as? Bool ?? false,
                                 hostCertificateRegistered: json["host_cert_registered"] as? Bool ?? false)
    }

    public func status(udid: String, identity: SupervisionIdentity?) async throws -> SupervisionStatus {
        var extra: [String] = []
        if let identity { extra += ["--cert", identity.certificateURL.path] }
        let json = try await helper.call("status", udid: udid, extra: extra)
        return SupervisionStatus(supervised: json["supervised"] as? Bool ?? false,
                                 hostCertificateRegistered: json["host_cert_registered"] as? Bool ?? false,
                                 findMyOn: json["find_my_on"] as? Bool,
                                 allowPairing: json["allow_pairing"] as? Bool)
    }

    /// Silent when the phone trusts the Pax certificate; otherwise (allowManual)
    /// the profile is sent as a download and the user taps Install in Settings.
    public func installProfile(udid: String, profile: Data, identity: SupervisionIdentity,
                               allowManual: Bool) async throws -> ProfileInstallOutcome {
        var extra = ["--cert", identity.certificateURL.path, "--key", identity.privateKeyURL.path]
        if allowManual { extra.append("--allow-manual") }
        let json = try await helper.call("install-profile", udid: udid, extra: extra, stdin: profile)
        return (json["method"] as? String) == "silent" ? .silent : .pendingUser
    }

    public func profileIdentifiers(udid: String) async throws -> [String] {
        try await helper.call("profiles", udid: udid)["identifiers"] as? [String] ?? []
    }
}
