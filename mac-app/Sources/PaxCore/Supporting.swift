// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// MARK: - Supervision identity

/// Creates a throw-away supervision identity with /usr/bin/openssl, using the
/// recipe from the cfgutil man page ("GENERATING SUPERVISION IDENTITIES").
///
/// Pax deletes the private key once the profile is installed (see
/// `destroyPrivateKey`): whoever holds it can manage the supervised phone, so
/// keeping it on the Mac would hand the user a way around their own lock.
/// Consequence: changing blocks later means removal (with the wait) + set-up again.
///
/// v0.2 (Keep my data): the certificate goes into the phone's cloud configuration
/// (SupervisorHostCertificates) so the profile installs silently; then the key is
/// destroyed. attention awareness registers no supervisor certificate at all and
/// has the user tap Install in Settings, which confirms the key is not needed after
/// set-up. Pax falls back to that when silent install fails.
public struct SupervisionIdentityStore: Sendable {
    public let directory: URL
    public let runner: CommandRunner
    public let openssl = URL(fileURLWithPath: "/usr/bin/openssl")

    public init(directory: URL? = nil, runner: CommandRunner = ProcessRunner()) {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        self.directory = directory ?? base.appendingPathComponent("Pax/identity", isDirectory: true)
        self.runner = runner
    }

    public func create() async throws -> SupervisionIdentity {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let tmpKey = directory.appendingPathComponent("tmp-privkey.pem")
        let tmpCert = directory.appendingPathComponent("tmp-cert.pem")
        let keyDER = directory.appendingPathComponent("identity-key.der")
        let certDER = directory.appendingPathComponent("identity-cert.der")
        let steps: [[String]] = [
            ["genrsa", "-out", tmpKey.path, "2048"],
            ["req", "-new", "-x509", "-key", tmpKey.path, "-out", tmpCert.path,
             "-days", "3650", "-subj", "/CN=Pax Supervision Identity/O=Pax"],
            ["rsa", "-outform", "DER", "-out", keyDER.path, "-in", tmpKey.path],
            ["x509", "-outform", "DER", "-out", certDER.path, "-in", tmpCert.path],
        ]
        for args in steps {
            let r = try await runner.run(openssl, arguments: args, stdin: nil)
            guard r.exitCode == 0 else {
                throw DeviceServiceError.commandFailed(command: "openssl \(args[0])", message: r.stderrString)
            }
        }
        try? fm.removeItem(at: tmpKey)
        try? fm.removeItem(at: tmpCert)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyDER.path)
        return SupervisionIdentity(certificateURL: certDER, privateKeyURL: keyDER)
    }

    public func destroyPrivateKey(_ identity: SupervisionIdentity) {
        SecureFile.overwriteAndDelete(identity.privateKeyURL)
    }
}

enum SecureFile {
    /// Best-effort overwrite then delete. (APFS copy-on-write means this is not a
    /// forensic guarantee; it stops casual recovery.)
    static func overwriteAndDelete(_ url: URL) {
        if let handle = try? FileHandle(forWritingTo: url) {
            let size = (try? handle.seekToEnd()) ?? 0
            try? handle.seek(toOffset: 0)
            handle.write(Data(repeating: 0, count: Int(size)))
            try? handle.close()
        }
        try? FileManager.default.removeItem(at: url)
    }
}

// MARK: - Profile generation

public struct GeneratedProfile: Sendable {
    public let profileData: Data
    public let profileIdentifier: String
    public let removalPassword: String
    public let platform: String
}

/// Runs profile/make_profile.py (from this repo) and reads its outputs from a
/// private temp directory, deleting them immediately. A native Swift generator
/// (or server-side generation) is on the roadmap so Python is not required.
public struct ProfileGenerator: Sendable {
    public let python: URL
    public let script: URL
    /// Interpreter flags before the script: `-I -B` on the Python bundled in Pax.app
    /// (v0.8.6), so it ignores the user's PYTHON* settings and never writes .pyc files
    /// into the signed app.
    public let interpreterArguments: [String]
    public let runner: CommandRunner

    public init(script: URL, python: URL = URL(fileURLWithPath: "/usr/bin/python3"),
                interpreterArguments: [String] = [], runner: CommandRunner = ProcessRunner()) {
        self.script = script
        self.python = python
        self.interpreterArguments = interpreterArguments
        self.runner = runner
    }

    /// v0.8.6: the bundled Python when Pax.app has one (no Command Line Tools prompt on the
    /// iPhone path), else /usr/bin/python3 as before.
    public init(script: URL, interpreter: BundledHelper, runner: CommandRunner = ProcessRunner()) {
        self.init(script: script, python: interpreter.profilePython,
                  interpreterArguments: interpreter.isBundled ? interpreter.arguments : [], runner: runner)
    }

    /// `userToken` (per-user pax-dns, v0.3) wins over `resolverURL` (a custom DoH
    /// URL), which wins over `filter`. `dnsBase` only applies with a token.
    public static func arguments(script: URL, platform: String, out: URL, escrow: URL,
                                 filter: DNSFilter, resolverURL: String?,
                                 blockApps: [String], blockURLs: [String],
                                 userToken: String? = nil, dnsBase: String? = nil,
                                 youtubeRestricted: Bool = true) -> [String] {
        var args = [script.path, "--platform", platform, "--out", out.path, "--escrow-out", escrow.path]
        if let userToken {
            args += ["--user-token", userToken]
            if let dnsBase { args += ["--dns-base", dnsBase] }
        } else if let resolverURL {
            args += ["--resolver-url", resolverURL]
        } else {
            args += ["--filter", filter.rawValue]
        }
        for app in blockApps { args += ["--block-app", app] }
        for url in blockURLs { args += ["--block-url", url] }
        if !youtubeRestricted { args.append("--no-youtube-restricted") }   // v0.8.6
        return args
    }

    public func generate(platform: String = "ios", filter: DNSFilter = .family, resolverURL: String? = nil,
                         blockApps: [String] = [], blockURLs: [String] = [],
                         userToken: String? = nil, dnsBase: String? = nil,
                         youtubeRestricted: Bool = true) async throws -> GeneratedProfile {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("pax-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: dir) }
        let out = dir.appendingPathComponent("pax.mobileconfig")
        let escrow = dir.appendingPathComponent("escrow.json")
        let args = Self.arguments(script: script, platform: platform, out: out, escrow: escrow,
                                  filter: filter, resolverURL: resolverURL,
                                  blockApps: blockApps, blockURLs: blockURLs,
                                  userToken: userToken, dnsBase: dnsBase, youtubeRestricted: youtubeRestricted)
        let r = try await runner.run(python, arguments: interpreterArguments + args, stdin: nil)
        guard r.exitCode == 0 else {
            throw DeviceServiceError.commandFailed(command: "make_profile.py", message: r.stderrString)
        }
        let data = try Data(contentsOf: out)
        let record = try JSONSerialization.jsonObject(with: Data(contentsOf: escrow)) as? [String: Any] ?? [:]
        SecureFile.overwriteAndDelete(out)
        SecureFile.overwriteAndDelete(escrow)
        guard let pw = record["removal_password"] as? String,
              let ident = record["profile_identifier"] as? String else {
            throw DeviceServiceError.unexpectedOutput("escrow record incomplete")
        }
        return GeneratedProfile(profileData: data, profileIdentifier: ident,
                                removalPassword: pw, platform: platform)
    }
}

// MARK: - Mac self-lock profile (v0.4)

public struct MacSelfLockProfile: Sendable {
    public let data: Data
    public let identifier: String
    public let resolverURL: String
}

extension ProfileGenerator {
    /// `make_profile.py --self-lock`: DNS + Private Relay off + browser policies,
    /// no removal password (the paxadmin password is the escrowed secret).
    public static func selfLockArguments(script: URL, out: URL, filter: DNSFilter,
                                         userToken: String? = nil, dnsBase: String? = nil,
                                         blockURLs: [String] = [], adblock: Bool = true,
                                         imageBlur: Bool = false, imageBlurSwitchable: Bool = false) -> [String] {
        var args = [script.path, "--self-lock", "--out", out.path]
        if let userToken {
            args += ["--user-token", userToken]
            if let dnsBase { args += ["--dns-base", dnsBase] }
        } else {
            args += ["--filter", filter.rawValue]
        }
        for url in blockURLs { args += ["--block-url", url] }
        if !adblock { args.append("--no-adblock") }
        if imageBlur { args.append("--image-blur") }  // v0.6 "Pax Max", opt-in
        if imageBlurSwitchable { args.append("--image-blur-switchable") }  // v0.8.12
        return args
    }

    /// Writes the profile to `out` (0600) and returns its identifier.
    public func generateMacSelfLock(out: URL, filter: DNSFilter = .family, userToken: String? = nil,
                                    dnsBase: String? = nil, blockURLs: [String] = [],
                                    adblock: Bool = true, imageBlur: Bool = false,
                                    imageBlurSwitchable: Bool = false) async throws -> MacSelfLockProfile {
        let args = Self.selfLockArguments(script: script, out: out, filter: filter, userToken: userToken,
                                          dnsBase: dnsBase, blockURLs: blockURLs, adblock: adblock,
                                          imageBlur: imageBlur, imageBlurSwitchable: imageBlurSwitchable)
        let r = try await runner.run(python, arguments: interpreterArguments + args, stdin: nil)
        guard r.exitCode == 0 else {
            throw DeviceServiceError.commandFailed(command: "make_profile.py --self-lock", message: r.stderrString)
        }
        let info = (try? JSONSerialization.jsonObject(with: r.stdout)) as? [String: Any] ?? [:]
        guard let ident = info["profile_identifier"] as? String else {
            throw DeviceServiceError.unexpectedOutput("make_profile.py printed no profile identifier")
        }
        let resolver = info["resolver_url"] as? String ?? ""
        return MacSelfLockProfile(data: try Data(contentsOf: out), identifier: ident, resolverURL: resolver)
    }
}

// MARK: - Mock (SwiftUI previews, demo mode)

public final class MockDeviceService: DeviceService, @unchecked Sendable {
    public var supervised = false
    public init() {}
    public func isAvailable() -> Bool { true }
    public func listDevices() async throws -> [ConnectedDevice] {
        [ConnectedDevice(ecid: "0x1A2B3C4D5E6F", udid: "00008110-DEMO", name: "Demo iPhone",
                         deviceType: "iPhone16,1", firmwareVersion: "27.0", isSupervised: supervised)]
    }
    public func isSupervised(ecid: String) async throws -> Bool { supervised }
    public func firmwareVersion(ecid: String) async throws -> String? { "27.0" }
    public func backup(ecid: String) async throws { try await Task.sleep(nanoseconds: 300_000_000) }
    public func erase(ecid: String) async throws { try await Task.sleep(nanoseconds: 300_000_000) }
    public func prepareSupervised(ecid: String, organization: SupervisingOrganization,
                                  identity: SupervisionIdentity) async throws {
        try await Task.sleep(nanoseconds: 300_000_000)
        supervised = true
    }
    public func restoreBackup(ecid: String, sourceUDID: String?) async throws {}
    public func installProfile(ecid: String, profile: Data, identity: SupervisionIdentity) async throws {}
    public func installedProfileIdentifiers(ecid: String) async throws -> [String] { [] }
}

/// Canned answers for the device helper (PAX_DEMO=1): an iPhone on iOS 27.2 that
/// needs Trust once after the restart, then takes the live configuration.
public final class DemoHelperRunner: CommandRunner, @unchecked Sendable {
    private let lock = NSLock()
    private var connectCalls = 0
    public var iosVersion = "27.2"
    public init() {}

    private func nextConnectCall() -> Int {
        lock.lock(); defer { lock.unlock() }
        connectCalls += 1
        return connectCalls
    }

    public func run(_ executable: URL, arguments: [String], stdin: Data?) async throws -> CommandResult {
        try await Task.sleep(nanoseconds: 400_000_000)
        let command = arguments.dropFirst().first ?? ""
        let mode = KeepDataPlan.forVersion(iosVersion).method?.rawValue ?? "null"
        let reply: String
        switch command {
        case "list":
            reply = #"{"ok":true,"devices":[{"udid":"00008110-DEMO","name":"Demo iPhone","product_type":"iPhone12,8","ios":"\#(iosVersion)","paired":true,"supervised":false}]}"#
        case "preflight":
            let confirmed = arguments.contains("--backup-confirmed")
            reply = confirmed
                ? #"{"ok":true,"mode":"\#(mode)","blocking":[],"warnings":[],"ask_user_find_my":false,"facts":{"battery_level":82,"find_my_on":false}}"#
                : #"{"ok":true,"mode":"\#(mode)","blocking":["Make a backup first and confirm it finished."],"warnings":[],"ask_user_find_my":false,"facts":{"battery_level":82,"find_my_on":false}}"#
        case "backup":
            reply = #"{"ok":true,"backup":"/tmp/pax-demo-backup/00008110-DEMO","verified":true}"#
        case "seed-restore":
            reply = #"{"ok":true,"mode":"\#(mode)","next":"reconnect"}"#
        case "connect":
            let n = nextConnectCall()
            let state = n < 3 ? "not_found" : (n == 3 ? "trust_requested" : "paired")
            reply = #"{"ok":true,"state":"\#(state)"}"#
        case "live-configure", "status":
            reply = #"{"ok":true,"supervised":true,"host_cert_registered":true,"find_my_on":false}"#
        case "install-profile":
            reply = #"{"ok":true,"installed":true,"method":"silent"}"#
        case "profiles":
            reply = #"{"ok":true,"identifiers":[]}"#
        default:
            reply = #"{"ok":false,"code":"unknown","error":"unknown command"}"#
        }
        return CommandResult(exitCode: 0, stdout: Data(reply.utf8), stderr: Data())
    }
}
