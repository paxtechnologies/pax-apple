// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// DeviceService backed by Apple's `cfgutil` (Apple Configurator automation tools).
///
/// Subcommands and options used here are taken from the cfgutil man page
/// (`man cfgutil`, mirrored at configautomation.omni-automation.com/cfgutil-man-page.html)
/// and `cfgutil help prepare`:
///   global:  -e/--ecid <ECID>, -C <cert.der>, -K <key.der>, --format JSON
///   list                      list attached devices
///   get <prop>...             e.g. isSupervised, firmwareVersion, UDID, configurationProfiles
///   backup                    local backup of a booted, set-up device
///   erase                     Erase All Content and Settings
///   prepare --supervised --name <org> --host-cert <cert.der> [--skip-* ...]
///   restore-backup [--source <UDID>]
///   install-profile <path or -> (silent when -C/-K identity is passed and device supervised)
///
/// NOT verified on hardware (no Mac in the build environment): the exact JSON
/// shape of `list` output, and whether newer Configurator versions renamed any
/// `--skip-*` flags. Run `cfgutil help prepare` and `cfgutil --format JSON list`
/// on a real Mac before release. Parsing below is defensive for that reason.
public struct CfgutilDeviceService: DeviceService {
    public static let defaultPath = URL(fileURLWithPath: "/usr/local/bin/cfgutil")

    public let cfgutil: URL
    public let runner: CommandRunner

    public init(cfgutil: URL = CfgutilDeviceService.defaultPath, runner: CommandRunner = ProcessRunner()) {
        self.cfgutil = cfgutil
        self.runner = runner
    }

    public func isAvailable() -> Bool {
        FileManager.default.isExecutableFile(atPath: cfgutil.path)
    }

    // MARK: - Low level

    /// Runs cfgutil in JSON mode and returns the decoded top-level dictionary.
    @discardableResult
    func runJSON(_ command: String, ecid: String? = nil, identity: SupervisionIdentity? = nil,
                 arguments: [String] = [], stdin: Data? = nil) async throws -> [String: Any] {
        guard isAvailable() else { throw DeviceServiceError.toolMissing(cfgutil.path) }
        var args: [String] = ["--format", "JSON"]
        if let ecid { args += ["-e", ecid] }
        if let identity {
            args += ["-C", identity.certificateURL.path, "-K", identity.privateKeyURL.path]
        }
        args.append(command)
        args += arguments
        let result = try await runner.run(cfgutil, arguments: args, stdin: stdin)
        let json = Self.lastJSONObject(in: result.stdout)
        if let json, (json["Type"] as? String) == "Error" {
            let message = (json["Message"] as? String) ?? "unknown error"
            let reason = (json["FailureReason"] as? String).map { " (\($0))" } ?? ""
            throw DeviceServiceError.commandFailed(command: command, message: message + reason)
        }
        guard result.exitCode == 0 else {
            let msg = result.stderrString.trimmingCharacters(in: .whitespacesAndNewlines)
            throw DeviceServiceError.commandFailed(command: command,
                                                   message: msg.isEmpty ? "exit \(result.exitCode)" : msg)
        }
        return json ?? [:]
    }

    /// cfgutil may print several JSON documents (progress, then result); keep the last.
    static func lastJSONObject(in data: Data) -> [String: Any]? {
        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return obj
        }
        let text = String(decoding: data, as: UTF8.self)
        for line in text.split(whereSeparator: \.isNewline).reversed() {
            if let d = line.data(using: .utf8),
               let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
                return obj
            }
        }
        return nil
    }

    /// `get` output: {"Output": {"<ECID>": {"<prop>": value}}}.
    static func properties(from json: [String: Any], ecid: String) -> [String: Any] {
        guard let output = json["Output"] as? [String: Any] else { return [:] }
        if let byDevice = output[ecid] as? [String: Any] { return byDevice }
        // Single-device output may be keyed differently; fall back to the only entry.
        if output.count == 1, let only = output.values.first as? [String: Any] { return only }
        return [:]
    }

    static func parseDevices(from json: [String: Any]) -> [ConnectedDevice] {
        guard let output = json["Output"] as? [String: Any] else { return [] }
        return output.compactMap { key, value -> ConnectedDevice? in
            guard let info = value as? [String: Any] else { return nil }
            let ecid = (info["ECID"] as? String) ?? key
            return ConnectedDevice(
                ecid: ecid,
                udid: info["UDID"] as? String,
                name: (info["name"] as? String) ?? (info["deviceName"] as? String) ?? "iPhone",
                deviceType: (info["deviceType"] as? String) ?? "unknown")
        }.sorted { $0.name < $1.name }
    }

    // MARK: - DeviceService

    public func listDevices() async throws -> [ConnectedDevice] {
        let json = try await runJSON("list")
        var devices = Self.parseDevices(from: json)
        for i in devices.indices {
            devices[i].firmwareVersion = try? await firmwareVersion(ecid: devices[i].ecid)
            devices[i].isSupervised = try? await isSupervised(ecid: devices[i].ecid)
        }
        return devices
    }

    public func isSupervised(ecid: String) async throws -> Bool {
        let json = try await runJSON("get", ecid: ecid, arguments: ["isSupervised"])
        let props = Self.properties(from: json, ecid: ecid)
        if let b = props["isSupervised"] as? Bool { return b }
        if let n = props["isSupervised"] as? NSNumber { return n.boolValue }
        throw DeviceServiceError.unexpectedOutput("isSupervised missing")
    }

    public func firmwareVersion(ecid: String) async throws -> String? {
        let json = try await runJSON("get", ecid: ecid, arguments: ["firmwareVersion"])
        return Self.properties(from: json, ecid: ecid)["firmwareVersion"] as? String
    }

    public func backup(ecid: String) async throws {
        try await runJSON("backup", ecid: ecid)
    }

    public func erase(ecid: String) async throws {
        try await runJSON("erase", ecid: ecid)
    }

    public func prepareSupervised(ecid: String, organization: SupervisingOrganization,
                                  identity: SupervisionIdentity) async throws {
        var args = ["--supervised", "--name", organization.name,
                    "--host-cert", identity.certificateURL.path]
        if let email = organization.email { args += ["--email", email] }
        // Skip only panes that are safe to skip; the user still sets a passcode,
        // signs into their Apple Account and chooses Location Services themselves.
        args += ["--skip-tos", "--skip-diagnostics", "--skip-zoom"]
        // Deliberately NOT --forbid-pairing: it would stop Finder backups/sync.
        try await runJSON("prepare", ecid: ecid, arguments: args)
    }

    public func restoreBackup(ecid: String, sourceUDID: String?) async throws {
        var args: [String] = []
        if let sourceUDID { args += ["--source", sourceUDID] }
        try await runJSON("restore-backup", ecid: ecid, arguments: args)
    }

    public func installProfile(ecid: String, profile: Data, identity: SupervisionIdentity) async throws {
        // `-` = read the file from stdin (cfgutil man page, OPTIONS).
        try await runJSON("install-profile", ecid: ecid, identity: identity,
                          arguments: ["-"], stdin: profile)
    }

    public func installedProfileIdentifiers(ecid: String) async throws -> [String] {
        let json = try await runJSON("get", ecid: ecid, arguments: ["configurationProfiles"])
        let value = Self.properties(from: json, ecid: ecid)["configurationProfiles"]
        // Shape not verified on hardware; collect every string that looks like an identifier.
        var ids: [String] = []
        func walk(_ v: Any?) {
            switch v {
            case let s as String where s.contains("."): ids.append(s)
            case let a as [Any]: a.forEach(walk)
            case let d as [String: Any]: d.values.forEach(walk)
            default: break
            }
        }
        walk(value)
        return ids
    }
}
