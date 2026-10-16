// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// An iPhone or iPad attached to this Mac over USB.
public struct ConnectedDevice: Identifiable, Equatable, Sendable {
    public var id: String { ecid }
    public let ecid: String
    public let udid: String?
    public let name: String
    public let deviceType: String
    public var firmwareVersion: String?
    public var isSupervised: Bool?

    public init(ecid: String, udid: String?, name: String, deviceType: String,
                firmwareVersion: String? = nil, isSupervised: Bool? = nil) {
        self.ecid = ecid
        self.udid = udid
        self.name = name
        self.deviceType = deviceType
        self.firmwareVersion = firmwareVersion
        self.isSupervised = isSupervised
    }

    /// Major iOS version, e.g. 27 for "27.0.1".
    public var majorOSVersion: Int? {
        firmwareVersion.flatMap { Int($0.split(separator: ".").first ?? "") }
    }
}

/// Organisation details shown on the device ("This iPhone is supervised by ...").
public struct SupervisingOrganization: Sendable {
    public var name: String
    public var email: String?

    public init(name: String = "Pax (self-managed)", email: String? = nil) {
        self.name = name
        self.email = email
    }
}

/// Supervision identity: DER certificate + DER private key on disk.
public struct SupervisionIdentity: Sendable {
    public let certificateURL: URL
    public let privateKeyURL: URL

    public init(certificateURL: URL, privateKeyURL: URL) {
        self.certificateURL = certificateURL
        self.privateKeyURL = privateKeyURL
    }
}

public enum SupervisionMode: String, CaseIterable, Identifiable, Sendable {
    /// Default since v0.2: supervise in place without erasing (iOS 17-27).
    /// See KeepDataSupervision.swift.
    case keepData
    /// Official Apple Configurator path: erase, then prepare as supervised.
    /// The fallback for iOS 28+, iOS < 17, or when Keep my data fails.
    case clean

    public var id: String { rawValue }
}

/// CleanBrowsing filter used for the profile's encrypted DNS.
public enum DNSFilter: String, CaseIterable, Identifiable, Sendable {
    /// Default since v0.2: restricted content, proxy/VPN domains and mixed-content
    /// sites such as Reddit; SafeSearch forced on Google, Bing and YouTube.
    case family
    /// Restricted content only (v0.1 default; CleanBrowsing's narrower filter).
    /// v0.8.1: renamed, `make_profile.py --filter core`.
    case core

    public var id: String { rawValue }
}

public enum DeviceServiceError: Error, LocalizedError, Equatable {
    case toolMissing(String)
    case commandFailed(command: String, message: String)
    case unexpectedOutput(String)
    case notSupported(String)
    case noDevice

    public var errorDescription: String? {
        switch self {
        case .toolMissing(let path):
            return "cfgutil was not found at \(path). Install Apple Configurator from the "
                + "Mac App Store, then choose Apple Configurator > Install Automation Tools."
        case .commandFailed(let command, let message):
            return "cfgutil \(command) failed: \(message)"
        case .unexpectedOutput(let detail):
            return "Unexpected cfgutil output: \(detail)"
        case .notSupported(let detail):
            return detail
        case .noDevice:
            return "No iPhone or iPad is connected."
        }
    }
}

/// Every device operation Pax performs goes through this protocol, so the UI can
/// be driven by a mock and the cfgutil backend can be swapped (e.g. for
/// pymobiledevice3 / go-ios in a cross-platform build later).
public protocol DeviceService: Sendable {
    /// True when the backing tool (cfgutil) is installed.
    func isAvailable() -> Bool
    func listDevices() async throws -> [ConnectedDevice]
    func isSupervised(ecid: String) async throws -> Bool
    func firmwareVersion(ecid: String) async throws -> String?
    /// Local backup into ~/Library/Application Support/MobileSync/Backup/<UDID>.
    func backup(ecid: String) async throws
    /// Erase All Content and Settings (device must be signed out of Find My).
    func erase(ecid: String) async throws
    /// Activate + supervise a device sitting in Setup Assistant.
    func prepareSupervised(ecid: String, organization: SupervisingOrganization,
                           identity: SupervisionIdentity) async throws
    /// Restore a local backup. The device must be freshly erased.
    func restoreBackup(ecid: String, sourceUDID: String?) async throws
    /// Silently install a profile on a supervised device. The profile bytes are
    /// piped over stdin so the removal password never touches disk here.
    func installProfile(ecid: String, profile: Data, identity: SupervisionIdentity) async throws
    /// Identifiers of installed configuration profiles (for verification).
    func installedProfileIdentifiers(ecid: String) async throws -> [String]
}
