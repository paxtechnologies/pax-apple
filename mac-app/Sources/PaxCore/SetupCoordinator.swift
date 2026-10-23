// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.8: the account's settings on Pax's DNS filter (iPhone/iPad).
/// v0.8.13: only YouTube Restricted Mode is a setting; pictures and video on X and
/// Bluesky are always blocked (AlwaysBlockedMedia), so they're no longer sent.
public struct PaxFilterSettings: Sendable, Equatable {
    public var youtubeRestricted: Bool
    public init(youtubeRestricted: Bool = true) {
        self.youtubeRestricted = youtubeRestricted
    }
}

/// Everything the user chose in the guided flow.
public struct SetupConfiguration: Sendable {
    public var email: String
    public var waitDays: Int            // 3...365, default 3 (= 72 h)
    public var partnerEmail: String?
    /// Default since v0.2: keep the phone's data (no erase).
    public var mode: SupervisionMode
    /// Default since v0.2: CleanBrowsing Family Filter.
    public var dnsFilter: DNSFilter
    /// Custom DoH URL (e.g. self-hosted pax-dns). Overrides `dnsFilter`.
    public var customResolverURL: String?
    /// v0.3 synced blocklist: when set (v0.8.8 default "https://dns.paxpeace.com", Pax's own filter), the profile's
    /// DNS points at `<base>/u/<token>/dns-query` with the account's pax-dns token, so
    /// the custom blocklist applies on every device. Overrides the two above. Nil keeps
    /// v0.2 behaviour (CleanBrowsing directly) until a pax-dns server is running.
    public var dnsBase: String?
    public var customBlockedApps: [String]
    public var customBlockedURLs: [String]
    /// Keep my data only, OFF by default: AllowPairing = false in the cloud
    /// configuration, so no other computer can pair with the phone. That also stops
    /// the same no-erase trick being used to unsupervise it, but Finder backups to
    /// any computer stop too. Untested on hardware.
    public var forbidPairing: Bool
    /// Clean mode only, experimental and OFF by default: restore the local backup after
    /// supervising. Apple documents that an unsupervised device's backup "can be restored
    /// only to an unsupervised device", and on iOS 27 restores drop supervision status, so
    /// this will usually undo supervision. We verify afterwards and stop if so.
    public var restoreBackupAfterPrepare: Bool
    /// v0.8.6: YouTube Restricted Mode (on by default). Fixed in the iPhone's locked
    /// profile at set-up: changing it later means setting the iPhone up again.
    public var youtubeRestricted: Bool = true
    /// v0.8.8: what the user chose for Pax's DNS filter (sent to the server just before the
    /// profile is made, only when `dnsBase` is set).
    public var filterSettings = PaxFilterSettings()
    /// v0.8.15 "Allow verified support release": on by default for new set-ups, with one
    /// calm line on the wait step where it can be switched off.
    public var supportRelease: Bool = VerifiedSupportRelease.setUpDefault

    public init(email: String = "", waitDays: Int = 3, partnerEmail: String? = nil,
                mode: SupervisionMode = .keepData, dnsFilter: DNSFilter = .family,
                customResolverURL: String? = nil, dnsBase: String? = nil, customBlockedApps: [String] = [],
                customBlockedURLs: [String] = [], forbidPairing: Bool = false,
                restoreBackupAfterPrepare: Bool = false) {
        self.email = email
        self.waitDays = waitDays
        self.partnerEmail = partnerEmail
        self.mode = mode
        self.dnsFilter = dnsFilter
        self.customResolverURL = customResolverURL
        self.dnsBase = dnsBase
        self.customBlockedApps = customBlockedApps
        self.customBlockedURLs = customBlockedURLs
        self.forbidPairing = forbidPairing
        self.restoreBackupAfterPrepare = restoreBackupAfterPrepare
    }
}

public enum SetupStepEvent: Sendable, Equatable {
    case started(String)
    case finished(String)
    case waitingForUser(String)
}

public enum SetupError: Error, LocalizedError, Equatable {
    case supervisionLost
    case supervisionNotConfirmed
    case profileNotVerified
    case keepDataUnavailable(String)
    case helperMissing

    public var errorDescription: String? {
        switch self {
        case .supervisionLost:
            return "Restoring the backup removed supervision, as Apple documents. Erase and run "
                + "Clean setup again without restoring the backup, then use iCloud to bring your "
                + "photos, messages and contacts back."
        case .supervisionNotConfirmed:
            return "The iPhone doesn't report itself as supervised, so Pax hasn't stored a password or "
                + "installed anything. Nothing is locked. Try Keep my data again, or use Clean set-up."
        case .profileNotVerified:
            return "The Pax profile was sent but could not be found on the device."
        case .keepDataUnavailable(let why):
            return why
        case .helperMissing:
            return "Pax's iPhone helper is missing from this copy of Pax. Download Pax again and drag it to Applications."
        }
    }
}

/// Orchestrates the device side of set-up. Order matters for safety:
///   1. supervise (Keep my data: preflight -> seed restore -> [iOS 27: live config];
///                 Clean: backup -> erase -> prepare)
///   2. CONFIRM supervision (read back from the phone). Nothing below runs without it.
///   3. generate profile + password
///   4. ESCROW FIRST: register the device and password with the server
///   5. only then install the locked profile, and verify it
///   6. destroy local secrets (profile bytes, password, supervision key)
/// If step 5 fails after step 4, the server simply holds an unused password;
/// the reverse order could lock a phone with nobody holding the password.
public final class SetupCoordinator: @unchecked Sendable {
    public let devices: DeviceService
    public let keepData: KeepDataSupervisor?
    public let identities: SupervisionIdentityStore
    public let profiles: ProfileGenerator
    public var escrow: EscrowClient
    /// v0.8.8: is Pax's DNS filter answering at this base? Checked before a profile that
    /// points at it is locked onto a phone. Replaceable in tests.
    public var dnsHealth: @Sendable (String) async -> Bool = { await PaxDNS.isHealthy(base: $0) }

    public init(devices: DeviceService, keepData: KeepDataSupervisor? = nil,
                identities: SupervisionIdentityStore, profiles: ProfileGenerator, escrow: EscrowClient) {
        self.devices = devices
        self.keepData = keepData
        self.identities = identities
        self.profiles = profiles
        self.escrow = escrow
    }

    /// Wait + partner on the account. Called before touching the phone. v0.8.32: the
    /// account itself comes first from the emailed code (EscrowClient.verifyEmailCode);
    /// nothing here makes one.
    public func saveAccountSettings(_ config: SetupConfiguration) async throws {
        guard escrow.token != nil else { throw EmailNotConfirmed() }
        try await escrow.setWait(days: config.waitDays)
        if let partner = config.partnerEmail, !partner.isEmpty {
            try await escrow.setPartner(email: partner)
        }
    }

    // MARK: Keep my data

    private func keepDataSupervisor() throws -> KeepDataSupervisor {
        guard let keepData, keepData.helper.isAvailable() else { throw SetupError.helperMissing }
        return keepData
    }

    static func udid(_ device: ConnectedDevice) -> String { device.udid ?? device.ecid }

    public func keepDataPreflight(_ device: ConnectedDevice, findMyConfirmedOff: Bool,
                                  backupConfirmed: Bool) async throws -> KeepDataPreflight {
        try await keepDataSupervisor().preflight(udid: Self.udid(device), findMyConfirmedOff: findMyConfirmedOff,
                                                 backupConfirmed: backupConfirmed)
    }

    public func keepDataBackup(_ device: ConnectedDevice) async throws -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return try await keepDataSupervisor().backup(udid: Self.udid(device),
                                                     directory: base.appendingPathComponent("Pax/Backups"))
    }

    /// Creates the supervision identity and restores the seed. iOS 17-26: the phone
    /// restarts supervised. iOS 27: it restarts into Setup and `keepDataConfirm`
    /// sends the live configuration.
    public func keepDataStart(_ device: ConnectedDevice, config: SetupConfiguration,
                              preflight: KeepDataPreflight,
                              progress: @escaping @Sendable (SetupStepEvent) -> Void)
        async throws -> (identity: SupervisionIdentity, outcome: SeedRestoreOutcome) {
        let supervisor = try keepDataSupervisor()
        guard preflight.ok, let method = preflight.method,
              KeepDataPlan.forVersion(device.firmwareVersion).method.map({ $0 == method }) ?? true else {
            throw SetupError.keepDataUnavailable(
                preflight.blocking.first ?? KeepDataPlan.forVersion(device.firmwareVersion).explanation)
        }
        let identity = try await identities.create()
        progress(.started(method == .live ? "Restoring the supervision settings (iOS 27 method)"
                                          : "Restoring the supervision settings"))
        let outcome = try await supervisor.seedRestore(udid: Self.udid(device), identity: identity,
                                                       forbidPairing: config.forbidPairing)
        if outcome.alreadySupervised {
            progress(.finished("Already supervised. Skipping to protection."))
        } else {
            progress(.finished("Settings restored. The iPhone is restarting."))
        }
        return (identity, outcome)
    }

    public func keepDataConnect(_ device: ConnectedDevice) async throws -> PhoneConnectState {
        try await keepDataSupervisor().connect(udid: Self.udid(device))
    }

    /// After the phone is back and paired: iOS 27 sends the live configuration, then
    /// both methods read supervision back. Throws unless the phone says supervised.
    public func keepDataConfirm(_ device: ConnectedDevice, identity: SupervisionIdentity,
                                method: KeepDataMethod, config: SetupConfiguration,
                                progress: @escaping @Sendable (SetupStepEvent) -> Void) async throws -> SupervisionStatus {
        let supervisor = try keepDataSupervisor()
        let udid = Self.udid(device)
        if method == .live {
            progress(.started("Supervising while the iPhone waits in Setup"))
            _ = try await supervisor.liveConfigure(udid: udid, identity: identity,
                                                   forbidPairing: config.forbidPairing)
        }
        progress(.started("Checking supervision"))
        let status = try await supervisor.status(udid: udid, identity: identity)
        guard status.supervised else { throw SetupError.supervisionNotConfirmed }
        progress(.finished("Supervised" + (status.hostCertificateRegistered ? "" : " (you'll tap Install in Settings)")))
        return status
    }

    // MARK: Clean

    public func supervise(_ device: ConnectedDevice, config: SetupConfiguration,
                          waitForSetupAssistant: @escaping @Sendable () async -> Void,
                          progress: @escaping @Sendable (SetupStepEvent) -> Void) async throws -> SupervisionIdentity {
        guard config.mode == .clean else {
            throw SetupError.keepDataUnavailable("Keep my data runs step by step; use keepDataStart.")
        }
        let identity = try await identities.create()

        progress(.started("Backing up \(device.name)"))
        try await devices.backup(ecid: device.ecid)
        progress(.finished("Backup saved on this Mac"))

        progress(.started("Erasing \(device.name)"))
        try await devices.erase(ecid: device.ecid)
        progress(.waitingForUser("Wait for the Hello screen, then keep the phone connected"))
        await waitForSetupAssistant()

        progress(.started("Supervising"))
        try await devices.prepareSupervised(ecid: device.ecid,
                                            organization: SupervisingOrganization(),
                                            identity: identity)
        guard try await devices.isSupervised(ecid: device.ecid) else { throw SetupError.supervisionLost }
        progress(.finished("Supervised"))

        if config.restoreBackupAfterPrepare, let udid = device.udid {
            progress(.started("Restoring backup (experimental)"))
            try await devices.restoreBackup(ecid: device.ecid, sourceUDID: udid)
            guard try await devices.isSupervised(ecid: device.ecid) else { throw SetupError.supervisionLost }
            progress(.finished("Backup restored and still supervised"))
        }
        return identity
    }

    // MARK: Lock

    /// Re-reads supervision from the phone right before anything is escrowed.
    func confirmSupervised(_ device: ConnectedDevice, identity: SupervisionIdentity,
                           mode: SupervisionMode) async throws -> SupervisionStatus {
        switch mode {
        case .keepData:
            let status = try await keepDataSupervisor().status(udid: Self.udid(device), identity: identity)
            guard status.supervised else { throw SetupError.supervisionNotConfirmed }
            return status
        case .clean:
            guard try await devices.isSupervised(ecid: device.ecid) else { throw SetupError.supervisionNotConfirmed }
            return SupervisionStatus(supervised: true, hostCertificateRegistered: true)
        }
    }

    /// Returns `.pendingUser` when the profile was sent as a download and the user
    /// must tap Install in Settings (then call `verifyProfileInstalled`).
    @discardableResult
    public func lockAndEscrow(_ device: ConnectedDevice, identity: SupervisionIdentity,
                              config: SetupConfiguration,
                              progress: @escaping @Sendable (SetupStepEvent) -> Void) async throws -> ProfileInstallOutcome {
        defer { identities.destroyPrivateKey(identity) }

        progress(.started("Confirming the iPhone is supervised"))
        _ = try await confirmSupervised(device, identity: identity, mode: config.mode)
        progress(.finished("Supervision confirmed"))

        progress(.started("Creating your protection profile"))
        var userToken: String? = nil
        if let base = config.dnsBase {
            // v0.8.8: a locked profile can't be changed, so never lock a phone to a
            // filter that isn't answering (PAX-DNS-012).
            guard await dnsHealth(base) else { throw PaxError("PAX-DNS-012", technical: base) }
            let f = config.filterSettings
            try await escrow.setDNSSettings(youtubeRestricted: f.youtubeRestricted)
            // Same token on every device of this account: one synced blocklist.
            userToken = try await escrow.dnsInfo().token
        }
        var generated: GeneratedProfile? = try await profiles.generate(
            platform: "ios", filter: config.dnsFilter, resolverURL: config.customResolverURL,
            blockApps: config.customBlockedApps, blockURLs: config.customBlockedURLs,
            userToken: userToken, dnsBase: config.dnsBase, youtubeRestricted: config.youtubeRestricted)
        defer { generated = nil }
        guard let profile = generated else { throw SetupError.profileNotVerified }

        progress(.started("Handing the removal password to Pax escrow"))
        _ = try await escrow.registerDevice(name: device.name, platform: "ios",
                                            profileIdentifier: profile.profileIdentifier,
                                            removalPassword: profile.removalPassword,
                                            supportRelease: config.supportRelease,
                                            // v0.8.18: a trial day, counted from this phone's first one.
                                            trial: TrialDay.setUpDefault,
                                            hardwareID: TrialDay.hardwareID(device.ecid))
        progress(.finished("Password escrowed. You will not see it."))

        progress(.started("Installing protection on \(device.name)"))
        let outcome: ProfileInstallOutcome
        switch config.mode {
        case .keepData:
            outcome = try await keepDataSupervisor().installProfile(
                udid: Self.udid(device), profile: profile.profileData, identity: identity,
                allowManual: true)
            if outcome == .pendingUser {
                progress(.waitingForUser("On the iPhone: Settings > Profile Downloaded > Install, then enter your passcode"))
                return .pendingUser
            }
            let installed = try await keepDataSupervisor().profileIdentifiers(udid: Self.udid(device))
            guard installed.contains(profile.profileIdentifier) else { throw SetupError.profileNotVerified }
        case .clean:
            try await devices.installProfile(ecid: device.ecid, profile: profile.profileData, identity: identity)
            outcome = .silent
            let installed = try await devices.installedProfileIdentifiers(ecid: device.ecid)
            if installed.isEmpty {
                // cfgutil's configurationProfiles output shape is unverified; don't fail on it.
                progress(.waitingForUser("Check Settings > General > VPN & Device Management shows \"Pax\""))
            } else if !installed.contains(profile.profileIdentifier) {
                throw SetupError.profileNotVerified
            }
        }
        progress(.finished("Protection installed"))
        return outcome
    }

    /// After a manual install in Settings: true once the phone lists a Pax profile.
    public func verifyProfileInstalled(_ device: ConnectedDevice) async throws -> Bool {
        let ids = try await keepDataSupervisor().profileIdentifiers(udid: Self.udid(device))
        return ids.contains { $0.hasPrefix("org.paxpeace.pax.ios.") }
    }
}
