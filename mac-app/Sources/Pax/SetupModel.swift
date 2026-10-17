// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import SwiftUI
import PaxCore

/// iPhone path (v0.7.0): four calm steps. Every check the old ten-step flow had is
/// still here; the technical ones run by themselves and only ask when they need you.
enum SetupStep: Int, CaseIterable, Identifiable {
    case connect, choose, wait, lockIn, done
    var id: Int { rawValue }

    var title: String {
        switch self {
        case .connect: return "Plug in"
        case .choose: return "What to block"
        case .wait: return TurnOffWait.stepTitle
        case .lockIn: return "Lock it in"
        case .done: return "Done"
        }
    }

    static let numbered: [SetupStep] = [.connect, .choose, .wait, .lockIn]
}

/// Top-level screens (v0.7.0).
enum AppScreen: Equatable {
    case welcome      // "This Mac" or "iPhone or iPad"
    case mac          // Mac path
    case iphone       // iPhone path
    case home         // after protection
    case blockedSites // full blocked-sites list
    case settings     // v0.8.14: the one Settings screen (app-wide), in this window. A device's own
                      // details and switches are on its page (Home for that device).
}

/// v0.7.0 device switcher: an iPhone or iPad this Mac has set up.
struct PaxDeviceRecord: Codable, Identifiable, Equatable {
    enum Status: String, Codable { case protected, pending }
    /// ECID (older records: the device name).
    let id: String
    var name: String
    var isIPad: Bool
    var iosVersion: String?
    var status: Status
    var keepData: Bool?
    var filter: String?
    /// Before 0.8.13: whether X / Bluesky media were blocked at set-up (switches then).
    /// Since 0.8.13 they're always blocked and new records say true; kept so a phone set
    /// up with either off can show what it needs (AlwaysBlockedMedia.legacyNote).
    var blocksXMedia: Bool?
    var blocksBlueskyMedia: Bool?
    /// v0.8.13: true when the phone's DNS goes through Pax's own filter (nil: older records).
    var usesPaxFilter: Bool?
    /// v0.8.6: YouTube Restricted Mode as set in the iPhone's profile (nil: before 0.8.6, on).
    var youtubeRestricted: Bool?
    /// v0.8.7: the user's own blocked apps in the profile (names, for the device's page).
    var blockedAppNames: [String]?
    /// The server's device_id, found after set-up.
    var escrowID: String?

    static let defaultsKey = "pax.devices"

    static func load(_ defaults: UserDefaults = .standard) -> [PaxDeviceRecord] {
        if let data = defaults.data(forKey: defaultsKey),
           let list = try? JSONDecoder().decode([PaxDeviceRecord].self, from: data) {
            return list
        }
        // v0.6 kept only names.
        return (defaults.stringArray(forKey: "pax.iphone.names") ?? []).map {
            PaxDeviceRecord(id: $0, name: $0, isIPad: false, status: .protected)
        }
    }

    static func save(_ list: [PaxDeviceRecord], _ defaults: UserDefaults = .standard) {
        if let data = try? JSONEncoder().encode(list) { defaults.set(data, forKey: defaultsKey) }
        defaults.set(list.filter { $0.status == .protected }.map(\.name), forKey: "pax.iphone.names")
    }
}

/// Where a Keep-my-data run is. The UI shows on-phone instructions for each.
enum KeepDataPhase: Equatable {
    case preflight
    case restoring
    case waitingForPhone(PhoneConnectState)
    case confirming
    case supervised
}

/// "Choose what to block" (shared by both paths).
struct BlockChoices: Equatable {
    /// Restricted content is always blocked (no switch). Ads and trackers: on by default.
    var adblock = true
    // v0.8.13: no X / Bluesky media switches: pictures and video there are always
    // blocked (AlwaysBlockedMedia), on every device.
    var paxMax = false
    /// v0.8.6: YouTube Restricted Mode, on by default.
    var youtubeRestricted = true
    var extraSitesText = ""
    /// v0.8.7 iPhone/iPad: the user's own blocked apps (bundle IDs, in the order chosen)
    /// and their names. Fixed in the locked profile until the phone is set up again.
    var blockedApps: [String] = []
    var blockedAppNames: [String: String] = [:]

    mutating func toggleApp(_ bundleID: String, name: String) {
        if let i = blockedApps.firstIndex(of: bundleID) {
            blockedApps.remove(at: i)
        } else {
            blockedApps.append(bundleID)
            blockedAppNames[bundleID] = name
        }
    }

    /// The user's own sites, normalised (example.com), from commas, spaces or new lines.
    var extraSites: [String] {
        var out: [String] = []
        for raw in extraSitesText.split(whereSeparator: { ",; \n\t".contains($0) }) {
            if let d = DomainInput.normalise(String(raw)), !out.contains(d) { out.append(d) }
        }
        return out
    }

    /// Words that couldn't be read as a site, to show gently under the field.
    var unreadableSites: [String] {
        extraSitesText.split(whereSeparator: { ",; \n\t".contains($0) }).map(String.init)
            .filter { DomainInput.normalise($0) == nil }
    }
}

/// Wait-time choices. v0.8.9: 24 hours to 365 days on the server and on a Mac's own
/// key alike; the picker shows only what the path in use accepts (WaitLimits: a
/// server older than 0.8.9 doesn't offer 24 hours).
enum WaitChoice: Int, CaseIterable, Identifiable {
    case day = 1, threeDays = 3, week = 7
    var id: Int { rawValue }
    var title: String {
        switch self {
        case .day, .threeDays, .week: return TurnOffWait.choiceTitle(days: rawValue)   // "1 day", "3 days", "7 days"
        }
    }
}

@MainActor
final class SetupModel: ObservableObject {
    @Published var step: SetupStep = .connect
    @Published var screen: AppScreen = .welcome
    @Published var config = SetupConfiguration()
    @Published var choices = BlockChoices()

    /// One plain agreement instead of three checkboxes: of age, my device, I understand the wait.
    @Published var agreed = false
    // Ready checks
    @Published var confirmedBackup = false
    @Published var confirmedFindMyOff = false

    @Published var devices: [ConnectedDevice] = []
    @Published var selected: ConnectedDevice?
    @Published var log: [String] = []
    @Published var busy = false
    /// A plain hint (not an error), e.g. what to do on the phone.
    @Published var errorMessage: String?
    /// v0.7.0: a classified failure with its support code.
    @Published var failure: PaxError?
    @Published var waitingForHello = false
    @Published var searching = false

    // Keep my data
    @Published var keepDataPhase: KeepDataPhase = .preflight
    @Published var preflight: KeepDataPreflight?
    @Published var paxBackupPath: String?
    @Published var keepDataMethod: KeepDataMethod?
    @Published var waitingTooLong = false
    // Protection
    @Published var supervised = false
    @Published var protecting = false
    @Published var profilePendingUser = false

    // v0.7.0 device switcher
    @Published var deviceRecords: [PaxDeviceRecord] = PaxDeviceRecord.load()
    /// "mac" or a PaxDeviceRecord id. Remembered between launches.
    @Published var selectedDevice: String = UserDefaults.standard.string(forKey: "pax.selectedDevice") ?? "mac" {
        didSet { UserDefaults.standard.set(selectedDevice, forKey: "pax.selectedDevice") }
    }
    @Published var phoneStatus: [String: EscrowClient.DeviceStatus] = [:]
    @Published var phoneStatusFetchedAt = Date()
    @Published var revealedPhonePassword: [String: String] = [:]

    let deviceService: DeviceService
    let coordinator: SetupCoordinator
    let cleanAvailable: Bool
    let tokenStore: TokenStore
    private var identity: SupervisionIdentity?
    private var helloContinuation: CheckedContinuation<Void, Never>?
    private var pollTask: Task<Void, Never>?
    private var searchTask: Task<Void, Never>?
    private var lastAction: (() -> Void)?

    init(deviceService: DeviceService, coordinator: SetupCoordinator,
         tokenStore: TokenStore = InMemoryTokenStore()) {
        self.deviceService = deviceService
        self.coordinator = coordinator
        self.cleanAvailable = deviceService.isAvailable()
        self.tokenStore = tokenStore
        if coordinator.escrow.token == nil, let saved = tokenStore.load() {
            coordinator.escrow.token = saved
        }
    }

    /// v0.8.8 Advanced: CleanBrowsing directly instead of Pax's filter. Sites added
    /// later, and the DNS settings, then never reach that phone (its profile is locked).
    var useDirectCleanBrowsing: Bool {
        get { config.dnsBase == nil }
        set { config.dnsBase = newValue ? nil : PaxDNS.setupBase(directCleanBrowsing: false) }
    }

    /// True once this Mac holds a Pax account token (Blocked sites needs it).
    var hasAccount: Bool { coordinator.escrow.token != nil }

    /// v0.8.9: the waits the server accepts (the picker offers only these).
    @Published var waitLimits: WaitLimits = .standard
    /// v0.8.9: the email already has a Pax account: a code was sent to it, and
    /// entering it signs this Mac in to that account (one shared list).
    @Published var signInCodeSentTo: String?
    @Published var signInCode = ""

    func loadWaitLimits() {
        Task { [weak self] in
            guard let self else { return }
            let limits = await self.coordinator.escrow.waitLimits()
            self.waitLimits = limits
            self.config.waitDays = limits.clamp(days: self.config.waitDays)
        }
    }

    static func live() -> SetupModel {
        let env = ProcessInfo.processInfo.environment
        let demo = env["PAX_DEMO"] == "1"
        let service: DeviceService = demo ? MockDeviceService() : CfgutilDeviceService()
        // PAX_SERVER_URL, else the server saved in Settings > Advanced (self-hosting), else the
        // production server https://api.paxpeace.com/ (v0.8.5).
        let server = ServerURLSetting.resolve(
            environment: env, stored: UserDefaults.standard.string(forKey: ServerURLSetting.defaultsKey))
        let script = ResourceLocator.locate(envKey: "PAX_PROFILE_SCRIPT", bundled: "profile/make_profile.py",
                                            devPath: "../profile/make_profile.py")
        let helperScript = ResourceLocator.locate(envKey: "PAX_DEVICE_HELPER", bundled: "device/pax_device.py",
                                                  devPath: "../device/pax_device.py")
        // v0.8.6: the helper runs on the Python inside Pax.app (PAX_PYTHON overrides it), so
        // plugging the iPhone in is all the set-up needs. No install step, venv or Homebrew.
        let interpreter = BundledHelper.resolve(environment: env)
        let helper = demo
            ? PaxDeviceHelper(script: helperScript, python: URL(fileURLWithPath: "/usr/bin/python3"),
                              runner: DemoHelperRunner(), assumeAvailable: true)
            : PaxDeviceHelper(script: helperScript, interpreter: interpreter)
        let coordinator = SetupCoordinator(
            devices: service,
            keepData: KeepDataSupervisor(helper: helper),
            identities: SupervisionIdentityStore(),
            profiles: ProfileGenerator(script: script, interpreter: interpreter),
            escrow: EscrowClient(baseURL: server))
        let model = SetupModel(deviceService: service, coordinator: coordinator,
                               tokenStore: demo ? InMemoryTokenStore() : KeychainTokenStore(serverURL: server))
        // v0.8.8: new iPhone/iPad set-ups point DNS at Pax's own filter
        // (https://dns.paxpeace.com/u/<token>/dns-query) unless PAX_DNS_BASE says otherwise or
        // the user picks CleanBrowsing directly under Advanced.
        model.config.dnsBase = PaxDNS.setupBase(environment: env, directCleanBrowsing: false)
        return model
    }

    var consentComplete: Bool { agreed }
    var emailLooksValid: Bool { config.email.contains("@") && config.email.contains(".") }
    var keepDataPlan: KeepDataPlan { KeepDataPlan.forVersion(selected?.firmwareVersion) }
    var keepDataAvailable: Bool {
        keepDataPlan.method != nil && (coordinator.keepData?.helper.isAvailable() ?? false)
    }
    /// Names that must never leave this Mac in "Copy details".
    var privateNames: [String] {
        devices.map(\.name) + [config.email] + (config.partnerEmail.map { [$0] } ?? [])
    }

    func next() {
        if let n = SetupStep(rawValue: step.rawValue + 1) { step = n }
    }

    func back() {
        if let p = SetupStep(rawValue: step.rawValue - 1) { step = p }
    }

    /// Back to the very start ("This Mac" or "iPhone or iPad").
    func startOver() {
        searchTask?.cancel()
        screen = .welcome
    }

    private func record(_ event: SetupStepEvent) {
        switch event {
        case .started(let s): log.append("… \(s)")
        case .finished(let s): log.append("✓ \(s)")
        case .waitingForUser(let s): log.append("→ \(s)")
        }
    }

    private var progressSink: @Sendable (SetupStepEvent) -> Void {
        { [weak self] e in Task { @MainActor in self?.record(e) } }
    }

    /// Runs work; a failure becomes a coded PaxError with "Try again" = run it again.
    private func run(_ work: @escaping () async throws -> Void) {
        busy = true
        errorMessage = nil
        failure = nil
        lastAction = { [weak self] in self?.run(work) }
        Task {
            do {
                try await work()
            } catch {
                let coded = PaxErrorClassifier.classify(error)
                failure = coded
                log.append("✗ \(coded.code) \(coded.technical)")
            }
            busy = false
        }
    }

    func retry() {
        let action = lastAction
        failure = nil
        action?()
    }

    func supportDetails(_ error: PaxError) -> String {
        Support.details(error, log: log, deviceOS: selected?.firmwareVersion, extraRedactions: privateNames)
    }

    // MARK: Step 1: find the iPhone (looks every 2 s until one appears)

    func startSearching() {
        searchTask?.cancel()
        searching = true
        searchTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.lookOnce()
                if !self.devices.isEmpty || self.failure != nil { break }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
            self?.searching = false
        }
    }

    func stopSearching() {
        searchTask?.cancel()
        searching = false
    }

    private func lookOnce() async {
        do {
            if deviceService.isAvailable() {
                devices = try await deviceService.listDevices()
            } else if let keepData = coordinator.keepData, keepData.helper.isAvailable() {
                // No Apple Configurator: Keep my data still works through the helper.
                devices = try await keepData.listDevices()
            } else {
                throw DeviceServiceError.toolMissing(CfgutilDeviceService.defaultPath.path)
            }
            if selected == nil || !devices.contains(where: { $0.ecid == selected?.ecid }) {
                selected = devices.first
            }
            failure = nil
        } catch {
            failure = PaxErrorClassifier.classify(error)
            lastAction = { [weak self] in self?.startSearching() }
        }
    }

    /// Lock it in: Keep my data when the phone's iOS allows it, else Clean.
    func chooseDefaultMode() {
        config.mode = keepDataAvailable ? .keepData : .clean
    }

    /// Wait step: creates or updates the account (email, wait, partner), then the
    /// user's own sites go on the synced list.
    func saveWaitAndAccount(then: @escaping () -> Void) {
        let sites = choices.extraSites
        run { [self] in
            // A token saved for a server whose database was reset no longer works:
            // forget it and register again (common with a local test server).
            if hasAccount {
                do {
                    _ = try await coordinator.escrow.accountSummary()
                } catch let e as EscrowClient.APIError where e.status == 401 {
                    tokenStore.clear()
                    coordinator.escrow.token = nil
                    if !emailLooksValid { throw e }   // the email field shows again
                }
            }
            // v0.8.9: signing in to an existing account with the emailed code.
            if !hasAccount, let sentTo = signInCodeSentTo, !signInCode.isEmpty {
                let account = try await coordinator.escrow.signIn(email: sentTo, code: signInCode,
                                                                  label: ProcessInfo.processInfo.hostName)
                coordinator.escrow.token = account.token
                try? tokenStore.save(account.token)
                signInCodeSentTo = nil
                signInCode = ""
            }
            do {
                try await coordinator.registerAccount(config)
            } catch let error where !hasAccount && EscrowClient.isExistingAccount(error) {
                // Same email as another device: use that account (shared list), with a code.
                try await coordinator.escrow.startSignIn(email: config.email)
                signInCodeSentTo = config.email
                return
            }
            if let token = coordinator.escrow.token { try? tokenStore.save(token) }
            for site in sites { _ = try? await coordinator.escrow.blockSite(site) }
            then()
        }
    }

    // MARK: Lock it in

    /// The single "Protect my iPhone" button: checks, then the right method.
    func startProtecting() {
        failure = nil
        if let device = selected { upsertRecord(device, status: .pending) }
        // The phone's own profile also blocks your sites in Safari (a second layer: Apple's
        // web filter only covers Safari and WebKit pages, and keeps the sites typed here;
        // Pax's DNS filter covers every app and later changes). v0.8.13: X and Bluesky
        // media are built into the profile (make_profile.py), always.
        config.customBlockedURLs = Array(choices.extraSites.prefix(BulkSiteImport.iosCustomLimit))
        if config.dnsFilter != .family { config.dnsBase = nil }   // Core exists on the direct path only
        // v0.8.8: on Pax's filter, YouTube Restricted Mode is applied by the filter (and can be
        // changed later), so the profile never carries the per-domain bypass.
        config.youtubeRestricted = config.dnsBase != nil ? true : choices.youtubeRestricted
        config.filterSettings = PaxFilterSettings(youtubeRestricted: choices.youtubeRestricted)
        config.customBlockedApps = choices.blockedApps       // v0.8.7
        if config.mode == .keepData {
            run { [self] in
                guard let device = selected else { throw DeviceServiceError.noDevice }
                preflight = try await coordinator.keepDataPreflight(
                    device,
                    findMyConfirmedOff: confirmedFindMyOff,
                    backupConfirmed: paxBackupPath != nil || confirmedBackup)
                if preflight?.ok == true {
                    Task { @MainActor in self.startKeepData() }
                } else {
                    throw PaxError("PAX-IOS-011", technical: (preflight?.blocking ?? []).joined(separator: "; "))
                }
            }
        } else {
            supervise()
        }
    }

    // MARK: Clean

    func userSawHelloScreen() {
        waitingForHello = false
        helloContinuation?.resume()
        helloContinuation = nil
    }

    func supervise() {
        guard let device = selected else { return }
        run { [self] in
            identity = try await coordinator.supervise(
                device, config: config,
                waitForSetupAssistant: { [weak self] in
                    await withCheckedContinuation { cont in
                        Task { @MainActor in
                            self?.helloContinuation = cont
                            self?.waitingForHello = true
                        }
                    }
                },
                progress: progressSink)
            supervised = true
        }
    }

    // MARK: Keep my data

    func runPreflight() {
        guard let device = selected else { return }
        run { [self] in
            preflight = try await coordinator.keepDataPreflight(
                device, findMyConfirmedOff: confirmedFindMyOff,
                backupConfirmed: paxBackupPath != nil || confirmedBackup)
        }
    }

    func backUpWithPax() {
        guard let device = selected else { return }
        run { [self] in
            record(.started("Backing up the iPhone to this Mac (this can take a while)"))
            paxBackupPath = try await coordinator.keepDataBackup(device).path
            record(.finished("Backup saved and checked"))
            preflight = try await coordinator.keepDataPreflight(
                device, findMyConfirmedOff: confirmedFindMyOff, backupConfirmed: true)
        }
    }

    func startKeepData() {
        guard let device = selected, let preflight, preflight.ok else { return }
        keepDataPhase = .restoring
        run { [self] in
            do {
                let (newIdentity, outcome) = try await coordinator.keepDataStart(
                    device, config: config, preflight: preflight, progress: progressSink)
                identity = newIdentity
                keepDataMethod = outcome.method
                if outcome.alreadySupervised {
                    keepDataPhase = .supervised
                    supervised = true
                } else {
                    waitForPhone()
                }
            } catch {
                keepDataPhase = .preflight
                throw error
            }
        }
    }

    /// Polls `connect` every 2 s while the phone is missing or locked. Stops as soon
    /// as a Trust prompt is showing (a Pair sent while the passcode is typed cancels
    /// it) and waits for `userTappedTrust`.
    private func waitForPhone() {
        guard let device = selected else { return }
        pollTask?.cancel()
        waitingTooLong = false
        let started = Date()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let state = (try? await self.coordinator.keepDataConnect(device)) ?? .notFound
                self.keepDataPhase = .waitingForPhone(state)
                if state == .paired { self.confirmKeepData(); return }
                if !state.pollAgain { return }
                if Date().timeIntervalSince(started) > 300 { self.waitingTooLong = true }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    func userTappedTrust() { waitForPhoneOnce() }

    private func waitForPhoneOnce() {
        guard let device = selected else { return }
        run { [self] in
            let state = try await coordinator.keepDataConnect(device)
            keepDataPhase = .waitingForPhone(state)
            if state == .paired { confirmKeepData() } else if state.pollAgain { waitForPhone() }
        }
    }

    func retryLiveConfiguration() { confirmKeepData() }

    private func confirmKeepData() {
        guard let device = selected, let identity, let method = keepDataMethod else { return }
        keepDataPhase = .confirming
        run { [self] in
            do {
                _ = try await coordinator.keepDataConfirm(device, identity: identity, method: method,
                                                          config: config, progress: progressSink)
                keepDataPhase = .supervised
                supervised = true
            } catch {
                keepDataPhase = .waitingForPhone(.paired)
                throw error
            }
        }
    }

    /// Advanced: erase and set up fresh instead.
    func fallBackToClean() {
        pollTask?.cancel()
        config.mode = .clean
        keepDataPhase = .preflight
        failure = nil
    }

    // MARK: Protect

    func protect() {
        guard let device = selected, let identity else { return }
        protecting = true
        run { [self] in
            do {
                let outcome = try await coordinator.lockAndEscrow(
                    device, identity: identity, config: config, progress: progressSink)
                self.identity = nil  // private key already destroyed by lockAndEscrow
                protecting = false
                if outcome == .pendingUser {
                    profilePendingUser = true
                } else {
                    finish(device)
                }
            } catch {
                protecting = false
                throw error
            }
        }
    }

    func checkProfileInstalled() {
        guard let device = selected else { return }
        run { [self] in
            if try await coordinator.verifyProfileInstalled(device) {
                profilePendingUser = false
                record(.finished("Protection installed"))
                finish(device)
            } else {
                throw SetupError.profileNotVerified
            }
        }
    }

    private func finish(_ device: ConnectedDevice) {
        upsertRecord(device, status: .protected)
        selectedDevice = device.ecid
        step = .done
        Task { await refreshPhones() }
    }

    /// Adds or updates this device in the switcher (pending while set-up runs).
    func upsertRecord(_ device: ConnectedDevice, status: PaxDeviceRecord.Status) {
        var rec = deviceRecords.first(where: { $0.id == device.ecid || $0.id == device.name })
            ?? PaxDeviceRecord(id: device.ecid, name: device.name, isIPad: device.deviceType.hasPrefix("iPad"),
                               status: status)
        rec.name = device.name
        rec.iosVersion = device.firmwareVersion
        if rec.status != .protected { rec.status = status }
        if status == .protected { rec.status = .protected }
        rec.keepData = config.mode == .keepData
        rec.filter = config.dnsFilter == .family ? "Family" : "Core"
        rec.blocksXMedia = true          // v0.8.13: always
        rec.blocksBlueskyMedia = true
        rec.usesPaxFilter = config.dnsBase != nil
        rec.youtubeRestricted = choices.youtubeRestricted
        rec.blockedAppNames = choices.blockedApps.map { choices.blockedAppNames[$0] ?? $0 }
        deviceRecords.removeAll { $0.id == rec.id || $0.id == device.name }
        deviceRecords.append(rec)
        PaxDeviceRecord.save(deviceRecords)
    }

    /// v0.8.7: the connected iPhone's apps for the set-up picker (icons in a temporary folder).
    var canListIPhoneApps: Bool {
        selected?.udid != nil && (coordinator.keepData?.helper.isAvailable() ?? false)
    }

    func loadIPhoneApps() async throws -> IPhoneAppList {
        guard let helper = coordinator.keepData, let udid = selected?.udid else {
            throw DeviceServiceError.noDevice
        }
        let icons = FileManager.default.temporaryDirectory.appendingPathComponent("pax-app-icons", isDirectory: true)
        return try await helper.installedApps(udid: udid, iconsDirectory: icons)
    }

    func forgetRecord(_ id: String) {
        deviceRecords.removeAll { $0.id == id }
        PaxDeviceRecord.save(deviceRecords)
        if selectedDevice == id { selectedDevice = "mac" }
    }

    /// iPhones and iPads this Mac has protected (shown on Home).
    var protectedPhones: [String] { deviceRecords.filter { $0.status == .protected }.map(\.name) }

    var selectedRecord: PaxDeviceRecord? { deviceRecords.first { $0.id == selectedDevice } }

    // MARK: v0.7.0 iPhone "Request a change" (same server wait as the Mac)

    /// Matches each protected iPhone to its device on the server (by name, newest
    /// first) and fetches its status.
    func refreshPhones() async {
        guard hasAccount, !deviceRecords.isEmpty else { return }
        do {
            let server = try await coordinator.escrow.devices()
                .filter { $0.platform != "mac" && $0.platform != "macos" }
                .sorted { $0.installed_at > $1.installed_at }
            var changed = false
            for i in deviceRecords.indices where deviceRecords[i].escrowID == nil {
                if let match = server.first(where: { $0.name == deviceRecords[i].name }) {
                    deviceRecords[i].escrowID = match.device_id
                    changed = true
                }
            }
            if changed { PaxDeviceRecord.save(deviceRecords) }
            var map: [String: EscrowClient.DeviceStatus] = [:]
            for rec in deviceRecords {
                if let id = rec.escrowID, let st = server.first(where: { $0.device_id == id }) { map[rec.id] = st }
            }
            phoneStatus = map
            phoneStatusFetchedAt = Date()
        } catch {
            failure = PaxErrorClassifier.classify(error)
            lastAction = { [weak self] in Task { await self?.refreshPhones() } }
        }
    }

    func requestPhoneRemoval(_ rec: PaxDeviceRecord) {
        guard let id = rec.escrowID else { return }
        run { [self] in
            phoneStatus[rec.id] = try await coordinator.escrow.requestRemoval(deviceID: id)
            phoneStatusFetchedAt = Date()
        }
    }

    func cancelPhoneRemoval(_ rec: PaxDeviceRecord) {
        guard let id = rec.escrowID else { return }
        run { [self] in
            phoneStatus[rec.id] = try await coordinator.escrow.cancelRemoval(deviceID: id)
            phoneStatusFetchedAt = Date()
        }
    }

    /// After the wait: the password that removes Pax's settings on the iPhone.
    func revealPhonePassword(_ rec: PaxDeviceRecord) {
        guard let id = rec.escrowID else { return }
        run { [self] in
            revealedPhonePassword[rec.id] = try await coordinator.escrow.confirmRemoval(deviceID: id).removal_password
            await refreshPhones()
        }
    }

    /// v0.8.15: a verified support code for this iPhone or iPad. The server checks it,
    /// emails the trusted person first, then releases the password at once.
    func redeemPhoneSupportCode(_ rec: PaxDeviceRecord, code: String) {
        guard let id = rec.escrowID else { return }
        run { [self] in
            revealedPhonePassword[rec.id] = try await coordinator.escrow.redeemSupportCode(deviceID: id, code: code)
                .removal_password
            await refreshPhones()
        }
    }

    /// v0.8.15 "Allow verified support release" for this iPhone or iPad (kept by the server).
    func setPhoneSupportRelease(_ rec: PaxDeviceRecord, _ on: Bool) {
        guard let id = rec.escrowID else { return }
        run { [self] in
            phoneStatus[rec.id] = try await coordinator.escrow.setSupportRelease(deviceID: id, allowed: on)
            phoneStatusFetchedAt = Date()
        }
    }

    /// v0.8.18 "Start my wait now": ends this iPhone's or iPad's trial day early.
    func endPhoneTrial(_ rec: PaxDeviceRecord) {
        guard let id = rec.escrowID else { return }
        run { [self] in
            phoneStatus[rec.id] = try await coordinator.escrow.endTrial(deviceID: id)
            phoneStatusFetchedAt = Date()
        }
    }

    func phoneRemaining(_ rec: PaxDeviceRecord, at now: Date) -> Int {
        guard let rr = phoneStatus[rec.id]?.removal_request else { return 0 }
        return max(0, rr.seconds_remaining - Int(now.timeIntervalSince(phoneStatusFetchedAt)))
    }

    /// Rough progress for the single bar on "Lock it in".
    var lockInProgress: (Double, String) {
        if profilePendingUser { return (0.92, "Almost there: one tap on your iPhone.") }
        if protecting { return (0.85, "Turning on protection…") }
        if supervised { return (0.75, "Your iPhone is ready for protection.") }
        if config.mode == .clean {
            if waitingForHello { return (0.5, "Waiting for your iPhone's Hello screen.") }
            return (min(0.7, 0.1 + Double(log.count) * 0.06), "Backing up and preparing your iPhone…")
        }
        switch keepDataPhase {
        case .preflight: return (0.05, "Checking your iPhone…")
        case .restoring: return (0.25, "Preparing your iPhone. It will restart by itself.")
        case .waitingForPhone(let s):
            return (0.45, s == .paired ? "Connected." : "Waiting for your iPhone. Follow the steps below.")
        case .confirming: return (0.6, "Making sure your iPhone is ready…")
        case .supervised: return (0.75, "Your iPhone is ready for protection.")
        }
    }

    /// True once the Lock-it-in step has started doing things on the phone.
    var lockInStarted: Bool {
        supervised || protecting || profilePendingUser || waitingForHello
            || (config.mode == .keepData && keepDataPhase != .preflight)
            || (config.mode == .clean && busy && !log.isEmpty)
    }
}
