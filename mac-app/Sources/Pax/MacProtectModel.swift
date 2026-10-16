// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import SwiftUI
import PaxCore

/// "Protect this Mac" (v0.4; v0.7.0 calm flow): set-up, status, removal request and
/// Remove Pax. The safety-critical order lives in PaxCore.MacLockdown (unit-tested);
/// this model only drives the screens.
@MainActor
final class MacProtectModel: ObservableObject {
    enum Phase: Equatable {
        case intro            // steps 1-3 of the Mac path (choices, wait, lock it in)
        case checked          // preflight passed but needs a confirmation or shows a warning
        case running          // lockdown in progress
        case approveProfile   // waiting for the user to approve the profile in System Settings
        case protected        // locked; status, removal, ad blocking
        case released         // password revealed; Remove Pax available
        case removed
    }

    @Published var phase: Phase = .intro
    /// Mac path step: 0 choose what to block, 1 wait time, 2 lock it in.
    @Published var step = 0
    @Published var password = ""
    /// One plain agreement: of age, my Mac, I understand the wait and the standard account.
    @Published var agreed = false
    @Published var savedRecoveryKey = false
    /// v0.8.10: "Also make these standard accounts" (on by default): Pax makes the
    /// Mac's other administrators standard itself, with this one OK.
    @Published var demoteOtherAdmins = true
    @Published var madeBackup = false
    /// The set-up choice until pax-guard (local) or the server says otherwise.
    @Published var adblock = UserDefaults.standard.object(forKey: "pax.mac.adblock") as? Bool ?? true
    /// v0.8.7: where the Home switch goes (pax-guard live, the server, or set-up only).
    @Published var adblockSwitch: AdblockSwitch = .guardLive
    /// v0.8.7: the Mac's Blocked apps (pax-guard; local escrow only).
    @Published var blockedApps: GuardClient.AppsView?
    /// v0.8.6: YouTube Restricted Mode (pax-guard's switch; on by default).
    @Published var youtubeRestricted = true
    @Published var youtubeAvailable = true
    // v0.8.13: pictures and video on X and Bluesky are always blocked (no state to keep;
    // Home shows AlwaysBlockedMedia.notice).
    /// v0.6 "Pax Max": force-install Pax Image Blur. Off by default (it blurs a
    /// lot of the web); chosen at setup and fixed in the profile until re-protect.
    @Published var paxMax = UserDefaults.standard.bool(forKey: "pax.mac.paxMax")
    /// v0.8.12: Pax Max after set-up, as pax-guard reports it (nil: older pax-guard).
    @Published var paxMaxView: GuardClient.PaxMaxView?
    /// v0.8.12: the confirmation after a Pax Max change (shown in Settings).
    @Published var paxMaxNotice: String?
    @Published var preflight: MacPreflight?
    @Published var log: [String] = []
    @Published var busy = false
    @Published var errorMessage: String?
    /// v0.7.0: a classified failure with its support code.
    @Published var failure: PaxError?
    /// The lockdown step running now (drives the single progress bar).
    @Published var currentStep: MacLockdownStep?
    @Published var status: EscrowClient.DeviceStatus?
    @Published var revealedPassword: String?
    @Published var emergencyReason = ""
    @Published var statusFetchedAt = Date()
    /// v0.8.0 local escrow: what pax-guard released (the FileVault recovery key
    /// and, on Intel, the firmware password come with paxadmin's password).
    @Published var released: GuardClient.Released?
    /// v0.8.0: pax-guard's own report (filter in use, updates, tamper log).
    @Published var guardStatus: GuardClient.Status?
    @Published var partnerView: GuardClient.PartnerView?

    private let setup: SetupModel
    private var approval: CheckedContinuation<Bool, Never>?
    private let defaults = UserDefaults.standard
    private let userName = NSUserName()

    init(setup: SetupModel) {
        self.setup = setup
        if deviceID != nil { phase = .protected }
    }

    var deviceID: String? {
        get { defaults.string(forKey: "pax.mac.deviceID") }
        set { defaults.set(newValue, forKey: "pax.mac.deviceID") }
    }

    var profileIdentifier: String? {
        get { defaults.string(forKey: "pax.mac.profileID") }
        set { defaults.set(newValue, forKey: "pax.mac.profileID") }
    }

    var hasAccount: Bool { setup.hasAccount }
    var consentComplete: Bool { agreed }
    var choices: BlockChoices { setup.choices }
    var confirmationsComplete: Bool {
        (savedRecoveryKey || !(preflight?.fileVaultOn ?? false)) && madeBackup
            && (demoteOtherAdmins || (preflight?.otherAdmins ?? []).isEmpty)
    }
    /// The accounts the user agreed to make standard (exactly what they saw).
    var agreedStandardAccounts: [String] { demoteOtherAdmins ? (preflight?.otherAdmins ?? []) : [] }
    var escrow: EscrowClient { setup.coordinator.escrow }
    /// v0.8.0: pax-guard's socket (local escrow, local blocked sites, updates).
    let guardClient = GuardClient()

    /// Where this Mac's key lives. Saved when the Mac is protected; can't change
    /// while it is (Settings › Advanced).
    var escrowMode: MacEscrowMode {
        get { MacEscrowMode.current(defaults) }
        set { defaults.set(newValue.rawValue, forKey: MacEscrowMode.defaultsKey); objectWillChange.send() }
    }
    var isLocal: Bool { escrowMode == .local }

    private func lockdown() -> MacLockdown {
        MacLockdown(userName: userName, escrow: escrow,
                    allowExtraAdmins: defaults.bool(forKey: "pax.testing.allowExtraAdmins"),
                    escrowMode: escrowMode, localWaitSeconds: max(1, setup.config.waitDays) * 86_400)
    }

    private var lastAction: (() -> Void)?

    private func perform(retry: (() -> Void)? = nil, _ work: @escaping () async throws -> Void) {
        busy = true
        errorMessage = nil
        failure = nil
        lastAction = retry ?? { [weak self] in self?.perform(work) }
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

    /// "Try again". After a failed set-up the password was wiped, so Try again just
    /// clears the message and lets the user type it again.
    func retry() {
        let action = lastAction
        failure = nil
        if phase == .intro && password.isEmpty { return }
        action?()
    }

    func supportDetails(_ error: PaxError) -> String {
        Support.details(error, log: log, extraRedactions: setup.privateNames)
    }

    /// Progress 0...1 and a friendly line for the single bar.
    var progress: (Double, String) {
        let steps = MacLockdownStep.allCases
        guard let step = currentStep, let i = steps.firstIndex(of: step) else {
            return (0.03, "Getting started…")
        }
        let fraction = Double(i + 1) / Double(steps.count)
        let line: String
        switch step {
        case .preflight: line = "Checking your Mac…"
        case .createAdmin, .secureToken, .verifyAdmin: line = "Creating the key Pax keeps for you…"
        case .escrow: line = "Storing your key safely behind your wait…"
        case .installProfile: line = "Adding Pax's protection settings…"
        case .installGuard: line = "Starting Pax's background protection…"
        case .demoteOthers: line = "Making the other administrator accounts standard…"
        case .demoteUser, .verifyDemotion: line = "Switching your account to a standard account…"
        case .done: line = "All done."
        }
        return (fraction, line)
    }

    // MARK: Set-up

    func registerAccountIfNeeded() async throws {
        // A token saved for a server whose database was reset no longer works:
        // forget it and register again (common with a local test server).
        if setup.hasAccount {
            do {
                _ = try await escrow.accountSummary()
            } catch let e as EscrowClient.APIError where e.status == 401 {
                setup.tokenStore.clear()
                setup.coordinator.escrow.token = nil
            }
        }
        if !setup.hasAccount {
            try await setup.coordinator.registerAccount(setup.config)
            if let token = setup.coordinator.escrow.token { try? setup.tokenStore.save(token) }
        }
    }

    /// Called when the set-up screen appears: drops a saved token the server no
    /// longer knows, so the account fields show up.
    func checkAccount() {
        guard setup.hasAccount, phase == .intro else { return }
        Task {
            do {
                _ = try await escrow.accountSummary()
            } catch let e as EscrowClient.APIError where e.status == 401 {
                setup.tokenStore.clear()
                setup.coordinator.escrow.token = nil
                objectWillChange.send()
            } catch {}
        }
    }

    func runPreflight() {
        perform { [self] in
            preflight = try await lockdown().preflight(password: password, demoteOtherAdmins: demoteOtherAdmins)
            if let p = preflight, !p.ok { throw MacLockdownError.preflightFailed(p.problems) }
            if preflight?.ok == true { phase = .checked }
        }
    }

    /// The single "Protect my Mac" button: check this Mac, then protect straight away
    /// unless something needs the user's eyes first (FileVault key, a warning such
    /// as test mode). The backup confirmation is asked before the button.
    func checkAndProtect() {
        perform(retry: { [weak self] in self?.checkAndProtect() }) { [self] in
            log.append("… Checking this Mac")
            let p = try await lockdown().preflight(password: password, demoteOtherAdmins: demoteOtherAdmins)
            preflight = p
            guard p.ok else { throw MacLockdownError.preflightFailed(p.problems) }
            log.append("✓ This Mac is ready")
            // v0.8.10: other administrators always get the one consent step first.
            if !importantWarnings(p).isEmpty || !confirmationsComplete || !p.otherAdmins.isEmpty {
                phase = .checked
            } else {
                Task { @MainActor in self.protect() }
            }
        }
    }

    /// Warnings worth stopping for. FileVault and backup advice are asked as
    /// checkboxes instead, so they're left out here.
    func importantWarnings(_ p: MacPreflight) -> [String] {
        p.warnings.filter { !$0.hasPrefix("FileVault is on") && !$0.hasPrefix("Make a Time Machine backup") }
    }

    func protect() {
        phase = .running
        log = []
        currentStep = nil
        let password = self.password
        let picks = setup.choices
        let adblock = picks.adblock
        let paxMax = picks.paxMax
        self.adblock = adblock
        self.paxMax = paxMax
        let local = isLocal
        let standardAccounts = agreedStandardAccounts
        perform(retry: { [weak self] in self?.phase = .intro }) { [self] in
            do {
                // Local escrow needs no server account (v0.8.0); the server path does.
                if !local { try await registerAccountIfNeeded() }
                let env = ProcessInfo.processInfo.environment
                let fm = FileManager.default
                let dir = fm.temporaryDirectory.appendingPathComponent("pax-mac-\(UUID().uuidString)", isDirectory: true)
                try fm.createDirectory(at: dir, withIntermediateDirectories: true,
                                       attributes: [.posixPermissions: 0o700])
                defer { try? fm.removeItem(at: dir) }
                let profileURL = dir.appendingPathComponent("Pax (this Mac).mobileconfig")
                var token: String?
                // v0.8.8: the iPhone default (Pax's filter) doesn't change the Mac: a Mac on the
                // server path still uses a per-user DoH address only when PAX_DNS_BASE is set.
                let macBase = ProcessInfo.processInfo.environment["PAX_DNS_BASE"].flatMap { $0.isEmpty ? nil : $0 }
                if !local, macBase != nil {
                    token = try await escrow.dnsInfo().token
                }
                let profile = try await setup.coordinator.profiles.generateMacSelfLock(
                    out: profileURL, filter: setup.config.dnsFilter, userToken: token,
                    dnsBase: macBase,
                    blockURLs: Array(picks.extraSites.prefix(BulkSiteImport.profileLimit)),
                    adblock: adblock, imageBlur: paxMax,
                    // v0.8.12: on this Mac's own key, Firefox gets Pax Image Blur either way so
                    // Pax Max can be switched later (pax-guard tells it whether to blur).
                    imageBlurSwitchable: local)
                // System Settings reads the file after we hand it over, so make it readable.
                try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: profileURL.path)
                try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)

                let guardDir = ResourceLocator.locate(envKey: "PAX_GUARD_DIR", bundled: "guard",
                                                      devPath: "../guard")
                var installScript = guardDir.appendingPathComponent("pax-guard-install.sh")
                if !fm.fileExists(atPath: installScript.path) {
                    installScript = guardDir.appendingPathComponent("scripts/pax-guard-install.sh")
                }
                let paths = MacLockdownPaths(guardSource: guardDir, guardInstallScript: installScript,
                                             configFile: dir.appendingPathComponent("guard-config.json"),
                                             profileFile: profileURL)
                let server = escrow.baseURL.absoluteString
                let resolverHost = GuardConfigFile.resolverHost(from: profile.resolverURL)
                let user = userName
                let testing = defaults.bool(forKey: "pax.testing.allowExtraAdmins")
                let managed = preflight?.mdmEnrolled ?? false
                let outcome = try await lockdown().protectThisMac(
                    password: password,
                    deviceName: Host.current().localizedName ?? "This Mac",
                    paths: paths,
                    profileIdentifier: profile.identifier,
                    standardAccounts: standardAccounts,
                    writeConfig: { path, guardToken in
                        let cfg = GuardConfigFile(server_url: server, guard_token: guardToken,
                                                  profile_identifier: profile.identifier, user: user,
                                                  resolver_host: resolverHost, adblock_default: adblock,
                                                  escrow_mode: local ? "local" : "server",
                                                  mdm_managed: managed,
                                                  testing_allow_extra_admins: testing,
                                                  youtube_restricted_default: picks.youtubeRestricted,
                                                  pax_max_switchable: local ? true : nil,
                                                  pax_max_default: local ? paxMax : nil)
                        let url = URL(fileURLWithPath: path)
                        try cfg.json().write(to: url, options: .atomic)
                        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
                    },
                    waitForProfileApproval: { [weak self] in
                        await self?.waitForApproval() ?? false
                    },
                    progress: { [weak self] p in
                        Task { @MainActor in
                            self?.currentStep = p.step
                            self?.log.append((p.finished ? "✓ " : "… ") + p.message)
                        }
                    })
                deviceID = outcome.deviceID
                profileIdentifier = outcome.profileIdentifier
                defaults.set(paxMax, forKey: "pax.mac.paxMax")
                defaults.set(adblock, forKey: "pax.mac.adblock")
                defaults.set(local ? "local" : "server", forKey: MacEscrowMode.defaultsKey)
                self.password = ""
                if !adblock && !local { try? await escrow.setAdblock(false) }
                phase = .protected
                await refreshStatus()
            } catch {
                self.password = ""
                phase = .intro
                throw error
            }
        }
    }

    private func waitForApproval() async -> Bool {
        await withCheckedContinuation { cont in
            approval = cont
            phase = .approveProfile
        }
    }

    func profileApproved(_ ok: Bool) {
        phase = .running
        approval?.resume(returning: ok)
        approval = nil
    }

    // MARK: Protected

    func refreshStatus() async {
        guard let id = deviceID else { return }
        do {
            if id == "local" || isLocal {
                status = try await guardClient.device()
                guardStatus = try? await guardClient.status()
                partnerView = try? await guardClient.partner()
            } else {
                status = try await escrow.device(id: id)
                if let me = try? await escrow.accountSummary() { adblock = me.adblock ?? adblock }
                guardStatus = try? await guardClient.status()
            }
            if let s = guardStatus?.settings {
                youtubeRestricted = s.youtube_restricted
                youtubeAvailable = s.youtube_available ?? true
                applyPaxMax(s.pax_max)
            }
            // v0.8.7: on local escrow the ads setting lives in pax-guard.
            adblockSwitch = AdblockSwitch.mode(localEscrow: localKey, settings: guardStatus?.settings)
            if localKey { blockedApps = try? await guardClient.blockedApps() }
            if adblockSwitch == .guardLive, let on = guardStatus?.settings?.adblock { adblock = on }
            statusFetchedAt = Date()
            await refreshSync()
        } catch {
            failure = PaxErrorClassifier.classify(error)
        }
    }

    func refresh() { perform { [self] in await refreshStatus() } }

    // MARK: v0.8.9 blocked-sites sync

    /// "Sync blocked sites across devices" (this Mac on its own key; on by default).
    @Published var sync: GuardClient.SyncStatus?
    var canSync: Bool { localKey && deviceID != nil }

    /// Reads the switch and, with no extra step, links this Mac's list to the account
    /// the app is signed in to (made when an iPhone was set up from this Mac, for
    /// partner emails, or by signing in with a code). Quietly retried next time if the
    /// server can't be reached: this Mac keeps enforcing its own list meanwhile.
    func refreshSync() async {
        guard canSync else { sync = nil; return }
        sync = try? await guardClient.syncStatus()
        guard ListSyncLinker.shouldLink(localKey: localKey, protected: deviceID != nil,
                                        hasAccount: setup.hasAccount, status: sync) else { return }
        do {
            let link = try await escrow.createSyncLink(deviceName: ProcessInfo.processInfo.hostName)
            sync = try await guardClient.linkSync(serverURL: escrow.baseURL.absoluteString,
                                                  token: link.sync_token, accountEmail: link.account_email)
        } catch {
            sync = try? await guardClient.syncStatus()
        }
    }

    /// Off never unblocks anything (each device keeps its copy); on merges the lists.
    func setSyncEnabled(_ on: Bool) {
        perform { [self] in
            sync = try await guardClient.setSync(on)
            if on { await refreshSync() }
        }
    }

    private var localKey: Bool { deviceID == "local" || isLocal }

    func requestRemoval(reason: String = "remove") {
        guard let id = deviceID else { return }
        perform { [self] in
            if localKey {
                do { status = try await guardClient.requestRemoval(reason: reason) } catch {
                    status = try? await guardClient.device()     // "telling your partner" still shows
                    throw error
                }
            } else {
                status = try await escrow.requestRemoval(deviceID: id)
            }
            statusFetchedAt = Date()
        }
    }

    func cancelRemoval() {
        guard let id = deviceID else { return }
        perform { [self] in
            if localKey {
                status = try await guardClient.cancelRemoval()
            } else {
                status = try await escrow.cancelRemoval(deviceID: id)
            }
            statusFetchedAt = Date()
        }
    }

    func emergency() {
        guard let id = deviceID else { return }
        let reason = emergencyReason
        perform { [self] in
            if localKey {
                status = try await guardClient.emergency(reason: reason)
            } else {
                try await escrow.emergencyRelease(deviceID: id, reason: reason)
            }
            await refreshStatus()
        }
    }

    func reveal() {
        guard let id = deviceID else { return }
        perform { [self] in
            if localKey {
                let r = try await guardClient.reveal()
                released = r
                if let pw = r.removal_password {
                    revealedPassword = pw
                    phase = .released
                }
            } else {
                revealedPassword = try await escrow.confirmRemoval(deviceID: id).removal_password
                phase = .released
            }
        }
    }

    /// "Ads and trackers". v0.8.7: on local escrow this goes straight to pax-guard
    /// (up to 0.8.6 it only changed this screen). Both directions are immediate, with
    /// no wait and no partner email; restricted content stays blocked either way.
    func setAdblock(_ on: Bool) {
        perform { [self] in
            if !localKey {
                try await escrow.setAdblock(on)
                adblock = on
                return
            }
            guard adblockSwitch != .setUpOnly else { return }
            let s = try await guardClient.setAdblock(on)
            adblock = s.adblock ?? on
            adblockSwitch = AdblockSwitch.mode(localEscrow: true, settings: s)
        }
    }

    // MARK: v0.8.7 Blocked apps

    /// Adding is instant; pax-guard closes the app and puts it away.
    func blockApp(path: String) {
        perform { [self] in blockedApps = try await guardClient.addBlockedApp(path: path) }
    }

    /// Unblocking waits like unblocking a site (your partner is told first).
    func unblockApp(_ bundleID: String) {
        perform { [self] in blockedApps = try await guardClient.unblockApp(bundleID: bundleID) }
    }

    func cancelAppRequest(_ requestID: String) {
        perform { [self] in blockedApps = try await guardClient.cancelAppRequest(requestID) }
    }

    var canBlockApps: Bool { localKey && deviceID != nil }

    /// v0.8.6: YouTube Restricted Mode, straight to pax-guard. Both directions are
    /// immediate (no wait, no partner email: the maintainer's decision); pax-guard
    /// writes the change to its tamper log. Everything else stays on.
    func setYouTubeRestricted(_ on: Bool) {
        perform { [self] in
            let s = try await guardClient.setYouTubeRestricted(on)
            youtubeRestricted = s.youtube_restricted
            youtubeAvailable = s.youtube_available ?? true
        }
    }

    // MARK: v0.8.12 Pax Max after set-up

    private func applyPaxMax(_ v: GuardClient.PaxMaxView?) {
        paxMaxView = v
        if let on = v?.on, v?.switchable == true {
            if paxMax != on, paxMaxView?.pending == nil {
                paxMaxNotice = on ? nil : PaxMax.turnedOff      // the hour ended
            }
            paxMax = on
            defaults.set(on, forKey: "pax.mac.paxMax")
        }
    }

    /// Settings › Pax Max opened: read the current state from pax-guard.
    func refreshPaxMax() {
        Task { [self] in
            if let v = try? await guardClient.paxMax() { applyPaxMax(v) }
        }
    }

    /// Instant, any time after set-up.
    func turnPaxMaxOn() {
        perform { [self] in
            applyPaxMax(try await guardClient.turnPaxMaxOn())
            paxMaxNotice = PaxMax.turnedOn
        }
    }

    /// Partner first (fail closed), then a fixed hour; refused offline.
    func requestPaxMaxOff() {
        perform { [self] in
            applyPaxMax(try await guardClient.requestPaxMaxOff())
            paxMaxNotice = PaxMax.offRequested
        }
    }

    func cancelPaxMaxOff() {
        guard let id = paxMaxView?.pending?.request_id else { return }
        perform { [self] in
            applyPaxMax(try await guardClient.cancelPaxMaxOff(requestID: id))
            paxMaxNotice = "Pax Max stays on."
        }
    }

    /// v0.8.0 Settings › Updates "Update now": pax-guard checks and installs.
    func updateNow() {
        perform { [self] in
            _ = try await guardClient.updateNow()
            guardStatus = try? await guardClient.status()
        }
    }

    /// v0.8.0 partner emails on local escrow (Settings › Accountability partner email).
    func saveEmailSettings(transport: [String: Any]?, ownerEmail: String?, partner: String?) {
        perform { [self] in
            try await applyEmailSettings(transport, ownerEmail: ownerEmail, partner: partner)
        }
    }

    /// v0.8.5: partner emails through a Pax server's /v1/notify relay, by default
    /// the server this app uses, with this Mac's account on it (registered with
    /// `ownerEmail` the first time; the server only relays, it keeps no key).
    func saveRelayEmailSettings(url typed: String, token typedToken: String, ownerEmail: String,
                                partner: String?) {
        perform { [self] in
            let appServer = escrow.baseURL
            let relay = try PartnerRelay.url(typed: typed, appServer: appServer).get()
            var token = typedToken.trimmingCharacters(in: .whitespacesAndNewlines)
            if PartnerRelay.usesAppAccount(relay: relay, typedToken: token, appServer: appServer) {
                try await ensureRelayAccount(email: ownerEmail)
                token = setup.coordinator.escrow.token ?? ""
            }
            try await applyEmailSettings(PartnerRelay.transport(relay: relay, token: token),
                                         ownerEmail: ownerEmail.isEmpty ? nil : ownerEmail, partner: partner)
        }
    }

    private func applyEmailSettings(_ transport: [String: Any]?, ownerEmail: String?, partner: String?) async throws {
        partnerView = try await guardClient.setEmailTransport(transport, ownerEmail: ownerEmail)
        if let partner, partner != (partnerView?.partner ?? "") {
            try await guardClient.setPartner(partner.isEmpty ? nil : partner)
            partnerView = try? await guardClient.partner()
        }
    }

    /// An account on the app's server for the relay only: no wait, no partner and
    /// no device there (the Mac's key stays on the Mac).
    private func ensureRelayAccount(email: String) async throws {
        if setup.hasAccount {
            do {
                _ = try await escrow.accountSummary()
                return
            } catch let e as EscrowClient.APIError where e.status == 401 {
                setup.tokenStore.clear()
                setup.coordinator.escrow.token = nil
            }
        }
        let address = email.isEmpty ? setup.config.email : email
        let account = try await escrow.registerAccount(email: address)
        setup.coordinator.escrow.token = account.token
        try? setup.tokenStore.save(account.token)
        objectWillChange.send()
    }

    func removePax() {
        guard let pw = revealedPassword else { return }
        let ident = profileIdentifier ?? ""
        perform { [self] in
            let dir = FileManager.default.temporaryDirectory
            let paths = MacLockdownPaths(guardSource: URL(fileURLWithPath: "/Library/PaxGuard/bin"),
                                         guardInstallScript: URL(fileURLWithPath: "/dev/null"),
                                         configFile: dir, profileFile: dir)
            log = try await lockdown().removePax(paxAdminPassword: pw, paths: paths, profileIdentifier: ident)
            deviceID = nil
            profileIdentifier = nil
            revealedPassword = nil
            phase = .removed
        }
    }

    func remaining(at now: Date) -> Int {
        guard let rr = status?.removal_request else { return 0 }
        return max(0, rr.seconds_remaining - Int(now.timeIntervalSince(statusFetchedAt)))
    }
}
