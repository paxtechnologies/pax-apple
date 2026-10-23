// SPDX-License-Identifier: GPL-3.0-only
// The app's state and every action that talks to Screen Time, the DNS settings or the
// Pax server. Fail closed throughout: settings are only ever added, except in
// `confirmTurnOff`, after the server released the secret and its hash matched, and in
// `refreshSites`, for one of your own sites once the server's turn-off wait for it has ended.
//
// 1.2 one-tap set-up: every Pax account has a verified email (server 0.8.31). The email and a
// 6-digit code come first (`sendCode`, `verifyCode`); then `turnOn` asks Screen Time once, only
// ever lengthens the turn-off wait, escrows the release key on the server and only then switches
// the settings on. Everything else is optional, on Home ("Make Pax stronger").
//
// Also in 1.2: the child path on its own routes (server 0.8.32, ChildSetup), removing your own
// blocked sites through the server's turn-off wait (SiteRemoval), and joining a set-up made from
// a Mac without adding anything that clashes with it (StrictSync).
import Foundation
import SwiftUI
import FamilyControls
import DeviceActivity
import UIKit

@MainActor
final class AppModel: ObservableObject {
    @Published var policy = PaxPolicy.load()
    @Published var selection = PaxSelection.load() ?? FamilyActivitySelection()
    @Published var phase: TurnOffPhase = .none
    @Published var inGrace = false
    @Published var dnsOn: Bool?
    @Published var accessLost = false
    @Published var message: String?
    @Published var busy = false
    /// The account as the server last described it (pending wait / trusted person changes).
    @Published var account: PaxAPI.AccountStatus?
    /// Shown once, after a turn-off: the Screen Time passcode (or "" if none was kept).
    @Published var revealedPasscode: String?
    /// After a code that signed in to an account this email already had: what's already set.
    @Published var existing: ExistingAccount?
    /// Whether this device has a working sign-in (the token is in the Keychain).
    @Published var signedIn = false
    /// Server clock − device clock at the last blocklist read (for "available in …" only).
    @Published var serverOffset: TimeInterval = 0
    /// Is Pax's filter on this device without this app's own DNS (a Mac set-up)? nil: can't tell.
    @Published var filteredHere: Bool?
    /// After the code: what to do about a set-up made from a Mac (nil before the check).
    @Published var macDecision: StrictSync.Decision?
    /// YouTube Restricted Mode as Settings shows it (on, no switch, until the server says more).
    @Published var youtube = YouTubeRow.fallback
    /// The server keeps a blocked-apps list (GET /v1/apps answered), so removing one can take the
    /// turn-off wait. false: blocked apps stay blocked and no removal is offered.
    @Published var appsServerList = false

    let api = PaxAPI()

    private static let pendingPasscodeKey = "pending-screen-time-passcode"
    private static let pendingEscrowKey = "pending-escrow-secret"

    init() {
        signedIn = api.signedIn
        #if DEBUG
        if ScreenshotMode.home { policy = ScreenshotMode.samplePolicy; dnsOn = true; signedIn = true }
        if ScreenshotMode.childHome { policy = ScreenshotMode.sampleChildPolicy; dnsOn = true; signedIn = true }
        if ScreenshotMode.macHome { policy = ScreenshotMode.sampleMacPolicy; signedIn = true; filteredHere = true }
        if ScreenshotMode.any {
            serverOffset = 0
            youtube = ScreenshotMode.sampleYouTube(policy)
            appsServerList = ScreenshotMode.appsRemoving
        }
        #endif
    }

    var isPad: Bool { UIDevice.current.userInterfaceIdiom == .pad }
    var authorized: Bool { AuthorizationCenter.shared.authorizationStatus == .approved }
    var hasApps: Bool {
        !(selection.applicationTokens.isEmpty && selection.webDomainTokens.isEmpty && selection.categoryTokens.isEmpty)
    }
    /// The name or email the trusted person's emails use for this account (as the server's who()).
    private var who: String {
        if let n = policy.displayName, !n.isEmpty { return n }
        return policy.accountEmail ?? ""
    }

    // MARK: launch / foreground

    private var checking = false

    func onActive() async {
        #if DEBUG
        if ScreenshotMode.any { return }   // screenshots: no network, no settings
        #endif
        signedIn = api.signedIn
        if policy.macSetUp && !policy.isActive {
            // Set up from a Mac: nothing of this app's own to re-apply or check on the device.
            guard !checking else { return }
            checking = true; defer { checking = false }
            let probe = await ProtectionCheck.run()
            filteredHere = StrictSync.filteredHere(probe: probe, ownDNSConfigured: false)
            await refreshAccount()
            await refreshSites()
            await refreshYouTube()
            return
        }
        guard policy.isActive, !checking else { return }
        checking = true; defer { checking = false }
        PaxRestrictions.apply(policy, selection: selection)      // self-heal
        await checkAccess()
        await checkDNS()
        await refreshStatus()
        await refreshAccount()
        await refreshSites()
        await refreshApps()
        await refreshYouTube()
    }

    func refreshAccount() async {
        guard api.signedIn else { signedIn = false; return }
        do { applyAccount(try await api.me()) }
        catch let e as PaxAPIError where e.status == 401 {
            signedOutHere()         // sign in again with the email and a code
        } catch {}
    }

    private func applyAccount(_ a: PaxAPI.AccountStatus) {
        account = a
        if let e = a.email, !e.isEmpty { policy.accountEmail = e }
        policy.accountID = a.account_id
        policy.displayName = (a.display_name ?? "").isEmpty ? nil : a.display_name
        policy.trustedEmail = a.partner_email
        policy.waitDays = TurnOffRules.days(fromSeconds: a.wait_seconds)
        policy.save()
    }

    func refreshStatus() async {
        guard let id = policy.deviceID, api.signedIn else { return }
        do {
            let d = try await api.status(device: id)
            inGrace = d.in_grace_period ?? false
            if let w = d.wait_seconds { policy.waitDays = TurnOffRules.days(fromSeconds: w); policy.save() }
            phase = Self.phase(of: d)
        } catch {
            switch phase {
            case .waiting, .ready: phase = .unknown
            default: break
            }
        }
    }

    private static func phase(of d: PaxAPI.DeviceStatus) -> TurnOffPhase {
        let r = d.removal_request
        return TurnOffRules.phase(requestStatus: r?.status, secondsRemaining: r?.seconds_remaining,
                                  canReveal: r?.can_reveal, now: Date())
    }

    /// Screen Time access switched off in Settings. Pax never asks for it again after
    /// set-up (asking again lifts the delete block); it tells the trusted person once.
    private func checkAccess() async {
        var checks = [authorized]
        try? await Task.sleep(nanoseconds: 3_000_000_000)
        checks.append(authorized)
        accessLost = AccessWatch.isLost(isActive: policy.isActive, checks: checks)
        if !accessLost {
            if policy.accessAlertSent { policy.accessAlertSent = false; policy.save() }
            return
        }
        guard !policy.accessAlertSent else { return }
        do {
            try await api.notify(.accessOff(device: UIDevice.current.name, email: who), trustedEmail: policy.trustedEmail)
            policy.accessAlertSent = true
            policy.save()
        } catch {}                                          // tried again next launch
    }

    private func checkDNS() async {
        guard let on = await PaxDNS.isEnabled() else { return }
        dnsOn = on
        var p = policy
        let alert = DNSWatch.update(&p, isEnabled: on, now: Date())
        policy = p
        policy.save()
        let device = UIDevice.current.name
        let mail: PaxAlertEmail
        switch alert {
        case .none: return
        case .switchedOff: mail = .dnsOff(device: device, email: who)
        case .neverOn: mail = .dnsNeverOn(device: device, email: who)
        }
        do {
            try await api.notify(mail, trustedEmail: policy.trustedEmail)
            policy.dnsAlertSent = DNSWatch.sentKey(for: alert)
            policy.save()
        } catch {}                                          // tried again next launch
    }

    // MARK: set-up: email and code (every account has a verified email)

    private var label: String { isPad ? "iPad app" : "iPhone app" }

    /// Emails a 6-digit code (POST /v1/accounts/email/start; always the same answer). On the
    /// child path: POST /v1/accounts/child/start, never /email/* (that would be the parent's own
    /// account).
    func sendCode(email raw: String, child: Bool = false) async -> Bool {
        let email = SetupRules.normaliseEmail(raw)
        busy = true; defer { busy = false }
        message = nil
        if child {
            if filteredHere == nil, !policy.isActive {
                let probe = await ProtectionCheck.run()
                filteredHere = StrictSync.filteredHere(probe: probe, ownDNSConfigured: policy.dnsInstalled)
            }
            if !policy.isActive, StrictSync.childRefused(filteredHere: filteredHere) {
                message = PaxCopy.childOnMacSetUp(isPad: isPad)
                return false
            }
            do { try await api.startChild(parentEmail: email); return true }
            catch let e as PaxAPIError {
                message = ChildSetup.problem(status: e.status, code: e.code, starting: true)
                    .map { ChildSetup.message($0, isPad: isPad) } ?? e.message
                return false
            } catch { message = PaxCopy.retryBody; return false }
        }
        do { try await api.startEmail(email: email); return true }
        catch let e as PaxAPIError {
            switch e.status {
            case 422: message = PaxCopy.emailInvalid
            case 429: message = PaxCopy.tooManyCodes
            default: message = e.message
            }
            return false
        } catch { message = PaxCopy.retryBody; return false }
    }

    /// Checks the code (POST /v1/accounts/email/verify) and keeps the token in the Keychain.
    /// `again`: signing in again on a device Pax is already on, so it can only be the account it
    /// was set up with; another account's token is never kept.
    func verifyCode(email raw: String, code raw2: String, again: Bool = false,
                    child: Bool = false, childName: String? = nil) async -> VerifyOutcome {
        let email = SetupRules.normaliseEmail(raw)
        let code = raw2.trimmingCharacters(in: .whitespacesAndNewlines)
        busy = true; defer { busy = false }
        message = nil
        if child { return await verifyChild(email: email, code: code, again: again, childName: childName) }
        let v: PaxAPI.Verified
        do { v = try await api.verifyEmail(email: email, code: code, label: label) }
        catch let e as PaxAPIError {
            switch e.status {
            case 401, 422: message = PaxCopy.codeWrong
            case 429: message = PaxCopy.tooManyCodes
            default: message = e.message
            }
            return .failed
        } catch { message = PaxCopy.retryBody; return .failed }
        if again, !SetupRules.sameAccount(setUpID: policy.accountID, setUpEmail: policy.accountEmail,
                                          signedInID: v.account_id, signedInEmail: email) {
            message = PaxCopy.wrongAccount(setUpWith: policy.accountEmail, isPad: isPad)
            return .failed
        }
        api.keep(token: v.token)
        signedIn = true
        policy.accountEmail = email
        policy.accountID = v.account_id
        policy.save()
        existing = nil
        macDecision = nil
        return v.created == true ? .newAccount : .existingAccount
    }

    /// The child path: always a new child account (0.8.32), or, signing in again, exactly the
    /// child account this device was set up with. The token is kept only if it's a child's.
    private func verifyChild(email: String, code: String, again: Bool, childName: String?) async -> VerifyOutcome {
        let v: PaxAPI.Verified
        do {
            if again {
                guard let id = policy.accountID, !id.isEmpty else { message = PaxCopy.childNoAccountKnown; return .failed }
                v = try await api.signInChild(parentEmail: email, code: code, accountID: id, label: label)
            } else {
                v = try await api.verifyChild(parentEmail: email, code: code, label: label,
                                              childName: childName.flatMap(SetupRules.cleanName),
                                              deviceName: ChildSetup.deviceName(isPad: isPad))
            }
        } catch let e as PaxAPIError {
            message = ChildSetup.problem(status: e.status, code: e.code, starting: false)
                .map { ChildSetup.message($0, isPad: isPad) } ?? e.message
            return .failed
        } catch { message = PaxCopy.retryBody; return .failed }
        guard ChildSetup.keep(kind: v.kind) else {
            message = ChildSetup.message(.notChild, isPad: isPad)        // never the parent's account
            return .failed
        }
        if again, v.account_id != policy.accountID {
            message = PaxCopy.wrongAccount(setUpWith: nil, isPad: isPad)
            return .failed
        }
        api.keep(token: v.token)
        signedIn = true
        policy.accountEmail = email
        policy.accountID = v.account_id
        policy.save()
        existing = nil
        macDecision = .normal
        return .newAccount              // no "Welcome back": a child account is always new
    }

    /// "Welcome back": reads what the existing account already has (its wait, trusted person
    /// and devices). Nothing is changed here.
    func loadExisting(child: Bool) async -> Bool {
        busy = true; defer { busy = false }
        message = nil
        do {
            let a = try await api.me()
            applyAccount(a)
            let list = try await api.devices()
            let decision = await checkMacSetUp(list)
            existing = ExistingAccount(waitSeconds: a.wait_seconds, pendingWaitSeconds: a.pending_wait_seconds,
                                       trustedEmail: a.partner_email,
                                       devices: list.map { (name: $0.name, platform: $0.platform, released: $0.released) },
                                       child: child, profiles: list.map { $0.profile_identifier },
                                       joiningMac: { if case .joinMacSetUp = decision { return true }; return false }())
            return true
        } catch {
            message = PaxCopy.welcomeBackLoadFailed
            return false
        }
    }

    // MARK: set-up: a device already set up from a Mac (StrictSync)

    /// Looks for a Mac set-up on this device and this account. Run after the code, before
    /// anything is asked or added.
    @discardableResult
    func checkMacSetUp(_ list: [PaxAPI.DeviceStatus]? = nil) async -> StrictSync.Decision {
        let devices: [PaxAPI.DeviceStatus]
        if let list { devices = list } else { devices = (try? await api.devices()) ?? [] }
        let probe = await ProtectionCheck.run()
        let here = StrictSync.filteredHere(probe: probe, ownDNSConfigured: policy.dnsInstalled)
        filteredHere = here
        let d = StrictSync.decide(filteredHere: here, accountDevices: devices.map {
            StrictSync.AccountDevice(id: $0.device_id, profileIdentifier: $0.profile_identifier, released: $0.released ?? false)
        })
        macDecision = d
        return d
    }

    /// Joins the Mac's set-up: the same account, nothing new on the device or the server. No
    /// Screen Time request, no device record, no DNS configuration, no wait sent.
    func joinMacSetUp(deviceID: String?) {
        policy.macSetUp = true
        policy.macDeviceID = deviceID
        policy.setUpAt = policy.setUpAt ?? Date()
        policy.setUpFinished = false        // the Done screen sets it
        policy.save()
    }

    /// The account the code signed in to belongs to another set-up: forget its sign-in here.
    func leaveOtherAccount() {
        api.signOutLocally()
        signedIn = false
        policy.accountEmail = nil
        policy.accountID = nil
        policy.trustedEmail = nil
        policy.displayName = nil
        policy.save()
        existing = nil
    }

    // MARK: set-up: Screen Time, wait, escrow, settings

    /// Face ID once. Never called once Pax is on, or once access was given: a second call
    /// after approval lifts the delete block.
    func authorize() async {
        guard !policy.isActive, !policy.macSetUp, !authorized else { return }
        do { try await AuthorizationCenter.shared.requestAuthorization(for: .individual) }
        catch { message = PaxCopy.accessDenied }
    }

    /// After the code. Order matters and is fail closed:
    /// account (already signed in) → Screen Time (once) → wait (only longer) → escrow on the
    /// server → only then the settings.
    func turnOn(child: Bool) async -> TurnOnOutcome {
        if policy.isActive { return .on }
        message = nil
        guard api.signedIn else { signedIn = false; return .signedOut }
        // A device set up from a Mac never gets a second set-up over it (StrictSync).
        if policy.macSetUp { return .failed }
        if macDecision == nil || macDecision == .checkAgain { await checkMacSetUp() }
        switch macDecision {
        case .some(.joinMacSetUp(let id)): joinMacSetUp(deviceID: id); return .macSetUp
        case .some(.otherAccount): leaveOtherAccount(); message = PaxCopy.macOtherAccount(isPad: isPad); return .signedOut
        case .some(.checkAgain): message = PaxCopy.macCheckAgain(isPad: isPad); return .failed
        default: break
        }
        await authorize()
        guard authorized else { message = PaxCopy.accessDenied; return .denied }
        busy = true; defer { busy = false }
        do {
            // Turn-off wait: 7 days (30 for a child). Only ever lengthens an existing account's.
            let current = try await api.me()
            applyAccount(current)
            if child {
                // 0.8.32 sets the child's 30-day wait when it makes the account: nothing is sent.
                // Only a child account is ever set up on the child path (fail closed).
                guard ChildSetup.keep(kind: current.kind) else {
                    message = PaxCopy.childNeedsUpdate
                    return .failed
                }
            } else if let send = SetupRules.waitToSend(chosenDays: SetupRules.defaultWait(child: child),
                                                       currentSeconds: current.wait_seconds) {
                let longer = try await api.setWait(days: send)
                applyAccount(longer)
            }
            // Escrow first, then lock.
            try await lockIn(child: child)
        } catch let e as PaxAPIError where e.status == 401 {
            signedOutHere()
            return .signedOut
        } catch {
            message = (error as? PaxAPIError)?.message ?? PaxCopy.retryBody
            return .failed
        }
        startMonitoring()
        return .on
    }

    /// The release key is saved on the server before anything is switched on; if that throws,
    /// nothing changes. (The Screen Time passcode can be added later from Home.)
    private func lockIn(child: Bool) async throws {
        let secret = EscrowSecret.make(passcode: nil)
        let install = UUID().uuidString.lowercased()
        let d = try await api.registerDevice(name: UIDevice.current.name, platform: isPad ? "ipados" : "ios",
                                             installID: install, secret: secret)
        policy.deviceID = d.device_id
        policy.releaseKeyHash = secret.releaseKeyHash
        policy.passcodeEscrowed = false
        policy.audience = child ? .child : .me
        policy.setUpAt = Date()
        policy.isActive = true
        policy.setUpFinished = false        // the Done screen sets it
        policy.save()
        PaxSelection.save(selection)
        PaxRestrictions.apply(policy, selection: selection)
        inGrace = true
    }

    private func startMonitoring() {
        let center = DeviceActivityCenter()
        for w in Pax.monitorWindows {
            let schedule = DeviceActivitySchedule(intervalStart: DateComponents(hour: w.start, minute: 0),
                                                  intervalEnd: DateComponents(hour: w.end, minute: 59),
                                                  repeats: true)
            try? center.startMonitoring(DeviceActivityName(w.name), during: schedule)
        }
    }

    func finishSetUp() {
        policy.setUpFinished = true
        policy.save()
    }

    // MARK: Make Pax stronger (a): Lock Screen Time

    /// The passcode to type into Settings, after it is safely escrowed on the server (nil on
    /// failure: nothing to type, nothing changed). The same passcode is offered again until
    /// "I've set it", so a cancelled sheet never leaves an unknown code behind.
    func preparePasscode() async -> String? {
        if let pending = Keychain.get(Self.pendingPasscodeKey), pending.count == 4 { return pending }
        guard policy.isActive, let id = policy.deviceID else { return nil }
        // A secret from an earlier try whose answer never came back is sent again as it is, so
        // the server's copy and this device's hashes always agree.
        let secret: EscrowSecret
        if let saved = Keychain.get(Self.pendingEscrowKey), let s = EscrowSecret.open(saved), s.screenTimePasscode != nil {
            secret = s
        } else {
            secret = EscrowSecret.make(passcode: EscrowSecret.makePasscode())
            Keychain.set(secret.sealed, for: Self.pendingEscrowKey)
        }
        guard let code = secret.screenTimePasscode else { return nil }
        busy = true; defer { busy = false }
        message = nil
        // Written down before the server's copy changes (see PaxPolicy.pendingReleaseKeyHash), and
        // kept on any failure: an earlier try whose answer never came back may have saved it.
        policy.pendingReleaseKeyHash = secret.releaseKeyHash
        policy.save()
        var ok = false
        do {
            try await api.replaceEscrow(device: id, secret: secret)
            policy.releaseKeyHash = secret.releaseKeyHash
            policy.pendingReleaseKeyHash = nil
            policy.save()
            ok = true
        } catch let e as PaxAPIError {
            if e.status == 401 { signedOutHere() }
            message = LockRefusal.of(status: e.status, reason: e.reason)?.message(isPad: isPad) ?? e.message
        } catch {
            message = PaxCopy.retryBody
        }
        guard ok else { return nil }        // nothing to type; the same secret is tried next time
        Keychain.delete(Self.pendingEscrowKey)
        Keychain.set(code, for: Self.pendingPasscodeKey)
        return code
    }

    /// "I've set it": the passcode is wiped from this device. Only the server keeps it now.
    func passcodeSet() {
        Keychain.delete(Self.pendingPasscodeKey)
        policy.passcodeEscrowed = true
        policy.save()
    }

    // MARK: (b) someone you trust

    /// `from_name`: the first name typed here; an emptied field clears a name given before, and
    /// an untouched empty one sends nothing.
    func addTrusted(email raw: String, name: String?) async -> Bool {
        let t = SetupRules.normaliseEmail(raw)
        let n = SetupRules.cleanName(name ?? "")
        let fromName: String? = n ?? (policy.displayName == nil ? nil : "")
        var status: PaxAPI.AccountStatus?
        let ok = await run { status = try await self.api.setTrustedPerson(email: t, fromName: fromName) }
        guard ok, let s = status else { return false }
        applyAccount(s)
        return true
    }

    // MARK: (c) encrypted DNS

    func installDNS() async -> Bool {
        // Never a DNS configuration of this app's own over a Mac set-up's locked one.
        guard !policy.macSetUp else { return false }
        let ok = await run {
            let url = try await self.api.dnsInfo()
            try await PaxDNS.install(dohURL: url)
            self.policy.dnsInstalled = true
            self.policy.save()
        }
        if ok { dnsOn = await PaxDNS.isEnabled() }
        return ok
    }

    // MARK: (d) apps to keep closed

    func saveSelection() {
        PaxSelection.save(selection)
        if policy.isActive { PaxRestrictions.apply(policy, selection: selection) }
    }

    /// After set-up the picker only adds: what's already closed stays closed.
    /// The picker opens empty and its choices are merged in (SelectionRules), so un-choosing there
    /// can never take anything off: removal isn't offered for picked apps at all.
    func addApps(_ more: FamilyActivitySelection) {
        var merged = selection
        merged.applicationTokens = SelectionRules.merged(selection.applicationTokens, adding: more.applicationTokens)
        merged.webDomainTokens = SelectionRules.merged(selection.webDomainTokens, adding: more.webDomainTokens)
        merged.categoryTokens = SelectionRules.merged(selection.categoryTokens, adding: more.categoryTokens)
        selection = merged
        saveSelection()
    }

    // MARK: (e) turn-off wait

    /// Longer is instant; shorter is pending on the server for the current wait.
    func changeWait(days: Int) async -> WaitChange {
        let change = WaitChange.of(currentDays: policy.waitDays, newDays: days)
        guard change != .same else { return .same }
        var status: PaxAPI.AccountStatus?
        let ok = await run { status = try await self.api.setWait(days: days) }
        guard ok, let s = status else {
            if policy.audience == .child, message != nil { message = PaxCopy.childWaitFixed }
            return .same
        }
        applyAccount(s)
        if change == .longerNow { message = nil }
        return change
    }

    // MARK: blocked sites

    func addSite(_ raw: String) async {
        guard let d = PaxPolicy.normalise(raw) else { message = PaxCopy.sitesInvalid; return }
        guard policy.blockedDomains.count < Pax.maxCustomDomains else {
            message = "Pax can add up to \(Pax.maxCustomDomains) of your own sites here."; return
        }
        guard policy.addDomain(d) else { return }
        policy.save()
        PaxRestrictions.apply(policy, selection: selection)            // adding is instant
        _ = await run { try await self.api.addBlocked(domain: d) }      // DNS layer too
    }

    /// Asks the server to remove one of your own sites. It never comes off here at once: the
    /// person you trust is emailed first (503: nothing starts), then the turn-off wait.
    func requestSiteRemoval(_ domain: String) async {
        guard SiteRemoval.canRemove(domain, policy: policy) else { return }
        guard api.signedIn else { signedIn = false; message = PaxCopy.sitesSignInFirst; return }
        busy = true; defer { busy = false }
        message = nil
        do {
            let r: BlocklistRequestResult
            do { r = try await api.requestUnblock(domain: domain) }
            catch let e as PaxAPIError where e.status == 404 {
                // Only on this device (adding it to the server failed earlier): put it on the
                // server's list first, so the removal takes the same wait.
                try await api.addBlocked(domain: domain)
                r = try await api.requestUnblock(domain: domain)
            }
            guard let p = SiteRemoval.record(from: r, domain: domain) else { message = PaxCopy.sitesRemoveFailed; return }
            policy.pendingSiteRemovals.removeAll { $0.domain == domain }
            policy.pendingSiteRemovals.append(p)
            policy.save()
            serverOffset = Double(r.list.now) - Date().timeIntervalSince1970
        } catch let e as PaxAPIError where e.status == 409 {
            await refreshSites()                                         // already waiting: show it
        } catch let e as PaxAPIError {
            if e.status == 401 { signedOutHere() }
            message = e.status == 503 ? e.message : PaxCopy.sitesRemoveFailed
        } catch {
            message = PaxCopy.sitesRemoveFailed
        }
    }

    /// Keeps the site blocked: the waiting removal is cancelled on the server.
    func cancelSiteRemoval(_ domain: String) async {
        guard let p = SiteRemoval.pending(domain, in: policy) else { return }
        let ok = await run { _ = try await self.api.cancelBlocklistRequest(id: p.requestID) }
        if ok {
            policy.pendingSiteRemovals.removeAll { $0.domain == domain }
            policy.save()
        }
        await refreshSites()
    }

    /// Reads the server's list: a site comes off this device only when the server no longer has
    /// it and the server's clock is past its wait (SiteRemoval.reconcile). Errors change nothing.
    func refreshSites() async {
        guard api.signedIn, !policy.blockedDomains.isEmpty || !policy.pendingSiteRemovals.isEmpty else { return }
        guard let view = try? await api.blocklist() else { return }
        serverOffset = Double(view.now) - Date().timeIntervalSince1970
        let r = SiteRemoval.reconcile(local: policy.pendingSiteRemovals, blockedDomains: policy.blockedDomains, server: view)
        var p = policy
        if SiteRemoval.apply(r, to: &p) {
            policy = p
            policy.save()
            if policy.isActive { PaxRestrictions.apply(policy, selection: selection) }
        }
    }

    // MARK: blocked apps (by bundle ID, installed or not; BlockedApps.swift)

    /// Instant: saved, applied (blockedApplications), its websites added to your blocked sites if
    /// asked, and put on the server's list when it has one. Returns a calm problem, or nil.
    func blockApp(bundleID raw: String, name: String, domains: [String]) async -> String? {
        let bundleID = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let problem = AppBlockRules.problem(bundleID, policy: policy) {
            return PaxCopy.blockedAppsProblem(problem, isPad: isPad)
        }
        policy.blockedApps.append(BlockedApp(bundleID: bundleID, name: name))
        policy.save()
        if policy.isActive { PaxRestrictions.apply(policy, selection: selection) }   // adding is instant
        for d in domains where !policy.blockedDomains.contains(d) { await addSite(d) }
        if appsServerList, api.signedIn { try? await api.addApp(bundleID: bundleID, name: name) }
        return nil
    }

    /// "Another app": an App Store link (looked up with Apple's iTunes Lookup API) or a bundle ID.
    func blockAppEntry(_ raw: String, alsoSites: Bool) async -> String? {
        guard let entry = AppEntry.parse(raw) else { return PaxCopy.blockedAppsProblem(.notAnApp, isPad: isPad) }
        let bundleID: String
        var name: String
        switch entry {
        case .bundleID(let b):
            bundleID = b
            name = b
        case .appStoreID(let id):
            busy = true
            let found = await PaxAPI.lookUpApp(appStoreID: id, country: Locale.current.regionCode)
            busy = false
            guard let found else { return PaxCopy.blockedAppsLookupFailed }
            bundleID = found.bundleID
            name = found.name
        }
        let known = AppCatalog.entry(bundleID: bundleID)
        if let k = known { name = k.name }
        return await blockApp(bundleID: bundleID, name: name, domains: alsoSites ? (known?.domains ?? []) : [])
    }

    /// Reads the server's blocked-apps list. 404: the server has none (removal not offered). An
    /// app comes off this device only when the server no longer lists it and the server's clock is
    /// past its wait (AppRemoval.reconcile). Other errors change nothing.
    func refreshApps() async {
        guard api.signedIn else { return }
        let view: AppsViewInfo
        do { view = try await api.apps() }
        catch let e as PaxAPIError where e.status == 404 || e.status == 405 { appsServerList = false; return }
        catch { return }
        appsServerList = true
        serverOffset = Double(view.now) - Date().timeIntervalSince1970
        // Apps blocked before the server had a list: put them on it, so removing one takes the wait.
        let listed = Set(view.apps.map { $0.bundle_id })
        for a in policy.blockedApps where !listed.contains(a.bundleID)
            && !policy.pendingAppRemovals.contains(where: { $0.bundleID == a.bundleID }) {
            try? await api.addApp(bundleID: a.bundleID, name: a.name)
        }
        let r = AppRemoval.reconcile(local: policy.pendingAppRemovals, blocked: policy.blockedApps, server: view)
        var p = policy
        if AppRemoval.apply(r, to: &p) {
            policy = p
            policy.save()
            if policy.isActive { PaxRestrictions.apply(policy, selection: selection) }
        }
    }

    /// Asks the server to remove a blocked app. Never on the device alone: the person you trust is
    /// emailed first (503: nothing starts), then the turn-off wait.
    func requestAppRemoval(_ bundleID: String) async {
        guard AppRemoval.canRemove(bundleID, policy: policy, serverHasList: appsServerList) else { return }
        guard api.signedIn else { signedIn = false; message = PaxCopy.blockedAppsSignInFirst; return }
        busy = true; defer { busy = false }
        message = nil
        do {
            let r: AppRequestResult
            do { r = try await api.requestAppRemoval(bundleID: bundleID) }
            catch let e as PaxAPIError where e.status == 404 {
                let name = policy.blockedApps.first { $0.bundleID == bundleID }?.name ?? bundleID
                try await api.addApp(bundleID: bundleID, name: name)
                r = try await api.requestAppRemoval(bundleID: bundleID)
            }
            guard let rec = AppRemoval.record(from: r, bundleID: bundleID) else { message = PaxCopy.blockedAppsRemoveFailed; return }
            policy.pendingAppRemovals.removeAll { $0.bundleID == bundleID }
            policy.pendingAppRemovals.append(rec)
            policy.save()
            serverOffset = Double(r.list.now) - Date().timeIntervalSince1970
        } catch let e as PaxAPIError where e.status == 409 {
            await refreshApps()
        } catch let e as PaxAPIError {
            if e.status == 401 { signedOutHere() }
            message = e.status == 503 ? e.message : PaxCopy.blockedAppsRemoveFailed
        } catch {
            message = PaxCopy.blockedAppsRemoveFailed
        }
    }

    func cancelAppRemoval(_ bundleID: String) async {
        guard let p = AppRemoval.pending(bundleID, in: policy) else { return }
        let ok = await run { _ = try await self.api.cancelBlocklistRequest(id: p.requestID) }
        if ok {
            policy.pendingAppRemovals.removeAll { $0.bundleID == bundleID }
            policy.save()
        }
        await refreshApps()
    }

    // MARK: YouTube Restricted Mode (on the server; YouTubeRestricted)

    /// Reads it from the server. Fail closed: nothing readable keeps what's shown (on, no switch,
    /// at first). Never changes anything.
    func refreshYouTube() async {
        #if DEBUG
        if ScreenshotMode.any { return }
        #endif
        let child = policy.audience == .child
        let mac = policy.macSetUp && !policy.isActive
        guard api.signedIn else {
            youtube = YouTubeRestricted.row(categories: nil, dnsSetting: nil, child: child, macSetUp: mac)
            return
        }
        let cats = try? await api.categories()
        let dns = try? await api.dnsSettings()
        if cats == nil, dns == nil { return }
        if cats == nil, youtube.canSwitch { return }    // keep the switch and any waiting turn-off as shown
        if let c = cats { serverOffset = Double(c.now) - Date().timeIntervalSince1970 }
        youtube = YouTubeRestricted.row(categories: cats, dnsSetting: dns?.settings.youtube_restricted,
                                        child: child, macSetUp: mac)
    }

    /// Instant, on the server.
    func turnYouTubeOn() async {
        guard YouTubeRestricted.flip(youtube, to: true) == .turnOnNow else { return }
        guard api.signedIn else { signedIn = false; message = PaxCopy.youtubeSignInFirst; return }
        let ok = await run { _ = try await self.api.setYouTubeRestricted(true) }
        if !ok, message == nil { message = PaxCopy.youtubeFailed }
        await refreshYouTube()
    }

    /// Starts the turn-off wait on the server (the person you trust emailed first; 503: nothing
    /// starts). It stays on until the server's wait ends.
    func requestYouTubeOff() async {
        guard YouTubeRestricted.flip(youtube, to: false) == .confirmTurnOff else { return }
        guard api.signedIn else { signedIn = false; message = PaxCopy.youtubeSignInFirst; return }
        busy = true
        message = nil
        do {
            let r = try await api.setYouTubeRestricted(false)
            if let req = r.request, req.status == "pending", req.action == YouTubeRestricted.offAction {
                youtube.turningOff = YouTubeTurnOff(requestID: req.request_id, effectiveAt: req.effective_at)
            }
            if let now = r.now { serverOffset = Double(now) - Date().timeIntervalSince1970 }
        } catch let e as PaxAPIError where e.status == 409 {
            // already waiting: shown after the refresh
        } catch let e as PaxAPIError {
            if e.status == 401 { signedOutHere() }
            message = e.status == 503 ? e.message : PaxCopy.youtubeFailed
        } catch {
            message = PaxCopy.youtubeFailed
        }
        busy = false
        await refreshYouTube()
    }

    func cancelYouTubeOff() async {
        guard let t = youtube.turningOff else { return }
        _ = await run { _ = try await self.api.cancelBlocklistRequest(id: t.requestID) }
        await refreshYouTube()
    }

    // MARK: turning off (server decides; fail closed)

    func requestTurnOff() async {
        guard let id = policy.deviceID else { return }
        _ = await run {
            do { _ = try await self.api.requestTurnOff(device: id) }
            catch let e as PaxAPIError where e.status == 409 {}         // already asked for: fine
        }
        await refreshStatus()
    }

    func cancelTurnOff() async {
        guard let id = policy.deviceID else { return }
        _ = await run { _ = try await self.api.cancelTurnOff(device: id) }
        await refreshStatus()
    }

    /// The only path that removes anything: after the server released the secret and its hash
    /// matched one this device wrote down.
    func confirmTurnOff() async {
        guard let id = policy.deviceID else { return }
        busy = true; defer { busy = false }
        let sealed: String
        do { sealed = try await api.confirmTurnOff(device: id) }
        catch { message = error.localizedDescription; return }       // nothing cleared
        switch EscrowSecret.decide(sealed: sealed, acceptedHashes: policy.acceptedReleaseHashes) {
        case .stayOn(let reason):
            message = reason
        case .release(let passcode):
            PaxRestrictions.clearAll()
            DeviceActivityCenter().stopMonitoring()
            await PaxDNS.remove()
            AuthorizationCenter.shared.revokeAuthorization { _ in }
            PaxSelection.clear()
            Keychain.delete(Self.pendingPasscodeKey)
            Keychain.delete(Self.pendingEscrowKey)
            let email = policy.accountEmail
            let account = policy.accountID
            policy = PaxPolicy()
            policy.accountEmail = email
            policy.accountID = account
            policy.save()
            phase = .none
            revealedPasscode = passcode ?? ""
        }
    }

    // MARK: account deletion

    enum DeletionOutcome: Equatable {
        case deleted
        case emailRequest(URL)
        /// Pax is still on these devices: nothing was deleted. Turn Pax off first.
        case stillProtected([AccountDeletion.StillOn])
        case failed
    }

    func deleteAccount() async -> DeletionOutcome {
        busy = true; defer { busy = false }
        message = nil
        let outcome: AccountDeletion.Outcome
        do { outcome = try await api.deleteAccount() }
        catch { message = error.localizedDescription; return .failed }
        switch outcome {
        case .deleted:
            // Every token of the account is dead on the server: forget them here too.
            api.signOutLocally()
            signedIn = false
            policy.accountEmail = nil
            policy.accountID = nil
            policy.trustedEmail = nil
            policy.displayName = nil
            if !policy.isActive { policy.deviceID = nil }
            policy.save()
            account = nil
            return .deleted
        case .notAvailable, .signedOut:
            return .emailRequest(deletionMail())
        case .stillProtected(_, _, let devices):
            return .stillProtected(devices)
        case .rateLimited:
            message = PaxCopy.deleteRateLimited
            return .failed
        case .failed(let text):
            message = text
            return .failed
        }
    }

    private func deletionMail() -> URL {
        let email = policy.accountEmail ?? ""
        let ref = policy.deviceID ?? "none"
        var c = URLComponents()
        c.scheme = "mailto"
        c.path = Pax.supportEmail
        c.queryItems = [URLQueryItem(name: "subject", value: PaxCopy.deleteMailSubject),
                        URLQueryItem(name: "body", value: PaxCopy.deleteMailBody(email: email, accountRef: ref))]
        return c.url ?? URL(string: "mailto:\(Pax.supportEmail)")!
    }

    // MARK: plumbing

    @discardableResult
    private func run(_ work: @escaping @MainActor () async throws -> Void) async -> Bool {
        busy = true; defer { busy = false }
        message = nil
        do { try await work(); return true }
        catch {
            if let e = error as? PaxAPIError, e.status == 401 { signedOutHere() }
            message = error.localizedDescription
            return false
        }
    }

    /// The server no longer takes this device's sign-in (or there is none): Home offers
    /// "Sign in to Pax again" with the same email and code. Nothing on the device changes.
    private func signedOutHere() {
        api.signOutLocally()
        signedIn = false
    }
}
