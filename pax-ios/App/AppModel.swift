// SPDX-License-Identifier: GPL-3.0-only
// The app's state and every action that talks to Screen Time, the DNS settings or the
// Pax server. Fail closed throughout: settings are only ever added, except in
// `confirmTurnOff`, after the server released the secret and its hash matched.
//
// 1.2 one-tap set-up: every Pax account has a verified email (server 0.8.31). The email and a
// 6-digit code come first (`sendCode`, `verifyCode`); then `turnOn` asks Screen Time once, only
// ever lengthens the turn-off wait, escrows the release key on the server and only then switches
// the settings on. Everything else is optional, on Home ("Make Pax stronger").
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

    let api = PaxAPI()

    private static let pendingPasscodeKey = "pending-screen-time-passcode"
    private static let pendingEscrowKey = "pending-escrow-secret"

    init() {
        signedIn = api.signedIn
        #if DEBUG
        if ScreenshotMode.home { policy = ScreenshotMode.samplePolicy; dnsOn = true; signedIn = true }
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
        if ScreenshotMode.home { return }                    // screenshots: no network, no settings
        #endif
        signedIn = api.signedIn
        guard policy.isActive, !checking else { return }
        checking = true; defer { checking = false }
        PaxRestrictions.apply(policy, selection: selection)      // self-heal
        await checkAccess()
        await checkDNS()
        await refreshStatus()
        await refreshAccount()
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

    /// Emails a 6-digit code (POST /v1/accounts/email/start; always the same answer).
    func sendCode(email raw: String) async -> Bool {
        let email = SetupRules.normaliseEmail(raw)
        busy = true; defer { busy = false }
        message = nil
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
    func verifyCode(email raw: String, code raw2: String, again: Bool = false) async -> VerifyOutcome {
        let email = SetupRules.normaliseEmail(raw)
        let code = raw2.trimmingCharacters(in: .whitespacesAndNewlines)
        busy = true; defer { busy = false }
        message = nil
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
        return v.created == true ? .newAccount : .existingAccount
    }

    /// "Welcome back": reads what the existing account already has (its wait, trusted person
    /// and devices). Nothing is changed here.
    func loadExisting(child: Bool) async -> Bool {
        busy = true; defer { busy = false }
        message = nil
        do {
            let a = try await api.me()
            applyAccount(a)
            let list = (try? await api.devices()) ?? []
            existing = ExistingAccount(waitSeconds: a.wait_seconds, pendingWaitSeconds: a.pending_wait_seconds,
                                       trustedEmail: a.partner_email,
                                       devices: list.map { (name: $0.name, platform: $0.platform, released: $0.released) },
                                       child: child)
            return true
        } catch {
            message = PaxCopy.welcomeBackLoadFailed
            return false
        }
    }

    // MARK: set-up: Screen Time, wait, escrow, settings

    /// Face ID once. Never called once Pax is on, or once access was given: a second call
    /// after approval lifts the delete block.
    func authorize() async {
        guard !policy.isActive, !authorized else { return }
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
        await authorize()
        guard authorized else { message = PaxCopy.accessDenied; return .denied }
        busy = true; defer { busy = false }
        do {
            // Turn-off wait: 7 days (30 for a child). Only ever lengthens an existing account's.
            let current = try await api.me()
            applyAccount(current)
            if let send = SetupRules.waitToSend(chosenDays: SetupRules.defaultWait(child: child),
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
    func addApps(_ more: FamilyActivitySelection) {
        var merged = selection
        merged.applicationTokens = selection.applicationTokens.union(more.applicationTokens)
        merged.webDomainTokens = selection.webDomainTokens.union(more.webDomainTokens)
        merged.categoryTokens = selection.categoryTokens.union(more.categoryTokens)
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
        guard ok, let s = status else { return .same }
        applyAccount(s)
        if change == .longerNow { message = nil }
        return change
    }

    // MARK: blocked sites

    func addSite(_ raw: String) async {
        guard let d = PaxPolicy.normalise(raw) else { message = "That doesn't look like a web address."; return }
        guard policy.blockedDomains.count < Pax.maxCustomDomains else {
            message = "Pax can add up to \(Pax.maxCustomDomains) of your own sites here."; return
        }
        guard policy.addDomain(d) else { return }
        policy.save()
        PaxRestrictions.apply(policy, selection: selection)            // adding is instant
        _ = await run { try await self.api.addBlocked(domain: d) }      // DNS layer too
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
