// SPDX-License-Identifier: GPL-3.0-only
// The app's state and every action that talks to Screen Time, the DNS settings or the
// Pax server. Fail closed throughout: settings are only ever added, except in
// `confirmTurnOff`, after the server released the secret and its hash matched.
//
// 1.2 one-tap set-up: `turnOn` asks Screen Time once, then quietly makes a private device
// account (no email; servers without that route ask for an email and code instead), sets the
// turn-off wait, escrows the release key on the server and only then switches the settings
// on. Everything else is optional, on Home ("Make Pax stronger").
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

    let api = PaxAPI()

    private static let pendingPasscodeKey = "pending-screen-time-passcode"
    private static let releasedPasscodeKey = "released-screen-time-passcode"
    private static let pendingEscrowKey = "pending-escrow-secret"

    init() {
        #if DEBUG
        if ScreenshotMode.home { policy = ScreenshotMode.samplePolicy; dnsOn = true }
        #endif
    }

    var isPad: Bool { UIDevice.current.userInterfaceIdiom == .pad }
    var authorized: Bool { AuthorizationCenter.shared.authorizationStatus == .approved }
    var hasApps: Bool {
        !(selection.applicationTokens.isEmpty && selection.webDomainTokens.isEmpty && selection.categoryTokens.isEmpty)
    }
    /// The name or email the trusted person's emails use for this account.
    private var who: String { policy.accountEmail ?? policy.displayName ?? "" }

    // MARK: launch / foreground

    private var checking = false

    func onActive() async {
        #if DEBUG
        if ScreenshotMode.home { return }                    // screenshots: no network, no settings
        #endif
        guard policy.isActive, !checking else { return }
        checking = true; defer { checking = false }
        PaxRestrictions.apply(policy, selection: selection)      // self-heal
        await checkAccess()
        await checkDNS()
        await refreshStatus()
        await refreshAccount()
    }

    func refreshAccount() async {
        guard api.signedIn else { return }
        if let a = try? await api.me() { applyAccount(a) }
    }

    private func applyAccount(_ a: PaxAPI.AccountStatus) {
        account = a
        if let e = a.email, !e.isEmpty { policy.accountEmail = e }
        policy.trustedEmail = a.partner_email
        policy.waitDays = TurnOffRules.days(fromSeconds: a.wait_seconds)
        policy.save()
    }

    func refreshStatus() async {
        guard let id = policy.deviceID, api.signedIn else { return }
        do {
            let main = try await api.status(device: id)
            inGrace = main.in_grace_period ?? false
            if let w = main.wait_seconds { policy.waitDays = TurnOffRules.days(fromSeconds: w); policy.save() }
            var second: TurnOffPhase?
            if let pid = policy.passcodeDeviceID {
                let other = try await api.status(device: pid)
                second = Self.phase(of: other)
            }
            phase = TurnOffRules.combine(Self.phase(of: main), second)
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

    // MARK: set-up: email and code (child path, and servers without private accounts)

    /// Sends the sign-in code (creating the account first if the email is new).
    func sendCode(email raw: String) async -> Bool {
        let email = SetupRules.normaliseEmail(raw)
        return await run {
            _ = try await self.api.createAccount(email: email)
            try await self.api.startSignIn(email: email)
        }
    }

    /// Signs in with the code, then reads the account (its wait and trusted person are kept).
    func verifyCode(email raw: String, code: String) async -> Bool {
        let email = SetupRules.normaliseEmail(raw)
        var status: PaxAPI.AccountStatus?
        let ok = await run {
            try await self.api.finishSignIn(email: email,
                                            code: code.trimmingCharacters(in: .whitespacesAndNewlines),
                                            label: self.isPad ? "iPad app" : "iPhone app")
            status = try await self.api.me()
        }
        guard ok, let s = status else { return false }
        policy.privateAccount = false
        applyAccount(s)
        return true
    }

    // MARK: set-up: one tap

    /// Face ID once. Never called once Pax is on, or once access was given: a second call
    /// after approval lifts the delete block.
    func authorize() async {
        guard !policy.isActive, !authorized else { return }
        do { try await AuthorizationCenter.shared.requestAuthorization(for: .individual) }
        catch { message = PaxCopy.accessDenied }
    }

    /// The whole one-tap set-up. Order matters and is fail closed:
    /// Screen Time (once) → account → wait → escrow on the server → only then the settings.
    func turnOn(child: Bool) async -> TurnOnOutcome {
        if policy.isActive { return .on }
        message = nil
        await authorize()
        guard authorized else { message = PaxCopy.accessDenied; return .denied }
        busy = true; defer { busy = false }
        do {
            // 1. Account: a private device account, unless already signed in (child path,
            //    the email fallback, or a retry after a server hiccup).
            if !api.signedIn {
                switch try await api.createDeviceAccount(label: isPad ? "iPad app" : "iPhone app") {
                case .done:
                    policy.privateAccount = true
                    policy.accountEmail = nil
                    policy.save()
                case .notAvailable:
                    return .needsEmail
                }
            }
            // 2. Turn-off wait: 7 days (30 for a child). Only ever lengthens an existing account's.
            let current = try await api.me()
            applyAccount(current)
            if let send = SetupRules.waitToSend(chosenDays: SetupRules.defaultWait(child: child),
                                                currentSeconds: current.wait_seconds) {
                let longer = try await api.setWait(days: send)
                applyAccount(longer)
            }
            // 3. Escrow first, then lock.
            try await lockIn(child: child)
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
        let ok = await run {
            guard self.policy.passcodeDeviceID == nil else { return }   // an older server's second record holds it
            // Written down before the server's copy changes (see PaxPolicy.pendingReleaseKeyHash).
            self.policy.pendingReleaseKeyHash = secret.releaseKeyHash
            self.policy.save()
            switch try await self.api.replaceEscrow(device: id, secret: secret) {
            case .done:
                self.policy.releaseKeyHash = secret.releaseKeyHash
                self.policy.pendingReleaseKeyHash = nil
            case .notAvailable:
                // Older server: a second record on the account holds the passcode.
                self.policy.pendingReleaseKeyHash = nil
                let d = try await self.api.registerDevice(
                    name: "\(UIDevice.current.name) · Screen Time passcode",
                    platform: self.isPad ? "ipados" : "ios",
                    installID: UUID().uuidString.lowercased(), secret: secret, kind: "appstore.passcode")
                self.policy.passcodeDeviceID = d.device_id
                self.policy.passcodeKeyHash = secret.releaseKeyHash
            }
            self.policy.save()
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

    func addTrusted(email raw: String, name: String?) async -> Bool {
        let t = SetupRules.normaliseEmail(raw)
        let n = SetupRules.cleanName(name ?? "")
        var status: PaxAPI.AccountStatus?
        let ok = await run { status = try await self.api.setTrustedPerson(email: t, fromName: n) }
        guard ok, let s = status else { return false }
        if let n { policy.displayName = n }
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

    /// Every escrow record this device has: the main one, and the passcode one on older servers.
    private var records: [String] { [policy.deviceID, policy.passcodeDeviceID].compactMap { $0 } }

    func requestTurnOff() async {
        guard !records.isEmpty else { return }
        _ = await run {
            for id in self.records {
                do { _ = try await self.api.requestTurnOff(device: id) }
                catch let e as PaxAPIError where e.status == 409 {}     // already asked for: fine
            }
        }
        await refreshStatus()
    }

    func cancelTurnOff() async {
        guard !records.isEmpty else { return }
        _ = await run {
            for id in self.records { _ = try await self.api.cancelTurnOff(device: id) }
        }
        await refreshStatus()
    }

    /// The only path that removes anything. With a passcode record, it is released first and
    /// its passcode kept on this device until the main record is released too.
    func confirmTurnOff() async {
        guard let id = policy.deviceID else { return }
        busy = true; defer { busy = false }
        var passcode: String? = Keychain.get(Self.releasedPasscodeKey)
        if let pid = policy.passcodeDeviceID, passcode == nil {
            let sealed: String
            do { sealed = try await api.confirmTurnOff(device: pid) }
            catch { message = error.localizedDescription; return }      // nothing cleared
            switch EscrowSecret.decide(sealed: sealed, expectedHash: policy.passcodeKeyHash) {
            case .stayOn(let reason): message = reason; return
            case .release(let p):
                passcode = p
                if let p { Keychain.set(p, for: Self.releasedPasscodeKey) }
            }
        }
        let sealed: String
        do { sealed = try await api.confirmTurnOff(device: id) }
        catch { message = error.localizedDescription; return }       // nothing cleared
        switch EscrowSecret.decide(sealed: sealed, acceptedHashes: policy.acceptedReleaseHashes) {
        case .stayOn(let reason):
            message = reason
        case .release(let mainPasscode):
            PaxRestrictions.clearAll()
            DeviceActivityCenter().stopMonitoring()
            await PaxDNS.remove()
            AuthorizationCenter.shared.revokeAuthorization { _ in }
            PaxSelection.clear()
            Keychain.delete(Self.releasedPasscodeKey)
            Keychain.delete(Self.pendingPasscodeKey)
            Keychain.delete(Self.pendingEscrowKey)
            let email = policy.accountEmail
            let priv = policy.privateAccount
            policy = PaxPolicy()
            policy.accountEmail = email
            policy.privateAccount = priv
            policy.save()
            phase = .none
            revealedPasscode = mainPasscode ?? passcode ?? ""
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
            policy.accountEmail = nil
            policy.trustedEmail = nil
            policy.displayName = nil
            policy.privateAccount = false
            if !policy.isActive { policy.deviceID = nil; policy.passcodeDeviceID = nil }
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
        catch { message = error.localizedDescription; return false }
    }
}
