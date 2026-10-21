// SPDX-License-Identifier: GPL-3.0-only
// The app's state and every action that talks to Screen Time, the DNS settings or the
// Pax server. Fail closed throughout: settings are only ever added, except in
// `confirmTurnOff`, after the server released the secret and its hash matched.
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
    /// Shown once, after a turn-off: the Screen Time passcode (or "" if none was kept).
    @Published var revealedPasscode: String?

    let api = PaxAPI()

    init() {
        #if DEBUG
        if ScreenshotMode.home { policy = ScreenshotMode.samplePolicy; dnsOn = true }
        #endif
    }

    var isPad: Bool { UIDevice.current.userInterfaceIdiom == .pad }
    var authorized: Bool { AuthorizationCenter.shared.authorizationStatus == .approved }

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
    }

    func refreshStatus() async {
        guard let id = policy.deviceID, api.signedIn else { return }
        do {
            let d = try await api.status(device: id)
            apply(d)
        } catch {
            switch phase {
            case .waiting, .ready: phase = .unknown
            default: break
            }
        }
    }

    private func apply(_ d: PaxAPI.DeviceStatus) {
        inGrace = d.in_grace_period ?? false
        if let w = d.wait_seconds { policy.waitDays = TurnOffRules.days(fromSeconds: w); policy.save() }
        let r = d.removal_request
        phase = TurnOffRules.phase(requestStatus: r?.status, secondsRemaining: r?.seconds_remaining,
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
            try await api.notify(.accessOff(device: UIDevice.current.name, email: policy.accountEmail ?? ""),
                                 trustedEmail: policy.trustedEmail)
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
        let device = UIDevice.current.name, email = policy.accountEmail ?? ""
        let mail: PaxAlertEmail
        switch alert {
        case .none: return
        case .switchedOff: mail = .dnsOff(device: device, email: email)
        case .neverOn: mail = .dnsNeverOn(device: device, email: email)
        }
        do {
            try await api.notify(mail, trustedEmail: policy.trustedEmail)
            policy.dnsAlertSent = DNSWatch.sentKey(for: alert)
            policy.save()
        } catch {}                                          // tried again next launch
    }

    // MARK: set-up: account

    /// Sends the sign-in code (creating the account first if the email is new).
    func sendCode(email raw: String) async -> Bool {
        let email = SetupRules.normaliseEmail(raw)
        return await run {
            _ = try await self.api.createAccount(email: email)
            try await self.api.startSignIn(email: email)
        }
    }

    /// Signs in with the code, then reads the account's current wait and trusted person.
    func verifyCode(email raw: String, code: String) async -> PaxAPI.AccountStatus? {
        let email = SetupRules.normaliseEmail(raw)
        var status: PaxAPI.AccountStatus?
        let ok = await run {
            try await self.api.finishSignIn(email: email,
                                            code: code.trimmingCharacters(in: .whitespacesAndNewlines),
                                            label: self.isPad ? "iPad app" : "iPhone app")
            status = try await self.api.me()
        }
        guard ok, let s = status else { return nil }
        policy.accountEmail = s.email
        policy.trustedEmail = s.partner_email
        return s
    }

    /// Adds a trusted person if the account has none. An existing one is kept (changing
    /// it waits the turn-off wait and tells the current one first; that's done later).
    func saveTrusted(_ raw: String, existing: String?) async -> Bool {
        let t = SetupRules.normaliseEmail(raw)
        if let e = existing, !e.isEmpty { policy.trustedEmail = e; return true }
        if t.isEmpty { policy.trustedEmail = nil; return true }
        let ok = await run { try await self.api.setTrustedPerson(email: t) }
        if ok { policy.trustedEmail = t }
        return ok
    }

    /// Sets the wait if it's at least the account's current one; otherwise keeps the longer one.
    func saveWait(days: Int, currentSeconds: Int?) async -> Bool {
        guard let send = SetupRules.waitToSend(chosenDays: days, currentSeconds: currentSeconds) else {
            policy.waitDays = TurnOffRules.days(fromSeconds: currentSeconds ?? days * 86_400)
            message = PaxCopy.waitKept(policy.waitDays)
            return true
        }
        let ok = await run { try await self.api.setWait(days: send) }
        if ok { policy.waitDays = send }
        return ok
    }

    // MARK: set-up: Screen Time

    /// Face ID once. Never called once Pax is on: a second call lifts the delete block.
    func authorize() async {
        guard !policy.isActive else { return }
        guard !authorized else { return }
        do { try await AuthorizationCenter.shared.requestAuthorization(for: .individual) }
        catch { message = PaxCopy.accessDenied }
    }

    /// Escrow first, then lock. The sealed secret (Screen Time passcode, if chosen, plus a
    /// release key) is saved on the server before anything is switched on; if that fails,
    /// nothing changes. Returns the passcode to type into Settings ("" if none chosen),
    /// or nil on failure.
    func lockIn(passcode: Bool, audience: PaxAudience) async -> String? {
        guard !policy.isActive else { return "" }
        guard authorized else { message = PaxCopy.accessDenied; return nil }
        let code = passcode ? EscrowSecret.makePasscode() : nil
        let secret = EscrowSecret.make(passcode: code)
        let ok = await run {
            let install = UUID().uuidString.lowercased()
            let platform = self.isPad ? "ipados" : "ios"
            let d = try await self.api.registerDevice(name: UIDevice.current.name, platform: platform,
                                                      installID: install, secret: secret)
            self.policy.deviceID = d.device_id
            self.policy.releaseKeyHash = secret.releaseKeyHash
            self.policy.passcodeEscrowed = code != nil
            self.policy.audience = audience
            self.policy.setUpAt = Date()
            self.policy.isActive = true
            self.policy.save()
            PaxSelection.save(self.selection)
            PaxRestrictions.apply(self.policy, selection: self.selection)
            self.inGrace = true
        }
        guard ok else { return nil }
        startMonitoring()
        return code ?? ""
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

    // MARK: set-up: DNS

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

    func finishSetUp() {
        policy.setUpFinished = true
        policy.save()
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
            let d = try await self.api.requestTurnOff(device: id)
            self.apply(d)
        }
    }

    func cancelTurnOff() async {
        guard let id = policy.deviceID else { return }
        _ = await run {
            let d = try await self.api.cancelTurnOff(device: id)
            self.apply(d)
        }
    }

    /// The only path that removes anything.
    func confirmTurnOff() async {
        guard let id = policy.deviceID else { return }
        busy = true; defer { busy = false }
        let sealed: String
        do { sealed = try await api.confirmTurnOff(device: id) }
        catch { message = error.localizedDescription; return }       // nothing cleared
        switch EscrowSecret.decide(sealed: sealed, expectedHash: policy.releaseKeyHash) {
        case .stayOn(let reason):
            message = reason
        case .release(let passcode):
            PaxRestrictions.clearAll()
            DeviceActivityCenter().stopMonitoring()
            await PaxDNS.remove()
            AuthorizationCenter.shared.revokeAuthorization { _ in }
            PaxSelection.clear()
            let email = policy.accountEmail
            policy = PaxPolicy()
            policy.accountEmail = email
            policy.save()
            phase = .none
            revealedPasscode = passcode ?? ""
        }
    }

    // MARK: account deletion

    enum DeletionOutcome { case deleted, emailRequest(URL), failed }

    func deleteAccount() async -> DeletionOutcome {
        busy = true; defer { busy = false }
        do {
            switch try await api.deleteAccount() {
            case .deleted:
                api.signOutLocally()
                policy.accountEmail = nil
                policy.save()
                return .deleted
            case .notAvailable:
                return .emailRequest(deletionMail())
            }
        } catch let e as PaxAPIError where e.status == 401 {
            return .emailRequest(deletionMail())                      // signed out: ask by email
        } catch {
            message = error.localizedDescription
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
