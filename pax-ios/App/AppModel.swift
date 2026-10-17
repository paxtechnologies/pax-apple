// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import SwiftUI
import FamilyControls
import DeviceActivity
import UIKit

@MainActor
final class AppModel: ObservableObject {
    @Published var policy = PaxPolicy.load()
    @Published var selection = PaxSelection.load() ?? FamilyActivitySelection()
    @Published var turnOffUnlockAt: Date?
    @Published var message: String?
    @Published var busy = false
    @Published var dnsOn = false

    let api = PaxAPI()
    private var pendingSecret: EscrowSecret?

    var authorized: Bool { AuthorizationCenter.shared.authorizationStatus == .approved }

    func onLaunch() async {
        if policy.isActive {
            PaxRestrictions.apply(policy, selection: selection)   // self-heal
            dnsOn = await PaxDNS.isEnabled()
            if let id = policy.deviceID, let d = try? await api.status(device: id),
               let r = d.removal_request, r.status == "pending" {
                turnOffUnlockAt = Date(timeIntervalSince1970: r.unlock_at)
            }
        }
    }

    // MARK: set-up

    /// Face ID once. Never called again after set-up: a second call lifts the delete block.
    func authorize() async {
        guard !authorized else { return }
        do { try await AuthorizationCenter.shared.requestAuthorization(for: .individual) }
        catch { message = "Screen Time access wasn't given, so Pax can't protect this device yet." }
    }

    func createAccount(email: String, partner: String?, waitDays: Int) async -> Bool {
        await run {
            try await self.api.createAccount(email: email)
            try await self.api.setWait(days: waitDays)
            if let p = partner, !p.isEmpty { try await self.api.setPartner(email: p) }
            self.policy.waitDays = TurnOffRules.clampWait(days: waitDays)
            self.policy.hasPartner = !(partner ?? "").isEmpty
        }
    }

    /// Generates the Screen Time passcode the person will type into Settings.
    func preparePasscode() -> String {
        let code = EscrowSecret.makePasscode()
        pendingSecret = EscrowSecret.make(passcode: code)
        return code
    }

    /// Finishes set-up: escrow first, then lock. If escrow fails nothing is switched on.
    func finishSetUp(passcodeEscrow: Bool) async -> Bool {
        guard authorized else { message = "Pax needs Screen Time access first."; return false }
        let secret = passcodeEscrow ? (pendingSecret ?? .make(passcode: nil)) : .make(passcode: nil)
        return await run {
            let install = UUID().uuidString.lowercased()
            let platform = UIDevice.current.userInterfaceIdiom == .pad ? "ipados" : "ios"
            let id = try await self.api.registerDevice(name: UIDevice.current.name, platform: platform,
                                                       installID: install, secret: secret)
            self.pendingSecret = nil
            self.policy.deviceID = id
            self.policy.releaseKeyHash = secret.releaseKeyHash
            self.policy.passcodeEscrowed = secret.screenTimePasscode != nil
            self.policy.setUpAt = Date()
            self.policy.isActive = true
            self.policy.save()
            PaxSelection.save(self.selection)
            PaxRestrictions.apply(self.policy, selection: self.selection)
            try DeviceActivityCenter().startMonitoring(
                DeviceActivityName(Pax.dailyActivity),
                during: DeviceActivitySchedule(intervalStart: DateComponents(hour: 0, minute: 0),
                                               intervalEnd: DateComponents(hour: 23, minute: 59),
                                               repeats: true))
        }
    }

    // MARK: blocked sites

    func addSite(_ raw: String) async {
        guard let d = PaxPolicy.normalise(raw) else { message = "That doesn't look like a web address."; return }
        guard policy.blockedDomains.count < Pax.maxCustomDomains else {
            message = "Pax can add up to \(Pax.maxCustomDomains) of your own sites on iPhone."; return
        }
        _ = policy.addDomain(d)
        policy.save()
        PaxRestrictions.apply(policy, selection: selection)            // adding is instant
        _ = await run { try await self.api.addBlocked(domain: d) }
    }

    // MARK: turning off (server decides; fail closed)

    func requestTurnOff() async {
        guard let id = policy.deviceID else { return }
        _ = await run {
            let d = try await self.api.requestTurnOff(device: id)
            self.turnOffUnlockAt = d.removal_request.map { Date(timeIntervalSince1970: $0.unlock_at) } ?? Date()
        }
    }

    func cancelTurnOff() async {
        guard let id = policy.deviceID else { return }
        _ = await run { try await self.api.cancelTurnOff(device: id); self.turnOffUnlockAt = nil }
    }

    /// Returns the Screen Time passcode to show, if one was escrowed.
    func confirmTurnOff() async -> String? {
        guard let id = policy.deviceID, let expected = policy.releaseKeyHash else { return nil }
        busy = true; defer { busy = false }
        do {
            let sealed = try await api.confirmTurnOff(device: id)
            guard let secret = EscrowSecret.open(sealed), secret.releaseKeyHash == expected else {
                message = "The release didn't match this device, so Pax stays on."
                return nil
            }
            PaxRestrictions.clearAll()
            DeviceActivityCenter().stopMonitoring()
            AuthorizationCenter.shared.revokeAuthorization { _ in }
            policy = PaxPolicy()
            policy.save()
            turnOffUnlockAt = nil
            return secret.screenTimePasscode
        } catch {
            message = error.localizedDescription   // fail closed: nothing was cleared
            return nil
        }
    }

    @discardableResult
    private func run(_ work: @escaping @MainActor () async throws -> Void) async -> Bool {
        busy = true; defer { busy = false }
        do { try await work(); return true }
        catch { message = error.localizedDescription; return false }
    }
}
