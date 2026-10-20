// SPDX-License-Identifier: GPL-3.0-only
// Applies the person's choices through Managed Settings. Only `clearAll()` removes
// anything, and the app calls it only after the server has released the escrowed
// secret (AppModel.confirmTurnOff). Everything else only ever adds: never fail open.
import Foundation
import ManagedSettings
import FamilyControls

enum PaxRestrictions {
    static let store = ManagedSettingsStore(named: ManagedSettingsStore.Name(Pax.storeName))

    static func apply(_ policy: PaxPolicy, selection: FamilyActivitySelection? = PaxSelection.load()) {
        guard policy.isActive else { return }
        let extra = Set(policy.blockedDomains.prefix(Pax.maxCustomDomains).map { WebDomain(domain: $0) })
        store.webContent.blockedByFilter = .auto(extra, except: [])
        store.application.denyAppRemoval = true
        store.dateAndTime.requireAutomaticDateAndTime = true
        store.account.lockAccounts = true                       // hardware test T3
        store.application.blockedApplications =                 // hardware test T6
            Set(Pax.bypassAppBundleIDs.map { Application(bundleIdentifier: $0) })
        if let s = selection {
            store.shield.applications = s.applicationTokens.isEmpty ? nil : s.applicationTokens
            store.shield.webDomains = s.webDomainTokens.isEmpty ? nil : s.webDomainTokens
            store.shield.applicationCategories = s.categoryTokens.isEmpty ? nil : .specific(s.categoryTokens)
        }
    }

    /// Only after the server released the secret and its hash matched.
    static func clearAll() { store.clearAllSettings() }
}

/// The apps and sites the person picked to shield (X, Bluesky, browsers). Opaque tokens only:
/// Pax can't read which apps they are, and nothing leaves the device.
enum PaxSelection {
    private static let key = "pax.selection.v1"
    static func load(from d: UserDefaults = Pax.shared) -> FamilyActivitySelection? {
        guard let data = d.data(forKey: key) else { return nil }
        return try? JSONDecoder().decode(FamilyActivitySelection.self, from: data)
    }
    static func save(_ s: FamilyActivitySelection, to d: UserDefaults = Pax.shared) {
        if let data = try? JSONEncoder().encode(s) { d.set(data, forKey: key) }
    }
    static func clear(from d: UserDefaults = Pax.shared) { d.removeObject(forKey: key) }
}
