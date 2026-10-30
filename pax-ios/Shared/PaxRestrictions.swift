// SPDX-License-Identifier: GPL-3.0-only
// Applies the person's choices through Managed Settings. Only `clearAll()` removes
// anything wholesale, and the app calls it only after the server has released the escrowed
// secret (AppModel.confirmTurnOff). One of the person's own sites leaves `blockedDomains` only
// after the server's turn-off wait for it ended (SiteRemoval). Never fail open.
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
        // Hardware tests T6/T6b: by bundle ID, so an app that isn't installed yet is named too.
        // Pax's untrusted browsers and the person's blocked apps (BlockedApps.swift), never
        // Pax itself, Apple's apps or password managers.
        store.application.blockedApplications =
            Set(AppBlockRules.bundleIDs(policy).map { Application(bundleIdentifier: $0) })
        if let s = selection {
            store.shield.applications = s.applicationTokens.isEmpty ? nil : s.applicationTokens
            store.shield.webDomains = s.webDomainTokens.isEmpty ? nil : s.webDomainTokens
            store.shield.applicationCategories = s.categoryTokens.isEmpty ? nil : .specific(s.categoryTokens)
        }
    }

    /// Only after the server released the secret and its hash matched.
    static func clearAll() { store.clearAllSettings() }
}

/// 1.3, a device set up from a Mac: the apps added on the phone, applied by the phone's own Screen
/// Time layer (.individual, asked for once; AppsAccess.shouldAskScreenTime). Its own named store,
/// so it never touches or competes with the Mac's profile or with `PaxRestrictions.store`: it sets
/// only `blockedApplications`, never a web filter, DNS or anything else, and is never cleared
/// wholesale. An app leaves it only after the server's turn-off wait (AppRemoval.reconcile).
/// Hardware test T6 (work/PLAN.md §9.5).
enum PhoneAppLayer {
    static let storeName = "pax.phone-apps"
    static let store = ManagedSettingsStore(named: ManagedSettingsStore.Name(storeName))

    static func apply(_ policy: PaxPolicy) {
        guard policy.macSetUp, !policy.isActive else { return }
        let ids = AppBlockRules.phoneLayerBundleIDs(policy)
        store.application.blockedApplications =
            ids.isEmpty ? nil : Set(ids.map { Application(bundleIdentifier: $0) })
    }
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
