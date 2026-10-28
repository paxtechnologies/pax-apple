// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import AppKit
import UserNotifications
import PaxCore

// v0.8.33 (Ruben, 28 Oct 2026): the simple doors into Pax-approved installs.
//   • Updates an app already downloaded → Home card + one notification per app and version.
//   • Open With › Pax, a drop on the Dock icon or the window → the one-button confirmation.
// Everything still goes through installs.start, so pax-guard's checks decide (nothing here
// can loosen Pax). Rules and wording live in PaxCore/AppUpdatePrompts.swift (tested).

@MainActor
final class AppUpdatesModel: ObservableObject {
    static let shared = AppUpdatesModel()

    /// "App update ready" cards on Home (from the latest scan).
    @Published private(set) var cards: [GuardClient.DownloadedUpdate] = []
    /// The confirmation sheet, when set.
    @Published var pending: AppInstallRequest?
    /// v0.8.34: Settings › Updates › "Install or update an app" should open (the admin-dialog helper).
    @Published var installerRequested = false

    private let client = GuardClient()
    private let defaults = UserDefaults.standard
    private var isProtected: () -> Bool = { false }
    private var attached = false
    private var waitingURLs: [URL] = []
    private var waitingClick: String??
    private var lastScan: Date?
    private var scanning = false
    private var timer: Task<Void, Never>?

    /// A real Pax.app bundle (not `swift run`): UserNotifications needs one.
    nonisolated static var notificationsAvailable: Bool {
        Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app"
    }

    /// Called once from PaxApp.init; files or a notification click that arrived first wait for this.
    func attach(isProtected: @escaping () -> Bool) {
        self.isProtected = isProtected
        attached = true
        if !waitingURLs.isEmpty { let urls = waitingURLs; waitingURLs = []; open(urls) }
        if let click = waitingClick { waitingClick = nil; openFromNotification(path: click) }
        scan(.launch)
        timer?.cancel()
        timer = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(AppUpdatePrompts.scanInterval * 1_000_000_000))
                guard let self else { return }
                self.scan(.periodic)
            }
        }
    }

    // MARK: downloaded updates → cards + notifications

    func scan(_ reason: AppUpdatePrompts.ScanReason) {
        guard attached, isProtected(), !scanning,
              AppUpdatePrompts.shouldScan(last: lastScan, now: Date(), reason: reason) else { return }
        scanning = true
        lastScan = Date()
        Task {
            defer { scanning = false }
            guard let found = try? await client.downloadedUpdates() else { return }
            let remembered = defaults.stringArray(forKey: AppUpdatePrompts.rememberedKey) ?? []
            let outcome = AppUpdatePrompts.process(found, remembered: remembered)
            cards = outcome.cards
            defaults.set(outcome.remembered, forKey: AppUpdatePrompts.rememberedKey)
            if !outcome.notify.isEmpty { Self.post(outcome.notify) }
        }
    }

    /// One notification per newly seen app+version (off the main actor: the completion runs elsewhere).
    nonisolated private static func post(_ updates: [GuardClient.DownloadedUpdate]) {
        guard notificationsAvailable else { return }
        let center = UNUserNotificationCenter.current()
        center.requestAuthorization(options: [.alert]) { granted, _ in
            guard granted else { return }      // the Home card is still there
            for u in updates {
                let content = UNMutableNotificationContent()
                content.title = "Pax"
                content.body = AppUpdatePrompts.notificationBody(u)
                content.categoryIdentifier = AppUpdatePrompts.categoryID
                content.userInfo = [AppUpdatePrompts.pathKey: u.path]
                let id = "pax.app-update." + AppUpdatePrompts.key(u)
                center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
            }
        }
    }

    /// A click on the notification: opens Pax on that install if it's still in the scan.
    func openFromNotification(path: String?) {
        guard attached else { waitingClick = .some(path); return }
        bringToFront()
        if let r = AppUpdatePrompts.requestForClick(path: path, current: cards) {
            pending = r
            return
        }
        // The cards may not be filled yet (Pax was just launched by the click): ask once more.
        Task {
            guard let found = try? await client.downloadedUpdates() else { return }
            cards = AppUpdatePrompts.process(found, remembered: defaults.stringArray(
                forKey: AppUpdatePrompts.rememberedKey) ?? []).cards
            if let r = AppUpdatePrompts.requestForClick(path: path, current: found) { pending = r }
        }
    }

    func update(_ u: GuardClient.DownloadedUpdate) { pending = AppUpdatePrompts.request(for: u) }

    // MARK: Open With, the Dock icon, a drop on the window

    func open(_ urls: [URL]) {
        guard attached else { waitingURLs += urls; return }
        switch AppOpenRouting.route(urls, protected: isProtected(), isInstalled: { name in
            FileManager.default.fileExists(atPath: "/Applications/\(name).app")
        }) {
        case .confirm(let r):
            bringToFront()
            if pending == nil { pending = r }
        case .reveal(let url):
            NSWorkspace.shared.activateFileViewerSelecting([url])
        case .ignore:
            break
        }
    }

    /// After a job finishes: the card for that app goes once the scan no longer finds it.
    func finished(_ path: String? = nil) {
        lastScan = nil
        scan(.appear)
        InstallHelpersModel.shared.jobFinished(path: path)      // v0.8.34
    }

    /// v0.8.34: a mounted disk image or the admin-dialog helper: Pax comes forward on the sheet
    /// (never over one that's already open).
    func present(_ r: AppInstallRequest) {
        guard attached, isProtected() else { return }
        bringToFront()
        if pending == nil { pending = r }
    }

    /// v0.8.34: Settings › Updates › "Install or update an app" (the row opens its sheet).
    func openInstaller() {
        bringToFront()
        installerRequested = true
    }

    private func bringToFront() {
        PaxActivation.showMainWindow()
    }
}

/// v0.8.35: an install-check launch starts with no Dock icon and its window ordered out; anything
/// that brings Pax forward (a sheet, a notification click, "Open Pax", reopening Pax) goes through here.
@MainActor
enum PaxActivation {
    static func becomeRegular() {
        if NSApp.activationPolicy() != .regular {
            _ = NSApp.setActivationPolicy(.regular)
        }
    }

    /// Main windows SwiftUI made (not the helper panel).
    static var mainWindows: [NSWindow] { NSApp.windows.filter { $0.canBecomeMain } }

    static func showMainWindow() {
        becomeRegular()
        NSApp.activate(ignoringOtherApps: true)
        if mainWindows.contains(where: { $0.isVisible }) { return }
        if let w = mainWindows.first {
            w.makeKeyAndOrderFront(nil)              // the window ordered out at launch
        } else {
            NSApp.sendAction(#selector(NSResponder.newWindowForTab(_:)), to: nil, from: nil)
        }
    }

    /// Keep Pax out of sight without hiding the app (a hidden app can't show the helper panel).
    static func orderOutMainWindows() {
        for w in mainWindows where w.isVisible { w.orderOut(nil) }
    }
}

/// Files opened with Pax (Finder's Open With, the Dock icon).
final class PaxAppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        if AppUpdatesModel.notificationsAvailable {
            UNUserNotificationCenter.current().delegate = PaxNotificationDelegate.shared
        }
        // v0.8.35: started by pax-guard for an install check: no Dock icon until there's something to show.
        if InstallCheckLaunch.startAsAccessory(arguments: ProcessInfo.processInfo.arguments, openedFiles: false) {
            _ = NSApp.setActivationPolicy(.accessory)
        }
    }

    /// v0.8.35: opening Pax again (Finder, Spotlight) after a quiet install-check start shows it normally.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard NSApp.activationPolicy() != .regular else { return true }     // as before
        Task { @MainActor in PaxActivation.showMainWindow() }
        return false
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        openedFiles = true
        Task { @MainActor in AppUpdatesModel.shared.open(urls) }
    }

    // v0.8.34: started at login by pax-guard's LaunchAgent (`--pax-login`): stay hidden in the
    // background, so the window doesn't pop open at each login. Pax still comes forward when
    // something needs it (an install prompt or notification activates it; so does the Dock icon).
    private var openedFiles = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        let args = ProcessInfo.processInfo.arguments
        if openedFiles, NSApp.activationPolicy() != .regular {
            _ = NSApp.setActivationPolicy(.regular)     // a file opened with Pax: show it normally
        }
        // v0.8.35: an install check keeps its windows ordered out (not NSApp.hide: a hidden app can't
        // put the helper panel up); Pax comes forward only for a sheet, a click or the panel.
        if InstallCheckLaunch.isInstallCheck(args) && !openedFiles {
            Task { @MainActor in
                PaxActivation.orderOutMainWindows()
                try? await Task.sleep(nanoseconds: 300_000_000)
                guard !self.openedFiles, !NSApp.isActive else { return }
                PaxActivation.orderOutMainWindows()
            }
            return
        }
        guard InstallCheckLaunch.startHidden(arguments: args, openedFiles: openedFiles) else { return }
        NSApp.hide(nil)
        // SwiftUI can put its window up just after launch: hide again on the next turn, unless
        // something has already brought Pax forward.
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 300_000_000)
            guard !self.openedFiles, !NSApp.isActive else { return }
            NSApp.hide(nil)
        }
    }
}

/// A click on "<App> has an update ready" opens Pax on that install.
final class PaxNotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = PaxNotificationDelegate()

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        let path = response.notification.request.content.userInfo[AppUpdatePrompts.pathKey] as? String
        Task { @MainActor in AppUpdatesModel.shared.openFromNotification(path: path) }
        completionHandler()
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                    @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner])
    }
}
