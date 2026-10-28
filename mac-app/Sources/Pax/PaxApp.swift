// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

// TODO(v0.8): the bundle and defaults ID is still org.paxmobile.pax (UserDefaults,
// Keychain service names and `defaults write` test switches use it). Moving to
// org.paxpeace.pax needs a one-time migration of those values.

@main
struct PaxApp: App {
    @NSApplicationDelegateAdaptor(PaxAppDelegate.self) private var appDelegate
    @StateObject private var model: SetupModel
    @StateObject private var blocklist: BlocklistModel
    @StateObject private var mac: MacProtectModel

    init() {
        let model = SetupModel.live()
        let mac = MacProtectModel(setup: model)
        // Something already protected: open on Home, not on the welcome screen.
        if mac.deviceID != nil || !model.protectedPhones.isEmpty { model.screen = .home }
        _model = StateObject(wrappedValue: model)
        _blocklist = StateObject(wrappedValue: BlocklistModel { [weak model, weak mac] () -> BlocklistBackend? in
            // v0.8.0: this Mac on local escrow keeps its own list in pax-guard;
            // iPhones (and a Mac on the server path) use the server's.
            // v0.8.27: follows the Blocked Sites / Apps page's device (turned-off phones are skipped).
            if let mac, mac.deviceID != nil, mac.isLocal, mac.shownOnBlockedPage,
               model?.blockedPageSubject(macShown: true) == .mac { return mac.guardClient }
            guard let escrow = model?.coordinator.escrow, escrow.token != nil else { return nil }
            return escrow
        })
        _mac = StateObject(wrappedValue: mac)
        // v0.8.33: Open With › Pax, Dock drops, "App update ready" cards and notifications.
        AppUpdatesModel.shared.attach(isProtected: { [weak mac] in mac?.deviceID != nil })
        // v0.8.34: a mounted disk image with an app → "Install <App>?"; macOS's administrator
        // dialog → a small "Pax can do it for you" panel beside it.
        InstallHelpersModel.shared.attach(isProtected: { [weak mac] in mac?.deviceID != nil },
                                          showSettings: { [weak model] in model?.screen = .settings })
    }

    static let mainWindowID = "main"

    var body: some Scene {
        WindowGroup(Brand.name, id: PaxApp.mainWindowID) {
            SetupFlowView()
                .environmentObject(model)
                .environmentObject(blocklist)
                .environmentObject(mac)
                .environmentObject(AppUpdatesModel.shared)
                .frame(minWidth: 760, minHeight: 640)
                .background(SkyBackground())   // v0.8.16: the soft sky wash
        }
        // v0.8.20: no .windowResizability (macOS 13+). Its default for a WindowGroup on
        // 13+ is already contentMinSize, and macOS 12 sizes the window from the same
        // .frame(minWidth:minHeight:), so the window behaves the same everywhere.
        .commands {
            // v0.8.14: Pax › Settings… (⌘,) opens Settings in this window. There's no
            // separate Settings window any more, so there is one place for settings.
            CommandGroup(replacing: .appSettings) {
                OpenSettingsCommand(model: model)
            }
            CommandMenu("Pax") {
                Button("Home") { model.screen = .home }
                    .keyboardShortcut("h", modifiers: [.command, .shift])
                Button(AppNav.blockedMenuTitle) { model.screen = .blockedSites }
                    .keyboardShortcut("b", modifiers: [.command, .shift])
                    .disabled(!model.hasAccount && !(mac.deviceID != nil && mac.isLocal))
                Divider()
                Button("Protect this Mac") { model.screen = mac.deviceID != nil ? .home : .mac }
                    .keyboardShortcut("m", modifiers: [.command, .shift])
                Button("Protect an iPhone or iPad") {
                    model.step = .connect
                    model.screen = .iphone
                }
                Button("Start Over") { model.startOver() }
            }
        }
    }
}

/// Pax › Settings… (⌘,): shows the Settings screen in the main window, reopening the
/// window if it was closed.
private struct OpenSettingsCommand: View {
    @ObservedObject var model: SetupModel

    var body: some View {
        if #available(macOS 13, *) {
            OpenSettingsCommand13(model: model)
        } else {
            // v0.8.20, macOS 12: no openWindow environment action. Asking the app for a
            // new window makes SwiftUI open another window of the WindowGroup.
            OpenSettingsButton(model: model) {
                NSApp.sendAction(#selector(NSResponder.newWindowForTab(_:)), to: nil, from: nil)
            }
        }
    }
}

@available(macOS 13, *)
private struct OpenSettingsCommand13: View {
    @ObservedObject var model: SetupModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        OpenSettingsButton(model: model) { openWindow(id: PaxApp.mainWindowID) }
    }
}

private struct OpenSettingsButton: View {
    @ObservedObject var model: SetupModel
    let reopenWindow: () -> Void

    var body: some View {
        Button("Settings…") {
            model.screen = .settings
            let hasWindow = NSApp.windows.contains { $0.isVisible && $0.canBecomeMain }
            if !hasWindow { reopenWindow() }
            NSApp.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut(",", modifiers: .command)
    }
}
