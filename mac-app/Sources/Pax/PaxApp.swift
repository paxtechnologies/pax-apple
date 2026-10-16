// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

// TODO(v0.8): the bundle and defaults ID is still org.paxmobile.pax (UserDefaults,
// Keychain service names and `defaults write` test switches use it). Moving to
// org.paxpeace.pax needs a one-time migration of those values.

@main
struct PaxApp: App {
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
            if let mac, mac.deviceID != nil, mac.isLocal, model?.selectedRecord == nil { return mac.guardClient }
            guard let escrow = model?.coordinator.escrow, escrow.token != nil else { return nil }
            return escrow
        })
        _mac = StateObject(wrappedValue: mac)
    }

    static let mainWindowID = "main"

    var body: some Scene {
        WindowGroup(Brand.name, id: PaxApp.mainWindowID) {
            SetupFlowView()
                .environmentObject(model)
                .environmentObject(blocklist)
                .environmentObject(mac)
                .frame(minWidth: 760, minHeight: 640)
                .background(Theme.background)
        }
        .windowResizability(.contentMinSize)
        .commands {
            // v0.8.14: Pax › Settings… (⌘,) opens Settings in this window. There's no
            // separate Settings window any more, so there is one place for settings.
            CommandGroup(replacing: .appSettings) {
                OpenSettingsCommand(model: model)
            }
            CommandMenu("Pax") {
                Button("Home") { model.screen = .home }
                    .keyboardShortcut("h", modifiers: [.command, .shift])
                Button("Blocked Sites") { model.screen = .blockedSites }
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
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Settings…") {
            model.screen = .settings
            let hasWindow = NSApp.windows.contains { $0.isVisible && $0.canBecomeMain }
            if !hasWindow { openWindow(id: PaxApp.mainWindowID) }
            NSApp.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut(",", modifiers: .command)
    }
}
