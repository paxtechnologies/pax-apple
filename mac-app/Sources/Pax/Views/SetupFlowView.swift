// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import UniformTypeIdentifiers
import AppKit
import Combine
import PaxCore

/// The whole app (v0.7.0): a device switcher on the left (This Mac, each iPhone or
/// iPad, "Add iPhone or iPad"), and one calm column on the right. On a narrow window
/// the switcher becomes a segmented control in the toolbar.
struct SetupFlowView: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel
    @EnvironmentObject var blocklist: BlocklistModel
    @EnvironmentObject var updates: AppUpdatesModel

    static let sidebarMinWindowWidth: CGFloat = 900

    private var hasProtectedSomething: Bool { mac.deviceID != nil || !model.deviceRecords.isEmpty }
    /// Welcome with nothing set up yet stays a single calm screen.
    private var showSwitcher: Bool { hasProtectedSomething || model.screen != .welcome }

    var body: some View {
        GeometryReader { geo in
            let wide = geo.size.width >= Self.sidebarMinWindowWidth
            VStack(spacing: 0) {
                ScreenHeader(onLogoTap: hasProtectedSomething ? { model.screen = .home } : nil) {
                    // v0.8.14: no gear here any more; Settings is one place, in the sidebar (and ⌘,).
                    HStack(spacing: 16) {
                        if showSwitcher && !wide { CompactNav() }
                    }
                    .font(Theme.body(13))
                }
                HStack(spacing: 0) {
                    if showSwitcher && wide {
                        DeviceSidebar()
                            .frame(width: 236)
                        Divider().overlay(Theme.border)
                    }
                    main
                }
            }
            .toolbar {
                ToolbarItem(placement: .principal) {
                    if showSwitcher && !wide { DeviceSegmentedPicker() }
                }
            }
        }
        .background(SkyBackground())
        .onChange(of: mac.phase) { phase in
            if phase == .protected {
                model.selectedDevice = "mac"
                model.screen = .home
            }
        }
        // v0.8.26: phones' server status when the app opens and whenever it becomes active
        // (one request for all phones; no timer). Home and "Refresh status" do the rest.
        .task { await model.refreshPhones(quiet: true) }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refreshPhones(quiet: true) }
            updates.scan(.appear)       // v0.8.33: at most once a minute
        }
        // v0.8.33: an app or disk image dropped on the window, opened with Pax, a Home card
        // or a notification click: one-button confirmation, then pax-guard checks it.
        .onDrop(of: [UTType.fileURL], isTargeted: nil) { providers in
            guard let p = providers.first else { return false }
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in AppUpdatesModel.shared.open([url]) }
            }
            return true
        }
        .sheet(item: $updates.pending) { r in
            AppInstallConfirmSheet(request: r).environmentObject(updates)
        }
    }

    @ViewBuilder private var main: some View {
        Group {
            switch model.screen {
            case .welcome: WelcomeView()
            case .mac: ProtectMacView()
            case .iphone: PhoneFlowView()
            case .home: HomeView()
            case .blockedSites: BlockedSitesView()
            case .settings: AppSettingsView()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
}

/// Status of one entry in the switcher.
enum DeviceState: Equatable {
    case protected, pending, notSetUp
    /// v0.8.26 (iPhone/iPad, from the server): a turn-off wait, Pax off, or gone quiet.
    case turningOff, turnedOff, notCheckingIn

    var label: String {
        switch self {
        case .protected: return "Protected"
        case .pending: return "Setting up"
        case .notSetUp: return "Not set up"
        case .turningOff: return PhoneStatus.sidebarLabel(.turningOff(secondsLeft: 0, notifying: false))
        case .turnedOff: return PhoneStatus.sidebarLabel(.turnedOff)
        case .notCheckingIn: return PhoneStatus.sidebarLabel(.notCheckingIn(lastSeen: nil))
        }
    }
}

extension SetupModel {
    /// Switches to a device and opens its page (v0.8.14: status, details and its own
    /// switches together), or its set-up if this Mac isn't protected yet.
    func select(_ id: String, mac: MacProtectModel) {
        selectedDevice = id
        if id == "mac" {
            screen = mac.deviceID != nil || mac.phase == .released || mac.phase == .removed ? .home : .mac
        } else {
            screen = .home
        }
    }

    func addPhone() {
        step = .connect
        screen = .iphone
    }

    /// v0.8.26: from the server once it has answered (never from the set-up record alone).
    func state(of rec: PaxDeviceRecord) -> DeviceState {
        guard rec.status == .protected else { return .pending }
        switch phoneState(rec) {
        case .turnedOff?: return .turnedOff
        case .turningOff?: return .turningOff
        case .notCheckingIn?: return .notCheckingIn
        default: return .protected
        }
    }
}

extension MacProtectModel {
    var deviceState: DeviceState {
        if deviceID != nil { return .protected }
        if phase == .running || phase == .approveProfile || phase == .checked { return .pending }
        return .notSetUp
    }
}

/// The sidebar: devices first (each opens its Home page), then Blocked Sites / Apps and
/// the one app-wide Settings (v0.8.14; v0.8.21: no separate "Home" row).
struct DeviceSidebar: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("DEVICES").font(Theme.body(10.5, weight: .semibold)).tracking(1.4)
                .foregroundStyle(Theme.mutedText).padding(.horizontal, 10).padding(.bottom, 4)
            DeviceRowButton(icon: "laptopcomputer", name: "This Mac", state: mac.deviceState,
                            selected: deviceSelected("mac")) { model.select("mac", mac: mac) }
            ForEach(model.deviceRecords) { rec in
                DeviceRowButton(icon: rec.isIPad ? "ipad" : "iphone", name: rec.name, state: model.state(of: rec),
                                selected: deviceSelected(rec.id)) { model.select(rec.id, mac: mac) }
            }
            Button { model.addPhone() } label: {
                Label("Add iPhone or iPad", systemImage: "plus.circle")
                    .font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                    .padding(.horizontal, 10).padding(.vertical, 8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            Divider().overlay(Theme.border).padding(.vertical, 12)

            // v0.8.21: no "Home" row. The app opens on Home; a device above goes back to it.
            NavRow(title: AppNav.blockedTitle, icon: "nosign", selected: model.screen == .blockedSites) {
                model.screen = .blockedSites
            }
            .disabled(!model.hasAccount && !(mac.deviceID != nil && mac.isLocal))
            NavRow(title: "Settings", icon: "gearshape", selected: model.screen == .settings) {
                model.screen = .settings
            }
            Spacer()
            Text("Free and open source · GPL-3.0").font(Theme.body(10.5)).foregroundStyle(Theme.mutedText)
                .padding(.horizontal, 10)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 18)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Theme.sidebar)   // v0.8.16: translucent Mist over the sky wash
    }

    /// The picked device is highlighted, except on Settings (which isn't about one device).
    private func deviceSelected(_ id: String) -> Bool { model.selectedDevice == id && model.screen != .settings }
}

private struct DeviceRowButton: View {
    let icon: String
    let name: String
    let state: DeviceState
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: icon).font(.system(size: 16, weight: .light))
                    .foregroundStyle(Theme.primaryText).frame(width: 22)
                VStack(alignment: .leading, spacing: 1) {
                    Text(name).font(Theme.body(13.5, weight: selected ? .semibold : .regular))
                        .foregroundStyle(Theme.primaryText).lineLimit(1)
                    HStack(spacing: 5) {
                        Circle().fill(state == .protected ? Theme.accent : state == .pending ? Theme.mutedText : Theme.border)
                            .frame(width: 6, height: 6)
                        Text(state.label).font(Theme.body(11)).foregroundStyle(Theme.mutedText)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(RoundedRectangle(cornerRadius: 12).fill(selected ? Theme.card : Color.clear)
                .shadow(color: selected ? Theme.shadow : Color.clear, radius: 8, x: 0, y: 2))
            .overlay(RoundedRectangle(cornerRadius: 12).stroke(selected ? Theme.border.opacity(0.6) : Color.clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(name), \(state.label)")
    }
}

private struct NavRow: View {
    let title: String
    let icon: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            // v0.8.16: selected is a soft Haze pill with a dusk-blue icon (no orange).
            Label {
                Text(title).foregroundStyle(Theme.primaryText)
            } icon: {
                Image(systemName: icon).foregroundStyle(selected ? Theme.accent : Theme.mutedText)
            }
                .font(Theme.body(13, weight: selected ? .semibold : .regular))
                .padding(.horizontal, 10).padding(.vertical, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 10).fill(selected ? Theme.secondary : Color.clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// Narrow window: the device switcher as a segmented control in the toolbar.
struct DeviceSegmentedPicker: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        Picker("Device", selection: Binding(
            get: { model.selectedDevice },
            set: { id in if id == "add" { model.addPhone() } else { model.select(id, mac: mac) } })) {
            Text("This Mac").tag("mac")
            ForEach(model.deviceRecords) { rec in Text(rec.name).tag(rec.id) }
            Image(systemName: "plus").tag("add")
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(maxWidth: 420)
    }
}

/// Narrow window: Blocked Sites / Apps and Settings as links in the header (v0.8.21: no
/// "Home" link; the device picker, the logo and each page's back link go to Home).
private struct CompactNav: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        HStack(spacing: 14) {
            Button(AppNav.blockedTitle) { model.screen = .blockedSites }.buttonStyle(.link)
                .disabled(!model.hasAccount && !(mac.deviceID != nil && mac.isLocal))
            Button("Settings") { model.screen = .settings }.buttonStyle(.link)
        }
    }
}

// MARK: - Welcome

struct WelcomeView: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        PageColumn(maxWidth: 700) {
            VStack(alignment: .leading, spacing: 14) {
                // v0.8.16: "living." as the one italic accent word, in dusk blue.
                (Text("Less scrolling. More ").font(Theme.heading(40)).foregroundColor(Theme.primaryText)
                    + Text("living.").font(Theme.accentItalic(42)).foregroundColor(Theme.accent))
                    .accessibilityLabel(Brand.tagline)
                Text("What would you like to protect?")
                    .font(Theme.body(15))
                    .foregroundStyle(Theme.mutedText)
            }
            .padding(.top, 24)
            HStack(spacing: 18) {
                ChoiceCard(icon: "laptopcomputer", title: "This Mac",
                           detail: mac.deviceID != nil ? "Already protected." : "Every browser and app on this Mac.") {
                    if mac.phase == .intro { mac.step = 0 }
                    model.select("mac", mac: mac)
                }
                ChoiceCard(icon: "iphone", title: "iPhone or iPad",
                           detail: "Plug it into this Mac with a cable. You keep everything on it.") {
                    model.addPhone()
                }
            }
        }
    }
}

// MARK: - iPhone path

/// iPhone path (v0.7.0): 1 Plug in, 2 Choose what to block, 3 Turn-off wait,
/// 4 Lock it in. The checks, backup and method choice are all still here; Pax
/// works out what it can and only asks for what it can't.
struct PhoneFlowView: View {
    @EnvironmentObject var model: SetupModel

    var body: some View {
        PageColumn {
            if model.step != .done {
                StepProgress(titles: SetupStep.numbered.map(\.title),
                             current: SetupStep.numbered.firstIndex(of: model.step) ?? 0)
            }
            switch model.step {
            case .connect:
                ConnectStep()
                BackLink { model.startOver() }
            case .choose:
                ChooseBlocksStep(platform: .iphone, choices: $model.choices,
                                 filter: $model.config.dnsFilter) { model.next() }
                BackLink { model.back() }
            case .wait:
                WaitStep { model.saveWaitAndAccount { model.next() } }
                BackLink { model.back() }
            case .lockIn:
                PhoneLockInStep()
                if !model.lockInStarted { BackLink { model.back() } }
            case .done:
                PhoneDoneStep()
            }
        }
    }
}

private struct ConnectStep: View {
    @EnvironmentObject var model: SetupModel

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Plug in your iPhone",
                       subtitle: "Use a cable, unlock it, and tap Trust if it asks.")
            if model.devices.isEmpty {
                Card {
                    HStack(spacing: 12) {
                        if model.searching { ProgressView().controlSize(.small) }
                        Text(model.searching ? "Looking for your iPhone or iPad…" : "No iPhone or iPad found yet.")
                            .font(Theme.body(14)).foregroundStyle(Theme.primaryText)
                    }
                    if !model.searching && model.failure == nil {
                        Button("Look again") { model.startSearching() }.buttonStyle(SecondaryButtonStyle())
                    }
                }
            } else {
                ForEach(model.devices) { device in
                    DeviceRow(device: device, selected: device.ecid == model.selected?.ecid)
                        .onTapGesture { model.selected = device }
                }
            }
            if let failure = model.failure {
                ErrorCard(error: failure, retry: { model.retry() }, details: { model.supportDetails(failure) })
            }
            Button("Use this \(model.selected?.deviceType.hasPrefix("iPad") == true ? "iPad" : "iPhone")") {
                model.stopSearching()
                model.next()
            }
            .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
            .disabled(model.selected == nil)
        }
        .onAppear { if model.devices.isEmpty { model.startSearching() } }
        .onDisappear { model.stopSearching() }
    }
}

private struct DeviceRow: View {
    let device: ConnectedDevice
    let selected: Bool

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: device.deviceType.hasPrefix("iPad") ? "ipad" : "iphone")
                .font(.system(size: 26, weight: .light))
                .foregroundStyle(Theme.primaryText)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.name).font(Theme.body(15, weight: .semibold)).foregroundStyle(Theme.primaryText)
                Text("iOS \(device.firmwareVersion ?? "?")")
                    .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
            }
            Spacer()
            if selected { Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.accent) }
        }
        .padding(16)
        .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius)
            .stroke(selected ? Theme.accent : Theme.border, lineWidth: selected ? 2 : 1))
        .contentShape(Rectangle())
    }
}

/// Step 4: get ready (Find My, backup, agreement), one button, then calm progress
/// with the on-phone steps only when the phone needs you.
private struct PhoneLockInStep: View {
    @EnvironmentObject var model: SetupModel
    @State private var showAdvanced = false

    private var deviceWord: String { model.selected?.deviceType.hasPrefix("iPad") == true ? "iPad" : "iPhone" }
    private var isLive: Bool { (model.keepDataMethod ?? model.keepDataPlan.method) == .live }
    private var backupOK: Bool {
        model.config.mode == .clean || model.confirmedBackup || model.paxBackupPath != nil
    }
    private var modeAvailable: Bool {
        model.config.mode == .keepData ? model.keepDataAvailable : model.cleanAvailable
    }
    private var canStart: Bool {
        model.agreed && model.confirmedFindMyOff && backupOK && modeAvailable && !model.busy
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            if model.profilePendingUser {
                profilePending
            } else if model.supervised {
                supervisedView
            } else if model.lockInStarted {
                workingView
            } else {
                readyView
            }
            if let failure = model.failure {
                ErrorCard(error: failure, retry: { model.retry() }, details: { model.supportDetails(failure) })
                if model.config.mode == .keepData && model.cleanAvailable && !model.supervised {
                    Button("Erase and set up fresh instead") { model.fallBackToClean() }
                        .buttonStyle(.link).font(Theme.body(12))
                }
            }
        }
        .onAppear { if model.keepDataPhase == .preflight && !model.supervised { model.chooseDefaultMode() } }
    }

    // Before anything touches the phone
    private var readyView: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Lock it in",
                       subtitle: model.config.mode == .keepData
                           ? "Pax keeps everything on your \(deviceWord). It restarts once. About 10 to 20 minutes."
                           : "Pax backs up your \(deviceWord), erases it and sets it up fresh. About 30 to 60 "
                               + "minutes. You sign back in to iCloud afterwards.")
            Card {
                Text("Get your \(deviceWord) ready").font(Theme.body(15, weight: .medium))
                    .foregroundStyle(Theme.primaryText)
                CheckRow(isOn: $model.confirmedFindMyOff,
                         text: "Find My is off (Settings › your name › Find My). You'll turn it back on at the end.")
                if model.config.mode == .keepData {
                    if let path = model.paxBackupPath {
                        NoteRow(icon: "externaldrive.badge.checkmark",
                                text: "Backup saved and checked on this Mac (\((path as NSString).lastPathComponent)).")
                    } else {
                        HStack(spacing: 12) {
                            Button("Back up with Pax") { model.backUpWithPax() }
                                .buttonStyle(SecondaryButtonStyle())
                                .disabled(model.busy)
                            Text("Recommended. Takes a while.").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                        }
                        CheckRow(isOn: $model.confirmedBackup,
                                 text: "Or: I backed up this \(deviceWord) today with iCloud or Finder, and it finished.")
                    }
                }
                Divider().overlay(Theme.border)
                CheckRow(isOn: $model.agreed,
                         text: "I'm 18 or over, and this \(deviceWord) is mine or my child's. I understand that turning Pax "
                             + "off takes my turn-off wait (\(TurnOffWait.duration(days: model.config.waitDays))).")
            }
            if let p = model.preflight, !p.blocking.isEmpty || !p.warnings.isEmpty {
                Card {
                    ForEach(p.blocking, id: \.self) { line in NoteRow(icon: "exclamationmark.circle", text: line) }
                    ForEach(p.warnings, id: \.self) { line in NoteRow(icon: "info.circle", text: line) }
                    if let level = p.batteryLevel {
                        Text("Battery \(level)%").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    }
                }
            }
            if !modeAvailable {
                NoteRow(icon: "info.circle", text: model.config.mode == .keepData
                        ? model.keepDataPlan.explanation
                        : "Erasing and setting up fresh needs Apple Configurator's automation tools.")
            }
            DisclosureGroup("Advanced", isExpanded: $showAdvanced) { advanced.padding(.top, 8) }
                .font(Theme.body(13))
                .foregroundStyle(Theme.mutedText)
            HStack(spacing: 14) {
                Button("Protect my \(deviceWord)") { model.startProtecting() }
                    .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                    .disabled(!canStart)
                if model.busy { ProgressView().controlSize(.small) }
            }
        }
    }

    private var advanced: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("How to set up", selection: $model.config.mode) {
                Text(model.keepDataAvailable ? "Keep my data (recommended)" : "Keep my data (not available)")
                    .tag(SupervisionMode.keepData)
                Text(model.cleanAvailable ? "Erase and set up fresh" : "Erase and set up fresh (needs Apple Configurator)")
                    .tag(SupervisionMode.clean)
            }
            .pickerStyle(.radioGroup)
            Toggle("Use CleanBrowsing directly instead of Pax's filter (sites you add later, and the YouTube "
                   + "choice, then never reach this \(deviceWord))",
                   isOn: $model.useDirectCleanBrowsing)
            if model.config.mode == .keepData {
                Toggle("Strict: stop other computers connecting to this \(deviceWord) (also stops Finder backups; untested)",
                       isOn: $model.config.forbidPairing)
            } else {
                Toggle("Try restoring my backup afterwards (experimental; usually undoes the set-up)",
                       isOn: $model.config.restoreBackupAfterPrepare)
            }
        }
        .font(Theme.body(12.5))
    }

    // While Pax works on the phone
    private var workingView: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Protecting your \(deviceWord)",
                       subtitle: "Keep the cable connected and the \(deviceWord) unlocked.")
            Card {
                FriendlyProgress(fraction: model.lockInProgress.0, status: model.lockInProgress.1, log: model.log)
            }
            if model.config.mode == .clean {
                if model.waitingForHello {
                    Card {
                        Text("When your \(deviceWord) shows the “Hello” screen, click below.")
                            .font(Theme.body(14)).foregroundStyle(Theme.primaryText)
                        Button("I can see Hello") { model.userSawHelloScreen() }
                            .buttonStyle(PrimaryButtonStyle(accent: true))
                    }
                }
            } else {
                onPhone
            }
        }
    }

    @ViewBuilder private var onPhone: some View {
        Card {
            Text("On your \(deviceWord)").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
            InstructionRow(n: 1, text: "Leave it while it restarts by itself.")
            InstructionRow(n: 2, text: "When it says “Press home to upgrade”, press the Home button, or swipe up.")
            InstructionRow(n: 3, text: "Enter your passcode.")
            InstructionRow(n: 4, text: "If it asks “Trust This Computer?”, tap Trust and enter your passcode.")
            if isLive {
                InstructionRow(n: 5, text: "If it shows “Restore Completed”, stay on that screen until Pax says so.")
            }
        }
        if case .waitingForPhone(let state) = model.keepDataPhase {
            Card {
                NoteRow(icon: state == .trustRequested ? "hand.tap" : "iphone", text: state.instruction)
                if state == .trustRequested {
                    Button("I tapped Trust") { model.userTappedTrust() }
                        .buttonStyle(PrimaryButtonStyle(accent: true))
                        .disabled(model.busy)
                }
                if state == .denied {
                    Button("I plugged it back in") { model.userTappedTrust() }
                        .buttonStyle(SecondaryButtonStyle())
                }
                if state == .paired, model.failure != nil {
                    Text("If it shows Restore Completed, don't tap Continue yet. Keep it unlocked.")
                        .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    Button("Try again") { model.retryLiveConfiguration() }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(model.busy)
                }
                if model.waitingTooLong {
                    Text("Still waiting after 5 minutes. Unplug the \(deviceWord), plug it back in and unlock it. "
                         + "Pax keeps looking.")
                        .font(Theme.body(12.5)).foregroundStyle(Theme.warning)
                }
            }
        }
    }

    // Ready for the protection itself
    private var supervisedView: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Nearly there",
                       subtitle: isLive && model.config.mode == .keepData
                           ? "On your \(deviceWord), tap Continue on “Restore Completed” (if it's showing) and "
                               + "finish the few setup screens. Your Apple Account may ask for its password once."
                           : "Unlock your \(deviceWord). If any setup screens appear, finish them.")
            Card {
                FriendlyProgress(fraction: model.lockInProgress.0, status: model.lockInProgress.1, log: model.log)
            }
            HStack(spacing: 14) {
                Button("Turn on protection") { model.protect() }
                    .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                    .disabled(model.busy)
                if model.busy { ProgressView().controlSize(.small) }
            }
        }
    }

    private var profilePending: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "One tap on your \(deviceWord)",
                       subtitle: "Your \(deviceWord) asks you to approve Pax yourself.")
            Card {
                InstructionRow(n: 1, text: "Open Settings and tap “Profile Downloaded” near the top.")
                InstructionRow(n: 2, text: "Tap Install, enter your passcode, and tap Install again.")
                InstructionRow(n: 3, text: "Keep it unlocked and connected, then click below.")
            }
            Button("I installed it") { model.checkProfileInstalled() }
                .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                .disabled(model.busy)
        }
    }
}

private struct PhoneDoneStep: View {
    @EnvironmentObject var model: SetupModel

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "You're protected",
                       subtitle: model.config.mode == .keepData
                           ? "Everything on your iPhone is where you left it. " + TrialDay.doneLine
                           : "Finish the setup screens on the phone and sign back in to iCloud. "
                               + TrialDay.doneLine)
            Card {
                Label("Turn Find My back on", systemImage: "location.circle")
                    .font(Theme.body(15, weight: .semibold)).foregroundStyle(Theme.primaryText)
                Text("Settings › your name › Find My › Find My iPhone. It protects you if the phone is lost.")
                    .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            }
            Button("Go to Home") { model.screen = .home }
                .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
            CrisisLines()
        }
    }
}
