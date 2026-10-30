// SPDX-License-Identifier: GPL-3.0-only
// Home, simplified (Ruben, 24 Oct 2026: "simple clean minimal and functional"): the status at the
// top ("Pax is on", the turn-off wait), the "Make Pax stronger" nudge only while Screen Time isn't
// locked, and two actions, Blocked sites and Settings. Everything else is one-line rows in
// Settings (HomeLayout), with Turn off Pax last: the turn-off wait, the person you trust emailed
// first, fail closed, as before. A device set up from a Mac shows that set-up and only adds to it;
// a child's device has YouTube Restricted Mode always on.
import SwiftUI
import UIKit
import FamilyControls

extension SettingsItem: Identifiable { var id: String { rawValue } }

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    @State private var settingsShown = false
    @State private var sitesShown = false
    @State private var appsShown = false
    @State private var lockShown = false
    @State private var signInShown = false
    @State private var dnsGuideShown = false
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    private var isPad: Bool { model.isPad }
    private var p: PaxPolicy { model.policy }
    /// Set up from a Mac and joined by this app (StrictSync): show it, add to it, nothing else.
    private var mac: Bool { p.macSetUp && !p.isActive }

    var body: some View {
        PaxPage {
            HStack {
                PaxLogo(height: 46)
                Spacer()
                Button { settingsShown = true } label: {
                    Image(systemName: "gearshape").font(.system(size: 24))
                }
                .foregroundStyle(Palette.accent)
                .accessibilityLabel(PaxCopy.homeSettings)
            }
            if !model.signedIn { signInAgain }
            status
            if HomeLayout.showsNudge(p, macSetUp: mac) { nudge }
            actions
            MessageText(text: model.message)
        }
        .refreshable { await model.onActive() }
        .onReceive(tick) { now = $0 }
        .sheet(isPresented: $settingsShown) { SettingsView().environmentObject(model) }
        .sheet(isPresented: $sitesShown) { SitesView().environmentObject(model) }
        .sheet(isPresented: $appsShown) { BlockedAppsView().environmentObject(model) }
        .sheet(isPresented: $lockShown) { LockScreenTimeView().environmentObject(model) }
        .sheet(isPresented: $signInShown) { SignInAgainView().environmentObject(model) }
        .sheet(isPresented: $dnsGuideShown) { DNSGuideView(isPad: isPad) }
        .onAppear {
            #if DEBUG
            if ScreenshotMode.settings { settingsShown = true }
            if ScreenshotMode.sites { sitesShown = true }
            if ScreenshotMode.apps { appsShown = true }
            if ScreenshotMode.dnsGuide { dnsGuideShown = true }
            #endif
        }
    }

    /// The sign-in on this device was lost: Pax stays on; the same email and code sign in again.
    private var signInAgain: some View {
        PaxCard {
            Text(PaxCopy.signInAgainTitle)
                .font(PaxFont.heading(22, relativeTo: .title3)).foregroundStyle(Palette.ink)
            BodyText(PaxCopy.signInAgainBody(isPad: isPad))
            Button(PaxCopy.signInButton) { signInShown = true }.buttonStyle(PaxPrimaryButton())
        }
    }

    // MARK: the status

    private var status: some View {
        PaxCard {
            if model.accessLost && !mac {
                Text(PaxCopy.homeAccessLost)
                    .font(PaxFont.heading(28, relativeTo: .title2)).foregroundStyle(Palette.caution)
                    .fixedSize(horizontal: false, vertical: true)
                BodyText(PaxCopy.homeAccessLostBody(isPad: isPad, trusted: p.hasTrustedPerson))
            } else {
                HStack(alignment: .center, spacing: 14) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 34))
                        .foregroundStyle(Palette.good)
                        .accessibilityHidden(true)
                    Text(PaxCopy.homeOn)
                        .font(PaxFont.heading(36, relativeTo: .largeTitle)).foregroundStyle(Palette.ink)
                        .accessibilityAddTraits(.isHeader)
                }
                BodyText(PaxCopy.homeFilter)
            }
            VStack(alignment: .leading, spacing: 10) {
                StatusRow(text: PaxCopy.homeWait(p.waitDays), symbol: "hourglass", good: true)
                if mac {
                    StatusRow(text: PaxCopy.homeMacSetUp, symbol: "laptopcomputer", good: true)
                } else if p.audience == .child {
                    StatusRow(text: PaxCopy.homeChild, symbol: "person.2", good: true)
                }
            }
            if !mac { turnOffLine }
        }
    }

    /// Only while a turn-off is waiting or ready: the time left and Keep Pax on. Starting one is
    /// in Settings › Turn off Pax.
    @ViewBuilder private var turnOffLine: some View {
        switch model.phase {
        case .waiting(let until):
            let left = until.timeIntervalSince(now)
            BodyText(left > 0 ? PaxCopy.turnOffWaiting(TurnOffRules.describe(remaining: left)) : PaxCopy.turnOffReady,
                     small: true)
            Button(PaxCopy.keepOn) { Task { await model.cancelTurnOff() } }.buttonStyle(PaxSecondaryButton())
        case .ready:
            BodyText(PaxCopy.turnOffReady, small: true)
            Button(PaxCopy.keepOn) { Task { await model.cancelTurnOff() } }.buttonStyle(PaxSecondaryButton())
        case .none, .unknown:
            EmptyView()
        }
    }

    // MARK: Make Pax stronger (only while Screen Time isn't locked)

    private var nudge: some View {
        PaxCard {
            HStack(alignment: .firstTextBaseline) {
                Text(PaxCopy.strongerTitle)
                    .font(PaxFont.body(14, weight: .semibold, relativeTo: .caption))
                    .foregroundStyle(Palette.accent)
                    .textCase(.uppercase)
                    .tracking(1.1)
                Spacer(minLength: 4)
                Text(PaxCopy.recommended)
                    .font(PaxFont.body(13, weight: .semibold, relativeTo: .caption))
                    .foregroundStyle(Palette.buttonText)
                    .padding(.horizontal, 10).padding(.vertical, 4)
                    .background(Capsule().fill(Palette.accent))
            }
            Text(PaxCopy.lockTitle)
                .font(PaxFont.body(19, weight: .semibold, relativeTo: .title3)).foregroundStyle(Palette.ink)
            BodyText(PaxCopy.lockBody, small: true)
            Button(PaxCopy.lockButton) { lockShown = true }.buttonStyle(PaxPrimaryButton())
        }
        .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).stroke(Palette.accent, lineWidth: 2))
    }

    // MARK: two actions

    private var actions: some View {
        RowGroup {
            ForEach(Array(HomeLayout.actions.enumerated()), id: \.offset) { i, a in
                if i > 0 { RowDivider() }
                switch a {
                case .blockedSites:
                    NavRow(title: PaxCopy.homeSites, symbol: "nosign",
                           value: PaxCopy.sitesCount(p.blockedDomains.count)) { sitesShown = true }
                case .settings:
                    NavRow(title: PaxCopy.homeSettings, symbol: "gearshape") { settingsShown = true }
                }
            }
        }
    }
}

// MARK: - Settings: everything else, one line each

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var open: SettingsItem?
    @State private var pickerShown = false
    @State private var moreApps = FamilyActivitySelection()
    @State private var confirmYouTubeOff = false
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    private var p: PaxPolicy { model.policy }
    private var mac: Bool { p.macSetUp && !p.isActive }

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.settingsTitle)
                group(PaxCopy.settingsProtection, HomeLayout.protection(macSetUp: mac, appsList: model.appsServerList))
                group(PaxCopy.settingsAccount, HomeLayout.yourAccount(macSetUp: mac))
                RowGroup {
                    ForEach(HomeLayout.last) { item in row(item) }
                }
                MessageText(text: model.message)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
        .onReceive(tick) { now = $0 }
        .onAppear { model.loadAppsCacheIfNeeded() }           // local cache only, no network
        .task { await model.refreshYouTube() }
        .familyActivityPicker(isPresented: $pickerShown, selection: $moreApps)
        .onChange(of: pickerShown) { shown in
            if !shown { model.addApps(moreApps); moreApps = FamilyActivitySelection() }
        }
        .sheet(item: $open) { item in sheet(for: item) }
        .confirmationDialog(PaxCopy.youtubeOffTitle, isPresented: $confirmYouTubeOff, titleVisibility: .visible) {
            Button(PaxCopy.turnOffStart) { Task { await model.requestYouTubeOff() } }
            Button(PaxCopy.youtubeKeepOn, role: .cancel) {}
        } message: {
            Text(PaxCopy.youtubeOffBody(waitDays: p.waitDays, trusted: p.hasTrustedPerson))
        }
    }

    private func group(_ title: String, _ items: [SettingsItem]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(PaxFont.body(14, weight: .semibold, relativeTo: .caption))
                .foregroundStyle(Palette.accent)
                .textCase(.uppercase)
                .tracking(1.1)
                .padding(.leading, 6)
                .accessibilityAddTraits(.isHeader)
            RowGroup {
                ForEach(Array(items.enumerated()), id: \.offset) { i, item in
                    if i > 0 { RowDivider() }
                    row(item)
                }
            }
        }
    }

    @ViewBuilder private func row(_ item: SettingsItem) -> some View {
        switch item {
        case .lockScreenTime:
            NavRow(title: PaxCopy.rowLock, symbol: "key",
                   value: p.passcodeEscrowed ? PaxCopy.rowOn : PaxCopy.rowNotYet) { open = .lockScreenTime }
        case .encryptedDNS:
            NavRow(title: PaxCopy.rowDNS, symbol: "network",
                   value: !p.dnsInstalled ? PaxCopy.rowNotAdded : (model.dnsOn == true ? PaxCopy.rowOn : PaxCopy.rowOff)) {
                open = .encryptedDNS
            }
        case .appsToClose:
            NavRow(title: PaxCopy.rowApps, symbol: "app.badge",
                   value: PaxCopy.rowAppsValue(model.selection.applicationTokens.count
                                               + model.selection.webDomainTokens.count
                                               + model.selection.categoryTokens.count)) { pickerShown = true }
        case .blockedApps:
            NavRow(title: PaxCopy.rowBlockedApps, symbol: "xmark.app",
                   value: PaxCopy.rowAppsValue(model.appRows.count)) { open = .blockedApps }
        case .blockedSites:
            NavRow(title: PaxCopy.homeSites, symbol: "nosign",
                   value: PaxCopy.sitesCount(p.blockedDomains.count)) { open = .blockedSites }
        case .youtube:
            youtubeRow
        case .trustedPerson:
            NavRow(title: PaxCopy.rowTrusted, symbol: "person.2",
                   value: p.hasTrustedPerson ? (p.trustedEmail ?? "") : PaxCopy.rowNotAdded) { open = .trustedPerson }
        case .turnOffWait:
            NavRow(title: PaxCopy.rowWait, symbol: "hourglass",
                   value: TurnOffRules.waitLabel(days: p.waitDays)) { open = .turnOffWait }
        case .computerSetup:
            NavRow(title: PaxCopy.rowComputer, symbol: "laptopcomputer") { open = .computerSetup }
        case .account:
            NavRow(title: PaxCopy.rowAccount, symbol: "person.crop.circle") { open = .account }
        case .turnOff:
            NavRow(title: PaxCopy.rowTurnOff, symbol: "power", value: turnOffValue, quiet: true) { open = .turnOff }
        }
    }

    private var turnOffValue: String? {
        if mac { return PaxCopy.rowFromMac }
        if case .waiting(let until) = model.phase, until.timeIntervalSince(now) > 0 {
            return TurnOffRules.describe(remaining: until.timeIntervalSince(now))
        }
        return nil
    }

    /// YouTube Restricted Mode: a switch only when the server does the wait (never for a child or a
    /// Mac set-up). Off asks first and starts the wait; on is instant. While it waits it's still on.
    @ViewBuilder private var youtubeRow: some View {
        let y = model.youtube
        VStack(alignment: .leading, spacing: 8) {
            if y.canSwitch {
                Toggle(isOn: Binding(get: { model.youtube.isOn }, set: { on in
                    switch YouTubeRestricted.flip(model.youtube, to: on) {
                    case .confirmTurnOff: confirmYouTubeOff = true
                    case .turnOnNow: Task { await model.turnYouTubeOn() }
                    case .nothing: break
                    }
                })) {
                    RowLabel(title: PaxCopy.youtubeTitle, symbol: "play.rectangle")
                }
                .tint(Palette.accent)
                .padding(.vertical, 12)
            } else {
                HStack(spacing: 12) {
                    RowLabel(title: PaxCopy.youtubeTitle, symbol: "play.rectangle")
                    Spacer(minLength: 8)
                    Text(y.value == .alwaysOn ? PaxCopy.youtubeAlwaysOn : (y.value == .off ? PaxCopy.rowOff : PaxCopy.rowOn))
                        .font(PaxFont.body(16, relativeTo: .callout)).foregroundStyle(Palette.body)
                }
                .padding(.vertical, 14)
                .accessibilityElement(children: .combine)
            }
            if let t = y.turningOff {
                let left = YouTubeRestricted.remaining(t, serverOffset: model.serverOffset, now: now)
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text(left > 60 ? PaxCopy.youtubeTurningOff(TurnOffRules.describe(remaining: left))
                                   : PaxCopy.youtubeTurningOffSoon)
                        .font(PaxFont.body(14, relativeTo: .footnote)).foregroundStyle(Palette.caution)
                    Spacer(minLength: 8)
                    Button(PaxCopy.youtubeCancel) { Task { await model.cancelYouTubeOff() } }
                        .font(PaxFont.body(15, weight: .semibold)).foregroundStyle(Palette.accent)
                }
                .padding(.bottom, 12)
            }
            if !mac, !p.dnsInstalled || model.dnsOn == false {
                Text(PaxCopy.youtubeWithDNS)
                    .font(PaxFont.body(14, relativeTo: .footnote)).foregroundStyle(Palette.body)
                    .padding(.bottom, 12)
            }
        }
    }

    @ViewBuilder private func sheet(for item: SettingsItem) -> some View {
        switch item {
        case .lockScreenTime: LockScreenTimeView().environmentObject(model)
        case .encryptedDNS: DNSView().environmentObject(model)
        case .blockedSites: SitesView().environmentObject(model)
        case .blockedApps: BlockedAppsView().environmentObject(model)
        case .trustedPerson: TrustedPersonView().environmentObject(model)
        case .turnOffWait: WaitChangeView().environmentObject(model)
        case .computerSetup: ComputerSetupView(isPad: model.isPad)
        case .account: AccountView().environmentObject(model)
        case .turnOff: TurnOffView().environmentObject(model)
        case .appsToClose, .youtube: EmptyView()
        }
    }
}

// MARK: - rows

/// A white rounded card holding one-line rows.
struct RowGroup<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(.horizontal, 18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 22, style: .continuous).fill(Palette.card))
            .shadow(color: Color.black.opacity(0.05), radius: 16, y: 6)
    }
}

struct RowDivider: View {
    var body: some View { Rectangle().fill(Palette.haze.opacity(0.6)).frame(height: 1).padding(.leading, 36) }
}

struct RowLabel: View {
    let title: String
    let symbol: String
    var quiet = false
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 17))
                .foregroundStyle(quiet ? Palette.body : Palette.accent)
                .frame(width: 24)
                .accessibilityHidden(true)
            Text(title)
                .font(PaxFont.body(17, weight: quiet ? .regular : .medium, relativeTo: .body))
                .foregroundStyle(quiet ? Palette.body : Palette.ink)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)   // the value shortens first, never the title
        }
        .layoutPriority(1)
    }
}

/// One line: symbol, title, a short value, chevron.
struct NavRow: View {
    let title: String
    let symbol: String
    var value: String? = nil
    var quiet = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                RowLabel(title: title, symbol: symbol, quiet: quiet)
                Spacer(minLength: 8)
                if let v = value, !v.isEmpty {
                    Text(v)
                        .font(PaxFont.body(16, relativeTo: .callout))
                        .foregroundStyle(Palette.body)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Palette.haze)
                    .accessibilityHidden(true)
            }
            .padding(.vertical, 15)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Blocked sites

/// Your blocked sites: adding is instant; removing one starts the turn-off wait on the server,
/// "Removing, available in …" with Cancel, and it comes off only after the wait.
struct SitesView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var newSite = ""
    @State private var removing: String?
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()
    private var p: PaxPolicy { model.policy }

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.sitesTitle)
                PaxCard {
                    HStack(spacing: 10) {
                        TextField("example.com", text: $newSite)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                            .font(PaxFont.body(17))
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: 12).fill(Palette.haze.opacity(0.35)))
                        Button(PaxCopy.sitesAdd) {
                            let s = newSite
                            newSite = ""
                            Task { await model.addSite(s) }
                        }
                        .font(PaxFont.body(17, weight: .semibold))
                        .foregroundStyle(Palette.accent)
                        .disabled(PaxPolicy.normalise(newSite) == nil)
                    }
                    ForEach(p.blockedDomains, id: \.self) { d in siteRow(d) }
                }
                BodyText(PaxCopy.sitesFooter, small: true)
                MessageText(text: model.message)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
        .onReceive(tick) { now = $0 }
        .confirmationDialog(PaxCopy.sitesRemoveTitle(removing ?? ""),
                            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
                            titleVisibility: .visible) {
            Button(PaxCopy.turnOffStart) {
                let d = removing ?? ""
                removing = nil
                Task { await model.requestSiteRemoval(d) }
            }
            Button(PaxCopy.sitesKeep, role: .cancel) { removing = nil }
        } message: {
            Text(PaxCopy.sitesRemoveBody(waitDays: p.waitDays, trusted: p.hasTrustedPerson))
        }
    }

    private func siteRow(_ d: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(d).font(PaxFont.body(16)).foregroundStyle(Palette.body)
                if let pr = SiteRemoval.pending(d, in: p) {
                    let left = SiteRemoval.remaining(pr, serverOffset: model.serverOffset, now: now)
                    Text(left > 60 ? PaxCopy.sitesRemoving(TurnOffRules.describe(remaining: left)) : PaxCopy.sitesRemovingSoon)
                        .font(PaxFont.body(14, relativeTo: .footnote)).foregroundStyle(Palette.caution)
                }
            }
            Spacer(minLength: 8)
            if SiteRemoval.pending(d, in: p) != nil {
                Button(PaxCopy.sitesCancel) { Task { await model.cancelSiteRemoval(d) } }
                    .font(PaxFont.body(15, weight: .semibold)).foregroundStyle(Palette.accent)
            } else {
                Button(PaxCopy.sitesRemove) {
                    if model.signedIn { removing = d } else { model.message = PaxCopy.sitesSignInFirst }
                }
                .font(PaxFont.body(15, weight: .medium)).foregroundStyle(Palette.accent)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Blocked apps (by bundle ID, installed or not; one list for Mac and iPhone)

/// Block an app, even one that isn't installed: a short curated search, or an App Store link /
/// bundle ID. Adding is instant. 1.3: the account's one list (AppsSync), each app labelled by where
/// it was added, shown at once from the cache and refreshed on pull. Removing one takes the
/// turn-off wait on the server ("Removing, available in …" + Cancel), and only where the server
/// keeps the list; otherwise it stays blocked. On a device set up from a Mac, apps added on the Mac
/// are read-only here (removed from Pax on that Mac).
struct BlockedAppsView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""
    @State private var other = ""
    @State private var alsoSites = true
    @State private var problem: String?
    @State private var removing: AppRow?
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()
    private var p: PaxPolicy { model.policy }
    private var mac: Bool { p.macSetUp && !p.isActive }

    private func isBlocked(_ bundleID: String, in rows: [AppRow]) -> Bool {
        rows.contains { $0.id == AppsSync.key(bundleID) }
    }

    var body: some View {
        let rows = model.appRows
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.blockedAppsTitle)
                BodyText(mac ? PaxCopy.blockedAppsMacIntro(isPad: model.isPad) : PaxCopy.blockedAppsIntro(isPad: model.isPad))
                RowGroup {
                    if rows.isEmpty {
                        BodyText(PaxCopy.blockedAppsNone).padding(.vertical, 15)
                    } else {
                        ForEach(Array(rows.enumerated()), id: \.element.id) { i, a in
                            if i > 0 { RowDivider() }
                            appRow(a)
                        }
                    }
                }
                BodyText(mac ? PaxCopy.blockedAppsMacFooter : PaxCopy.blockedAppsFooter(serverHasList: model.appsServerList),
                         small: true)
                if mac && !p.phoneAppsAuthAsked && !model.authorized {
                    BodyText(PaxCopy.blockedAppsMacScreenTimeNote(isPad: model.isPad), small: true)
                }
                PaxCard {
                    TextField(PaxCopy.blockedAppsSearch, text: $search)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(PaxFont.body(17))
                        .padding(12)
                        .background(RoundedRectangle(cornerRadius: 12).fill(Palette.haze.opacity(0.35)))
                    Toggle(isOn: $alsoSites) {
                        Text(PaxCopy.blockedAppsAlsoSites)
                            .font(PaxFont.body(16, relativeTo: .callout)).foregroundStyle(Palette.ink)
                    }
                    .tint(Palette.accent)
                    ForEach(AppCatalog.search(search)) { a in catalogRow(a, rows: rows) }
                }
                PaxCard {
                    Text(PaxCopy.blockedAppsOtherTitle)
                        .font(PaxFont.body(17, weight: .semibold, relativeTo: .headline)).foregroundStyle(Palette.ink)
                    HStack(spacing: 10) {
                        TextField(PaxCopy.blockedAppsOtherPlaceholder, text: $other)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(.URL)
                            .font(PaxFont.body(17))
                            .padding(12)
                            .background(RoundedRectangle(cornerRadius: 12).fill(Palette.haze.opacity(0.35)))
                        Button(PaxCopy.blockedAppsAdd) {
                            let raw = other
                            Task {
                                problem = await model.blockAppEntry(raw, alsoSites: alsoSites)
                                if problem == nil { other = "" }
                            }
                        }
                        .font(PaxFont.body(17, weight: .semibold))
                        .foregroundStyle(Palette.accent)
                        .disabled(other.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
                if !mac { BodyText(PaxCopy.blockedAppsCategoryHint, small: true) }
                MessageText(text: problem ?? model.message)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .refreshable { await model.refreshApps() }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
        .onReceive(tick) { now = $0 }
        .onAppear {
            model.loadAppsCacheIfNeeded()          // the cached list, at once; no network here
            #if DEBUG
            if ScreenshotMode.apps { search = ScreenshotMode.appSearch }
            #endif
        }
        .confirmationDialog(PaxCopy.blockedAppsRemoveTitle(removing?.name ?? ""),
                            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
                            titleVisibility: .visible) {
            Button(PaxCopy.turnOffStart) {
                let id = removing?.bundleID ?? ""
                removing = nil
                Task { await model.requestAppRemoval(id) }
            }
            Button(PaxCopy.sitesKeep, role: .cancel) { removing = nil }
        } message: {
            Text(PaxCopy.sitesRemoveBody(waitDays: p.waitDays, trusted: p.hasTrustedPerson))
        }
    }

    private func catalogRow(_ a: CatalogApp, rows: [AppRow]) -> some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(a.name).font(PaxFont.body(17, weight: .medium)).foregroundStyle(Palette.ink)
                Text(a.domains.joined(separator: ", "))
                    .font(PaxFont.body(13, relativeTo: .caption)).foregroundStyle(Palette.body)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            if isBlocked(a.bundleID, in: rows) {
                Text(PaxCopy.blockedAppsAlreadyBlocked)
                    .font(PaxFont.body(15, weight: .medium)).foregroundStyle(Palette.good)
            } else {
                Button(PaxCopy.blockedAppsBlock) {
                    Task { problem = await model.blockApp(bundleID: a.bundleID, name: a.name,
                                                          domains: alsoSites ? a.domains : []) }
                }
                .font(PaxFont.body(15, weight: .semibold)).foregroundStyle(Palette.accent)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func appRow(_ a: AppRow) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(a.name).font(PaxFont.body(17, weight: .medium)).foregroundStyle(Palette.ink).lineLimit(1)
                if let src = a.source {
                    Text(PaxCopy.blockedAppsAdded(src, isPad: model.isPad))
                        .font(PaxFont.body(13, relativeTo: .caption)).foregroundStyle(Palette.body)
                }
                if let pr = a.pending {
                    let left = AppRemoval.remaining(pr, serverOffset: model.serverOffset, now: now)
                    Text(left > 60 ? PaxCopy.sitesRemoving(TurnOffRules.describe(remaining: left)) : PaxCopy.sitesRemovingSoon)
                        .font(PaxFont.body(14, relativeTo: .footnote)).foregroundStyle(Palette.caution)
                }
            }
            Spacer(minLength: 8)
            if a.pending != nil {
                Button(PaxCopy.sitesCancel) { Task { await model.cancelAppRemoval(a.bundleID) } }
                    .font(PaxFont.body(15, weight: .semibold)).foregroundStyle(Palette.accent)
            } else if a.macOnly {
                Text(PaxCopy.blockedAppsOnMac)
                    .font(PaxFont.body(14, relativeTo: .footnote)).foregroundStyle(Palette.body)
            } else if model.appsServerList && a.removable {
                Button(PaxCopy.sitesRemove) {
                    if model.signedIn { removing = a } else { model.message = PaxCopy.blockedAppsSignInFirst }
                }
                .font(PaxFont.body(15, weight: .medium)).foregroundStyle(Palette.accent)
            }
        }
        .padding(.vertical, 14)
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Encrypted DNS

struct DNSView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var guideShown = false
    private var p: PaxPolicy { model.policy }

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.dnsTitle)
                PaxCard {
                    if !p.dnsInstalled {
                        BodyText(PaxCopy.dnsBody)
                        Button(PaxCopy.dnsAdd) {
                            Task { if await model.installDNS(), model.dnsOn != true { guideShown = true } }
                        }
                        .buttonStyle(PaxPrimaryButton())
                    } else {
                        StatusRow(text: model.dnsOn == true ? PaxCopy.homeDNSOn : PaxCopy.homeDNSOff,
                                  symbol: model.dnsOn == true ? "checkmark.circle" : "exclamationmark.circle",
                                  good: model.dnsOn == true)
                        if model.dnsOn != true {
                            Button(PaxCopy.dnsShowSteps) { guideShown = true }.buttonStyle(PaxPrimaryButton())
                        }
                    }
                }
                BodyText(PaxCopy.dnsHonest(trusted: p.hasTrustedPerson), small: true)
                MessageText(text: model.message)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
        .sheet(isPresented: $guideShown) { DNSGuideView(isPad: model.isPad) }
    }
}

// MARK: - Set up from a computer ("Make Pax unremovable")

struct ComputerSetupView: View {
    let isPad: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var macShown = false

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.computerTitle)
                PaxCard {
                    Text(PaxCopy.computerSubtitle)
                        .font(PaxFont.body(16, weight: .semibold, relativeTo: .callout))
                        .foregroundStyle(Palette.accent)
                    BodyText(PaxCopy.computerBody(isPad: isPad))
                    Link(destination: Pax.computerSetupURL) { Text(PaxCopy.computerOpen) }
                        .buttonStyle(PaxPrimaryButton())
                    Button(PaxCopy.macLink) { macShown = true }.buttonStyle(PaxSecondaryButton())
                }
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
        .sheet(isPresented: $macShown) { MacSetupView(isPad: isPad) }
    }
}

// MARK: - Turn off Pax (the server decides; fail closed)

struct TurnOffView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmTurnOff = false
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()
    private var p: PaxPolicy { model.policy }
    private var mac: Bool { p.macSetUp && !p.isActive }

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.turnOffTitle)
                PaxCard {
                    if mac { BodyText(PaxCopy.macTurnOff(isPad: model.isPad)) } else { phaseContent }
                }
                MessageText(text: model.message)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
        .onReceive(tick) { now = $0 }
        .task { await model.refreshStatus() }
        .confirmationDialog(PaxCopy.turnOffConfirmTitle, isPresented: $confirmTurnOff, titleVisibility: .visible) {
            Button(PaxCopy.turnOffStart) { Task { await model.requestTurnOff() } }
            Button(PaxCopy.keepOn, role: .cancel) {}
        } message: {
            Text(PaxCopy.turnOffConfirmBody(trusted: p.hasTrustedPerson))
        }
    }

    @ViewBuilder private var phaseContent: some View {
        switch model.phase {
        case .none:
            BodyText(PaxCopy.turnOffIdle(trusted: p.hasTrustedPerson))
            Button(PaxCopy.turnOffAsk) { confirmTurnOff = true }.buttonStyle(PaxSecondaryButton())
        case .waiting(let until):
            let left = until.timeIntervalSince(now)
            if left > 0 {
                BodyText(PaxCopy.turnOffWaiting(TurnOffRules.describe(remaining: left)))
            } else {
                BodyText(PaxCopy.turnOffReady)
                Button(PaxCopy.turnOffNow) { Task { await model.refreshStatus() } }
                    .buttonStyle(PaxPrimaryButton())
            }
            Button(PaxCopy.keepOn) { Task { await model.cancelTurnOff() } }.buttonStyle(PaxSecondaryButton())
        case .ready:
            BodyText(PaxCopy.turnOffReady)
            Button(PaxCopy.turnOffNow) { Task { await model.confirmTurnOff() } }.buttonStyle(PaxPrimaryButton())
            Button(PaxCopy.keepOn) { Task { await model.cancelTurnOff() } }.buttonStyle(PaxSecondaryButton())
        case .unknown:
            BodyText(PaxCopy.turnOffUnknown)
            Button("Try again") { Task { await model.refreshStatus() } }.buttonStyle(PaxSecondaryButton())
        }
    }
}

/// Encrypted DNS: the steps to switch it on in Settings. Apple lets an app open only its own page
/// in Settings (UIApplication.openSettingsURLString), so the steps start there and say how to get
/// to General › VPN & Device Management › DNS on this iOS version. No private Settings URLs.
struct DNSGuideView: View {
    let isPad: Bool
    @Environment(\.dismiss) private var dismiss
    private var osMajor: Int { ProcessInfo.processInfo.operatingSystemVersion.majorVersion }

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.dnsGuideTitle)
                BodyText(PaxCopy.dnsGuideIntro(isPad: isPad))
                PaxCard {
                    ForEach(Array(PaxCopy.dnsGuideSteps(isPad: isPad, osMajor: osMajor).enumerated()), id: \.offset) { i, line in
                        HStack(alignment: .firstTextBaseline, spacing: 10) {
                            Text("\(i + 1).").font(PaxFont.body(17, weight: .semibold)).foregroundStyle(Palette.accent)
                            BodyText(line)
                        }
                    }
                }
                Button(PaxCopy.dnsOpenSettings) {
                    if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                }
                .buttonStyle(PaxPrimaryButton())
                Button(PaxCopy.dnsGuideClose) { dismiss() }.buttonStyle(PaxSecondaryButton())
            }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
    }
}

/// (a) Lock Screen Time: Pax makes up a passcode, escrows it on the server first, then shows
/// it (hold to see each digit) while it's typed into Settings, then forgets it.
struct LockScreenTimeView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var passcode: String?
    @State private var shownDigit: Int?

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.lockTitle)
                if let code = passcode {
                    PaxCard {
                        ForEach(Array(PaxCopy.passcodeSteps(isPad: model.isPad).enumerated()), id: \.offset) { i, line in
                            HStack(alignment: .firstTextBaseline, spacing: 10) {
                                Text("\(i + 1).").font(PaxFont.body(17, weight: .semibold)).foregroundStyle(Palette.accent)
                                BodyText(line)
                            }
                        }
                        HStack(spacing: 12) {
                            ForEach(0..<code.count, id: \.self) { i in
                                Text(shownDigit == i ? String(Array(code)[i]) : "•")
                                    .font(.system(size: 34, weight: .semibold, design: .rounded))
                                    .foregroundStyle(Palette.ink)
                                    .frame(width: 58, height: 66)
                                    .background(RoundedRectangle(cornerRadius: 14).fill(Palette.haze.opacity(0.45)))
                                    .onLongPressGesture(minimumDuration: 0.05, perform: {},
                                                        onPressingChanged: { pressing in shownDigit = pressing ? i : nil })
                                    .accessibilityLabel("Digit \(i + 1)")
                                    .accessibilityValue(shownDigit == i ? String(Array(code)[i]) : "hidden")
                            }
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                    }
                    BodyText(PaxCopy.passcodeAfter, small: true)
                    Button(PaxCopy.passcodeDone) {
                        passcode = nil          // wiped from memory
                        shownDigit = nil
                        model.passcodeSet()
                        dismiss()
                    }.buttonStyle(PaxPrimaryButton())
                } else {
                    BodyText(PaxCopy.lockBody)
                    BodyText(PaxCopy.lockIntro)
                    Button(PaxCopy.lockMake) {
                        Task { passcode = await model.preparePasscode() }
                    }.buttonStyle(PaxPrimaryButton())
                    Button(PaxCopy.passcodeLater) { dismiss() }.buttonStyle(PaxSecondaryButton())
                }
                MessageText(text: model.message)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
        }
        .navigationViewStyle(.stack)
        .interactiveDismissDisabled(passcode != nil)
    }
}

/// (b) Someone you trust: their email, and your first name for their emails (`from_name`).
struct TrustedPersonView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var email = ""
    @State private var name = ""
    @State private var problem: String?

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.trustedTitle)
                BodyText(PaxCopy.trustedBody)
                if model.policy.hasTrustedPerson {
                    StatusRow(text: PaxCopy.homeTrusted(model.policy.trustedEmail), symbol: "person.2", good: true)
                    BodyText(PaxCopy.trustedChangeNote, small: true)
                }
                PaxTextField(placeholder: PaxCopy.trustedEmailPlaceholder, text: $email, email: true)
                PaxTextField(placeholder: PaxCopy.trustedNamePlaceholder, text: $name)
                BodyText(PaxCopy.trustedNameHint, small: true)
                BodyText(PaxCopy.trustedWitness, small: true)
                MessageText(text: problem ?? model.message)
                Button(PaxCopy.trustedSave) {
                    problem = SetupRules.trustedProblem(email, account: model.policy.accountEmail)
                        ?? SetupRules.nameProblem(name)
                    guard problem == nil else { return }
                    Task { if await model.addTrusted(email: email, name: name) { dismiss() } }
                }
                .buttonStyle(PaxPrimaryButton())
                .disabled(email.isEmpty)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
            .onAppear { name = model.policy.displayName ?? "" }
        }
        .navigationViewStyle(.stack)
    }
}

/// (e) Change turn-off wait. Longer is instant; shorter comes in after the current wait and
/// the person you trust is told first (the server's rule).
struct WaitChangeView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var days = Pax.defaultWaitDays
    @State private var confirmShorter = false

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.waitTitle)
                BodyText(PaxCopy.waitBody(currentDays: model.policy.waitDays))
                PaxCard {
                    ForEach(SetupRules.waitChoices(child: model.policy.audience == .child), id: \.self) { d in
                        Button { days = d } label: {
                            HStack {
                                Text(TurnOffRules.waitLabel(days: d))
                                    .font(PaxFont.body(18, weight: days == d ? .semibold : .regular))
                                    .foregroundStyle(Palette.ink)
                                Spacer()
                                if days == d { Image(systemName: "checkmark").foregroundStyle(Palette.accent) }
                            }
                            .contentShape(Rectangle())
                            .padding(.vertical, 6)
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(days == d ? .isSelected : [])
                    }
                }
                MessageText(text: model.message)
                Button(PaxCopy.waitSave) {
                    switch WaitChange.of(currentDays: model.policy.waitDays, newDays: days) {
                    case .same: dismiss()
                    case .longerNow: Task { if await model.changeWait(days: days) != .same { dismiss() } }
                    case .shorterAfterWait: confirmShorter = true
                    }
                }.buttonStyle(PaxPrimaryButton())
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
            .onAppear { days = model.policy.waitDays }
            .confirmationDialog(PaxCopy.waitShorterTitle, isPresented: $confirmShorter, titleVisibility: .visible) {
                Button(PaxCopy.waitShorterConfirm) {
                    Task { if await model.changeWait(days: days) != .same { dismiss() } }
                }
                Button(PaxCopy.keepOn, role: .cancel) {}
            } message: {
                Text(PaxCopy.waitShorterBody(currentDays: model.policy.waitDays))
            }
        }
        .navigationViewStyle(.stack)
    }
}

/// Account: privacy, support, and deleting the account (needed for App Review).
struct AccountView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var confirmDelete = false
    @State private var result: String?
    @State private var stillOn: [AccountDeletion.StillOn]?

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.accountTitle)
                if let e = model.policy.accountEmail, !e.isEmpty {
                    BodyText(e)
                }
                PaxCard {
                    Link(PaxCopy.privacy, destination: Pax.privacyURL)
                    Link(PaxCopy.support, destination: URL(string: "mailto:\(Pax.supportEmail)")!)
                }
                .font(PaxFont.body(17, weight: .medium))
                .foregroundStyle(Palette.accent)
                PaxCard {
                    Text(PaxCopy.deleteTitle).font(PaxFont.heading(22, relativeTo: .title3)).foregroundStyle(Palette.ink)
                    BodyText(PaxCopy.deleteBody(isActive: model.policy.isActive))
                    Button(PaxCopy.deleteConfirm, role: .destructive) { confirmDelete = true }
                        .buttonStyle(PaxSecondaryButton())
                    if let r = result { BodyText(r, small: true) }
                }
                MessageText(text: model.message)
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .confirmationDialog(PaxCopy.deleteTitle, isPresented: $confirmDelete, titleVisibility: .visible) {
                Button(PaxCopy.deleteConfirm, role: .destructive) {
                    Task {
                        switch await model.deleteAccount() {
                        case .deleted: result = PaxCopy.deleteDone
                        case .emailRequest(let url):
                            result = PaxCopy.deleteRequested
                            openURL(url)
                        case .stillProtected(let devices):
                            result = nil
                            stillOn = devices
                        case .failed: break
                        }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(PaxCopy.deleteBody(isActive: model.policy.isActive))
            }
        }
        .navigationViewStyle(.stack)
        .sheet(isPresented: Binding(get: { stillOn != nil }, set: { if !$0 { stillOn = nil } })) {
            StillProtectedView(devices: stillOn ?? []) { stillOn = nil }
        }
    }
}

/// The server refused to delete the account because Pax is still on one or more devices
/// (409 devices_still_protected). Nothing was deleted; turn Pax off first, wait included.
struct StillProtectedView: View {
    let devices: [AccountDeletion.StillOn]
    var onDone: () -> Void

    var body: some View {
        PaxPage {
            SectionTitle(PaxCopy.deleteStillOnTitle)
            BodyText(PaxCopy.deleteStillOnBody(count: max(devices.count, 1)))
            if !devices.isEmpty {
                PaxCard {
                    ForEach(Array(devices.enumerated()), id: \.offset) { _, d in
                        HStack(alignment: .firstTextBaseline, spacing: 12) {
                            Image(systemName: d.kind == "Mac" ? "laptopcomputer"
                                  : d.kind == "iPad" ? "ipad" : "iphone")
                                .foregroundStyle(Palette.accent)
                                .frame(width: 22)
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(d.name)
                                    .font(PaxFont.body(17, weight: .medium, relativeTo: .body))
                                    .foregroundStyle(Palette.ink)
                                Text("\(d.kind) · \(PaxCopy.deleteStillOnReason(d.reason, checkingIn: d.checkingIn))")
                                    .font(PaxFont.body(15, relativeTo: .footnote))
                                    .foregroundStyle(Palette.body)
                            }
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
            }
            BodyText(PaxCopy.deleteStillOnHowTo)
            BodyText(PaxCopy.deleteStillOnNothingChanged, small: true)
            Button(PaxCopy.doneButton, action: onDone).buttonStyle(PaxPrimaryButton())
        }
    }
}
