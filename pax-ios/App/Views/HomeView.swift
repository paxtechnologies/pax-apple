// SPDX-License-Identifier: GPL-3.0-only
// Home: what's on, then "Make Pax stronger" (optional cards in a fixed order: Lock Screen
// Time, someone you trust, encrypted DNS, apps to keep closed, turn-off wait, set up from a
// computer), your blocked sites (removing one takes the turn-off wait on the server), turning
// off (server wait, the person you trust emailed first, fail closed), account. 1.2: no "Good to
// know" section, and a device set up from a Mac shows that set-up and only adds to it.
import SwiftUI
import UIKit
import FamilyControls

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    @State private var newSite = ""
    @State private var confirmTurnOff = false
    @State private var accountShown = false
    @State private var pickerShown = false
    @State private var lockShown = false
    @State private var trustedShown = false
    @State private var waitShown = false
    @State private var macShown = false
    @State private var signInShown = false
    @State private var moreApps = FamilyActivitySelection()
    @State private var dnsGuideShown = false
    @State private var removing: String?
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    private var isPad: Bool { model.isPad }
    private var p: PaxPolicy { model.policy }
    /// Set up from a Mac and joined by this app (StrictSync): show it, add to it, nothing else.
    private var mac: Bool { p.macSetUp && !p.isActive }

    private var scrollTarget: String? {
        #if DEBUG
        return ScreenshotMode.scroll
        #else
        return nil
        #endif
    }

    var body: some View {
        PaxPage(scrollTo: scrollTarget) {
            HStack {
                PaxLogo(height: 54)
                Spacer()
                Button { accountShown = true } label: {
                    Image(systemName: "person.crop.circle").font(.system(size: 26))
                }
                .foregroundStyle(Palette.accent)
                .accessibilityLabel(PaxCopy.accountTitle)
            }
            if !model.signedIn { signInAgain }
            status
            stronger
            sites.id("sites")
            turnOff
            MessageText(text: model.message)
            Color.clear.frame(height: 1).id("end")
        }
        .refreshable { await model.onActive() }
        .onReceive(tick) { now = $0 }
        .familyActivityPicker(isPresented: $pickerShown, selection: $moreApps)
        .onChange(of: pickerShown) { shown in
            if !shown { model.addApps(moreApps); moreApps = FamilyActivitySelection() }
        }
        .confirmationDialog(PaxCopy.turnOffConfirmTitle, isPresented: $confirmTurnOff, titleVisibility: .visible) {
            Button(PaxCopy.turnOffStart) { Task { await model.requestTurnOff() } }
            Button(PaxCopy.keepOn, role: .cancel) {}
        } message: {
            Text(PaxCopy.turnOffConfirmBody(trusted: p.hasTrustedPerson))
        }
        .sheet(isPresented: $accountShown) { AccountView().environmentObject(model) }
        .sheet(isPresented: $lockShown) { LockScreenTimeView().environmentObject(model) }
        .sheet(isPresented: $trustedShown) { TrustedPersonView().environmentObject(model) }
        .sheet(isPresented: $waitShown) { WaitChangeView().environmentObject(model) }
        .sheet(isPresented: $macShown) { MacSetupView(isPad: isPad) }
        .sheet(isPresented: $signInShown) { SignInAgainView().environmentObject(model) }
        .sheet(isPresented: $dnsGuideShown) { DNSGuideView(isPad: isPad) }
        .onAppear {
            #if DEBUG
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

    private var status: some View {
        PaxCard {
            if mac {
                Text(PaxCopy.homeOn)
                    .font(PaxFont.heading(28, relativeTo: .title)).foregroundStyle(Palette.ink)
                StatusRow(text: PaxCopy.homeMacSetUp, symbol: "laptopcomputer", good: true)
                StatusRow(text: PaxCopy.homeFilter, symbol: "checkmark.shield")
                if model.filteredHere != false {
                    StatusRow(text: PaxCopy.homeMacFilter, symbol: "lock", good: true)
                }
                StatusRow(text: PaxCopy.homeWait(p.waitDays), symbol: "hourglass", good: true)
            } else {
                appStatus
            }
        }
    }

    @ViewBuilder private var appStatus: some View {
            if model.accessLost {
                Text(PaxCopy.homeAccessLost)
                    .font(PaxFont.heading(26, relativeTo: .title2)).foregroundStyle(Palette.caution)
                BodyText(PaxCopy.homeAccessLostBody(isPad: isPad, trusted: p.hasTrustedPerson))
            } else {
                Text(PaxCopy.homeOn)
                    .font(PaxFont.heading(28, relativeTo: .title)).foregroundStyle(Palette.ink)
                StatusRow(text: PaxCopy.homeFilter, symbol: "checkmark.shield")
                StatusRow(text: PaxCopy.homeDelete, symbol: "lock")
            }
            StatusRow(text: p.passcodeEscrowed ? PaxCopy.homePasscodeKept : PaxCopy.homeNoPasscode,
                      symbol: p.passcodeEscrowed ? "key" : "exclamationmark.circle", good: p.passcodeEscrowed)
            StatusRow(text: PaxCopy.homeWait(p.waitDays), symbol: "hourglass", good: true)
    }

    // MARK: Make Pax stronger

    private var stronger: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(PaxCopy.strongerTitle)
                .font(PaxFont.heading(24, relativeTo: .title2)).foregroundStyle(Palette.ink)
                .accessibilityAddTraits(.isHeader)
            if !mac {
                let prog = StrongerList.progress(p, hasApps: model.hasApps)
                BodyText(PaxCopy.strongerProgress(done: prog.done, total: prog.total), small: true)
            }
            ForEach(StrongerList.cards(macSetUp: mac), id: \.self) { card in
                strongerCard(card)
            }
        }
    }

    @ViewBuilder private func strongerCard(_ card: StrongerCard) -> some View {
        let done = card.isDone(p, hasApps: model.hasApps)
        switch card {
        case .lockScreenTime:
            StrongerCardView(title: PaxCopy.lockTitle, symbol: "key", done: done,
                             recommended: StrongerList.nudge(p)) {
                if done {
                    BodyText(PaxCopy.lockDone, small: true)
                } else {
                    BodyText(PaxCopy.lockBody)
                    Button(PaxCopy.lockButton) { lockShown = true }.buttonStyle(PaxPrimaryButton())
                }
            }
        case .trustedPerson:
            StrongerCardView(title: PaxCopy.trustedTitle, symbol: "person.2", done: done) {
                if done {
                    StatusRow(text: PaxCopy.homeTrusted(p.trustedEmail), symbol: "person.2", good: true)
                    if let pending = model.account?.pending_partner_email {
                        BodyText(PaxCopy.trustedPending(pending), small: true)
                    }
                    Button(PaxCopy.trustedChange) { trustedShown = true }.buttonStyle(PaxSecondaryButton())
                } else {
                    BodyText(PaxCopy.trustedBody)
                    Button(PaxCopy.trustedTitle) { trustedShown = true }.buttonStyle(PaxSecondaryButton())
                }
            }
        case .encryptedDNS:
            StrongerCardView(title: PaxCopy.dnsTitle, symbol: "network", done: done) {
                if !p.dnsInstalled {
                    BodyText(PaxCopy.dnsBody)
                    BodyText(PaxCopy.dnsHonest(trusted: p.hasTrustedPerson), small: true)
                    Button(PaxCopy.dnsAdd) {
                        Task { if await model.installDNS(), model.dnsOn != true { dnsGuideShown = true } }
                    }
                    .buttonStyle(PaxSecondaryButton())
                } else {
                    StatusRow(text: model.dnsOn == true ? PaxCopy.homeDNSOn : PaxCopy.homeDNSOff,
                              symbol: model.dnsOn == true ? "checkmark.circle" : "exclamationmark.circle",
                              good: model.dnsOn == true)
                    if model.dnsOn != true {
                        Button(PaxCopy.dnsShowSteps) { dnsGuideShown = true }.buttonStyle(PaxSecondaryButton())
                    }
                }
            }
        case .appsToClose:
            StrongerCardView(title: PaxCopy.appsTitle, symbol: "app.badge", done: done) {
                BodyText(PaxCopy.appsBody)
                BodyText(PaxCopy.appsChosen(model.selection.applicationTokens.count
                                            + model.selection.webDomainTokens.count
                                            + model.selection.categoryTokens.count), small: true)
                Button(PaxCopy.appsChoose) { pickerShown = true }.buttonStyle(PaxSecondaryButton())
            }
        case .turnOffWait:
            StrongerCardView(title: PaxCopy.waitTitle, symbol: "hourglass", done: false) {
                BodyText(PaxCopy.waitBody(currentDays: p.waitDays))
                if let line = pendingWaitLine { BodyText(line, small: true) }
                Button(PaxCopy.waitTitle) { waitShown = true }.buttonStyle(PaxSecondaryButton())
            }
        case .computerSetup:
            StrongerCardView(title: PaxCopy.computerTitle, symbol: "laptopcomputer", done: false) {
                Text(PaxCopy.computerSubtitle)
                    .font(PaxFont.body(16, weight: .semibold, relativeTo: .callout))
                    .foregroundStyle(Palette.accent)
                BodyText(PaxCopy.computerBody(isPad: isPad))
                Link(destination: Pax.computerSetupURL) { Text(PaxCopy.computerOpen) }
                    .buttonStyle(PaxSecondaryButton())
                Button(PaxCopy.macLink) { macShown = true }
                    .font(PaxFont.body(16, weight: .medium, relativeTo: .callout))
                    .foregroundStyle(Palette.accent)
            }
        }
    }

    private var pendingWaitLine: String? {
        guard let s = model.account?.pending_wait_seconds, let at = model.account?.pending_wait_effective_at else { return nil }
        let date = Date(timeIntervalSince1970: at).formatted(date: .abbreviated, time: .shortened)
        return PaxCopy.waitPending(days: TurnOffRules.days(fromSeconds: s), on: date)
    }

    // MARK: sites, turning off, limits

    private var sites: some View {
        PaxCard {
            Text(PaxCopy.sitesTitle).font(PaxFont.heading(22, relativeTo: .title3)).foregroundStyle(Palette.ink)
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
            BodyText(PaxCopy.sitesFooter, small: true)
        }
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

    /// One of your own sites: Remove (starts the turn-off wait on the server), or, while it
    /// waits, "Removing, available in …" with Cancel. It comes off only after the wait.
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

    private var turnOff: some View {
        PaxCard {
            Text(PaxCopy.turnOffTitle).font(PaxFont.heading(22, relativeTo: .title3)).foregroundStyle(Palette.ink)
            if mac {
                BodyText(PaxCopy.macTurnOff(isPad: isPad))
            } else {
                appTurnOff
            }
        }
    }

    @ViewBuilder private var appTurnOff: some View {
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

/// One "Make Pax stronger" card: a title with a symbol, a "Recommended" or "Done" tag, content.
struct StrongerCardView<Content: View>: View {
    let title: String
    let symbol: String
    let done: Bool
    var recommended = false
    @ViewBuilder var content: Content

    var body: some View {
        PaxCard {
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Image(systemName: done ? "checkmark.circle.fill" : symbol)
                    .foregroundStyle(done ? Palette.good : Palette.accent)
                    .frame(width: 24)
                    .accessibilityHidden(true)
                Text(title)
                    .font(PaxFont.body(19, weight: .semibold, relativeTo: .title3))
                    .foregroundStyle(Palette.ink)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                if done || recommended {
                    Text(done ? PaxCopy.doneTag : PaxCopy.recommended)
                        .font(PaxFont.body(13, weight: .semibold, relativeTo: .caption))
                        .foregroundStyle(done ? Palette.good : Palette.buttonText)
                        .padding(.horizontal, 10).padding(.vertical, 4)
                        .background(Capsule().fill(done ? Palette.good.opacity(0.15) : Palette.accent))
                }
            }
            .accessibilityElement(children: .combine)
            content
        }
        .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous)
            .stroke(recommended && !done ? Palette.accent : Color.clear, lineWidth: 2))
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
