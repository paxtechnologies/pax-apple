// SPDX-License-Identifier: GPL-3.0-only
// Home: what's on, the note about setting up from a Mac, your blocked sites, turning
// off (server wait, trusted person emailed first, fail closed), honest limits, account.
import SwiftUI
import UIKit
import FamilyControls

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    @State private var newSite = ""
    @State private var confirmTurnOff = false
    @State private var accountShown = false
    @State private var pickerShown = false
    @State private var moreApps = FamilyActivitySelection()
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    private var isPad: Bool { model.isPad }
    private var p: PaxPolicy { model.policy }

    var body: some View {
        PaxPage {
            HStack {
                PaxLogo(height: 54)
                Spacer()
                Button { accountShown = true } label: {
                    Image(systemName: "person.crop.circle").font(.system(size: 26))
                }
                .foregroundStyle(Palette.accent)
                .accessibilityLabel(PaxCopy.accountTitle)
            }
            status
            MacNoteCard(isPad: isPad)
            sites
            turnOff
            limits
            MessageText(text: model.message)
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
    }

    private var status: some View {
        PaxCard {
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
            if !p.dnsInstalled {
                StatusRow(text: PaxCopy.homeDNSNotAdded, symbol: "exclamationmark.circle", good: false)
                Button(PaxCopy.dnsAdd) { Task { _ = await model.installDNS() } }
                    .buttonStyle(PaxSecondaryButton())
            } else if model.dnsOn == true {
                StatusRow(text: PaxCopy.homeDNSOn, symbol: "checkmark.circle")
            } else {
                StatusRow(text: PaxCopy.homeDNSOff, symbol: "exclamationmark.circle", good: false)
            }
            StatusRow(text: PaxCopy.homeTrusted(p.trustedEmail), symbol: "person.2", good: true)
            StatusRow(text: PaxCopy.homeWait(p.waitDays), symbol: "hourglass", good: true)
            if model.inGrace { BodyText(PaxCopy.homeGrace, small: true) }
        }
    }

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
            ForEach(p.blockedDomains, id: \.self) { d in
                Text(d).font(PaxFont.body(16)).foregroundStyle(Palette.body)
            }
            BodyText(PaxCopy.sitesFooter, small: true)
            Button(PaxCopy.appsChoose) { pickerShown = true }.buttonStyle(PaxSecondaryButton())
        }
    }

    private var turnOff: some View {
        PaxCard {
            Text(PaxCopy.turnOffTitle).font(PaxFont.heading(22, relativeTo: .title3)).foregroundStyle(Palette.ink)
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

    private var limits: some View {
        PaxCard {
            Text(PaxCopy.limitsTitle)
                .font(PaxFont.body(15, weight: .semibold, relativeTo: .subheadline))
                .foregroundStyle(Palette.accent)
            BulletList(lines: PaxCopy.limits(isPad: isPad, passcode: p.passcodeEscrowed))
        }
    }
}

/// Account: privacy, support, and deleting the account (needed for App Review).
struct AccountView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var confirmDelete = false
    @State private var result: String?

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.accountTitle)
                if let e = model.policy.accountEmail { BodyText(e) }
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
    }
}
