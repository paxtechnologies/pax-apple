// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

/// v0.8.14: the one Settings screen, in the main window (sidebar › Settings, or
/// Pax › Settings… ⌘,). App-wide things only; a device's own details and switches are
/// on its page. Rare options sit under a closed "Advanced". Before 0.8.14 this was a
/// separate window with tabs, next to a per-device "Settings" screen.
struct AppSettingsView: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel
    @State private var showAdvanced = false
    @State private var showPaxMax = false              // v0.8.23: folded like Advanced, closed by default

    var body: some View {
        PageColumn(maxWidth: 680) {
            // v0.8.21: no Home row in the sidebar any more, so Settings has its own way back.
            BackLink(title: AppNav.backToHome) { model.screen = .home }
            StepHeader(eyebrow: "", title: "Settings", subtitle: AppSettingsLayout.subtitle)
            if let failure = mac.failure {
                ErrorCard(error: failure, retry: { mac.refresh() }, details: { mac.supportDetails(failure) })
            }
            // v0.8.23 (Ruben: "only keep what is necessary"): each card is a title and its state;
            // explanations and rare actions are under "Details". Order: AppSettingsLayout.sections.
            if mac.deviceID != nil { Card { BlockingSettings() } }
            Card { TurningOffSettings() }                      // v0.8.16 turn-off wait; v0.8.18 trial, support release
            Card { PartnerEmailSettings() }
            Card { UpdateSettings() }                          // v0.8.23: About folded inside
            Card {                                             // v0.8.12; v0.8.23 folded, off by default
                DisclosureGroup(isExpanded: $showPaxMax) {
                    PaxMaxSettings().padding(.top, 12)
                } label: {
                    FoldedLabel(title: AppSettingsLayout.paxMax,
                                state: PaxMax.stateLabel(on: mac.paxMaxView?.on ?? mac.paxMax,
                                                         pending: mac.paxMaxView?.pending != nil),
                                line: PaxMax.summary)
                }
            }
            .onAppear { mac.refreshPaxMax() }
            Card {
                DisclosureGroup(isExpanded: $showAdvanced) {
                    VStack(alignment: .leading, spacing: 18) {
                        if mac.deviceID != nil {
                            MacDetailsSettings()               // v0.8.18: filter, security notices
                            Divider().overlay(Theme.border)
                        }
                        MacKeySettings()
                        Divider().overlay(Theme.border)
                        ServerSettingsView(current: model.coordinator.escrow.baseURL)
                        Divider().overlay(Theme.border)
                        VStack(alignment: .leading, spacing: 6) {
                            Text("For testers").font(Theme.body(13, weight: .semibold))
                                .foregroundStyle(Theme.primaryText)
                            Text("Error codes and what they mean are listed in docs/ERROR_CODES.md. "
                                 + "\"Copy details\" on any error copies what support needs, with no personal data.")
                                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(.top, 12)
                } label: {
                    Text(AppSettingsLayout.advanced).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
                }
            }
        }
    }
}

/// v0.8.23: the label of a folded card: title, its state on the right, one muted line.
private struct FoldedLabel: View {
    let title: String
    let state: String
    let line: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
                Spacer(minLength: 8)
                Text(state).font(Theme.body(13, weight: .medium)).foregroundStyle(Theme.mutedText)
            }
            Text(line).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }
}

/// v0.8.23: a card's own "Details" disclosure (closed): its explanations and rare actions.
private struct DetailsDisclosure<Content: View>: View {
    let title: String
    let content: Content
    @State private var open = false

    init(title: String = AppSettingsLayout.details, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        DisclosureGroup(isExpanded: $open) {
            VStack(alignment: .leading, spacing: 8) { content }
                .padding(.top, 6)
                .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(title).font(Theme.body(13, weight: .medium)).foregroundStyle(Theme.mutedText)
        }
    }
}

/// A small muted explanation line inside Details.
private struct DetailText: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// v0.8.23: About is folded inside the Updates card (was its own card).
private struct AboutDetails: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            PaxWordmark(size: 28)
            Text(Brand.tagline).font(Theme.heading(17)).foregroundStyle(Theme.primaryText)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Brand.principles, id: \.self) { p in
                    NoteRow(icon: "leaf", text: p)
                }
            }
            DetailText("Free and open source under the GPL-3.0. Your settings stay with you and the server you choose.")
            Link(Brand.site, destination: Brand.siteURL).font(Theme.body(13))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}


/// v0.8.18 Settings › Blocking: this Mac's live switches (they were on Home's "This Mac"
/// card). v0.8.23: just the switches; what each one does is under Details.
private struct BlockingSettings: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(AppSettingsLayout.blocking).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            switch mac.adblockSwitch {
            case .guardLive, .server:
                ToggleRow(title: "Ads and trackers", detail: nil,
                          isOn: Binding(get: { mac.adblock }, set: { mac.setAdblock($0) }))
            case .setUpOnly:
                NoteRow(icon: "hand.raised",
                        text: "Ads and trackers: \(mac.adblock ? "blocked" : "allowed"), as chosen at set-up. "
                            + "The switch works here once Pax has finished updating.")
            }
            if mac.canSync && mac.sync != nil {
                ToggleRow(title: "Sync blocked sites across devices", detail: nil,
                          isOn: Binding(get: { mac.sync?.enabled ?? true }, set: { mac.setSyncEnabled($0) }))
            }
            if mac.youtubeAvailable {
                ToggleRow(title: "YouTube Restricted Mode", detail: nil,
                          isOn: Binding(get: { mac.youtubeRestricted }, set: { mac.setYouTubeRestricted($0) }))
            }
            DetailsDisclosure {
                if mac.adblockSwitch != .setUpOnly {
                    DetailText("Ads and trackers: " + (mac.adblockSwitch == .guardLive ? AppSettingsLayout.Line.adsLive
                                                                                       : AppSettingsLayout.Line.adsServer))
                }
                if mac.canSync && mac.sync != nil {
                    DetailText("Sync: " + AppSettingsLayout.Line.sync + " " + ListSyncLinker.detail(mac.sync))
                }
                if mac.youtubeAvailable {
                    DetailText("YouTube: " + AppSettingsLayout.Line.youtube)
                }
                DetailText(AlwaysBlockedMedia.notice)      // v0.8.13: no switch
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// v0.8.18 Settings › Turning Pax off: the turn-off wait, the trial day, and "Allow verified
/// support release" (was Home's Details card). v0.8.23: the rules are under Details.
/// v0.8.27: this Mac's Support ID (moved from Advanced), shown only with the switch on.
private struct TurningOffSettings: View {
    @EnvironmentObject var mac: MacProtectModel
    @State private var confirmEndTrial = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(AppSettingsLayout.turningOff).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            if let w = mac.status?.wait_seconds {
                TurnOffWaitRow(seconds: w)
            }
            if let line = TrialDay.settingsLine(mac.status?.trial) {
                NoteRow(icon: "sun.max", text: line)
                if mac.trialActive {
                    Button(TrialDay.startWaitButton) { confirmEndTrial = true }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(mac.busy)
                }
            }
            if let sr = mac.status?.support_release {
                SupportReleaseRow(state: sr, busy: mac.busy, trialActive: mac.trialActive) { mac.setSupportRelease($0) }
            }
            // v0.8.27: the Support ID sits here, next to the switch (was under Advanced). Only with
            // verified support release on, and never once this Mac is turned off.
            if let id = SupportIDPlacement.visibleID(mac.status, turnedOff: mac.phase == .released || mac.phase == .removed) {
                SupportIDRow(supportID: id)
            }
            DetailsDisclosure {
                DetailText(AppSettingsLayout.Line.turnOffWait + " Each iPhone or iPad shows its own on its page.")
                if let s = mac.status, s.support_id != nil || s.support_release != nil {
                    DetailText(VerifiedSupportRelease.title + ": " + AppSettingsLayout.Line.supportRelease)
                    DetailText(AppSettingsLayout.Line.supportReleaseRule)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .alert(TrialDay.confirmTitle, isPresented: $confirmEndTrial) {
            Button(TrialDay.startWaitButton, role: .destructive) { mac.endTrial() }
            Button("Not now", role: .cancel) {}
        } message: {
            Text(TrialDay.confirmMessage)
        }
    }
}

/// v0.8.18 Settings › Advanced: which filter is answering, and the security notices (were on
/// Home). v0.8.27: the Support ID moved to Settings › Turning Pax off.
private struct MacDetailsSettings: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("This Mac's details").font(Theme.heading(17)).foregroundStyle(Theme.primaryText)
            NoteRow(icon: "shield", text: FilterStatusText.line(mac.guardStatus?.dns))
            // v0.8.18: which filter answers, and the backup's reason when it's on.
            if let dns = mac.guardStatus?.dns, dns.filter_mode != nil {
                DetailRow(label: "Filter", value: FilterModeText.label(dns.filter_mode))
                if let line = FilterModeText.fallbackLine(dns) {
                    Text(line).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            // v0.8.19: the filter lists in use (signed filter packs, checked every 6 hours).
            if let v = FilterPackText.value(mac.guardStatus?.filter_pack) {
                DetailRow(label: "Filter lists", value: v)
                if let line = FilterPackText.lastCheck(mac.guardStatus?.filter_pack) {
                    Text(line).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            FamilyLayerSettings()
            // v0.8.23: brief backup-filter episodes (e.g. after an update) aren't shown; no raw codes.
            let notices = SecurityNotices.visible(mac.guardStatus?.tamper?.recent ?? [])
            if !notices.isEmpty {
                Text("Security notices").font(Theme.body(13, weight: .semibold)).foregroundStyle(Theme.primaryText)
                Text(AppSettingsLayout.Line.securityNotices).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                ForEach(Array(notices.suffix(5).reversed().enumerated()), id: \.offset) { _, n in
                    NoteRow(icon: "exclamationmark.shield", text: n.text)
                }
            }
        }
    }
}

/// v0.8.18 Settings › Advanced: "Extra family filter layer" (off by default). On is
/// instant; off waits like a removal (partner first, then the turn-off wait), cancellable.
private struct FamilyLayerSettings: View {
    @EnvironmentObject var mac: MacProtectModel
    @State private var confirmOff = false

    var body: some View {
        if let on = mac.familyLayer {
            VStack(alignment: .leading, spacing: 8) {
                if mac.familyLayerLocal == false {
                    NoteRow(icon: "shield.lefthalf.filled",
                            text: "\(AppSettingsLayout.familyLayerTitle): \(on ? "on" : "off"). "
                                + "It's kept in your Pax account for this Mac.")
                } else {
                    ToggleRow(title: AppSettingsLayout.familyLayerTitle,
                              detail: AppSettingsLayout.Line.familyLayer,
                              isOn: Binding(get: { on && mac.familyLayerPending == nil },
                                            set: { want in
                                                if want { mac.setFamilyLayer(true) }
                                                else if mac.familyLayerPending == nil { confirmOff = true }
                                            }))
                    .disabled(mac.busy)
                    Text(AppSettingsLayout.Line.familyLayerRule)
                        .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    if let p = mac.familyLayerPending {
                        TimelineView(.periodic(from: .now, by: 60)) { ctx in
                            let left = max(0, p.effective_at - Int(ctx.date.timeIntervalSince1970))
                            Text(p.status == "notifying"
                                 ? "Pax is telling your trusted person first. The wait starts once they're told."
                                 : "Turns off in \(TurnOffWait.countdown(seconds: left)).")
                                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                        }
                        Button("I've changed my mind") { mac.cancelFamilyLayerOff() }
                            .buttonStyle(SecondaryButtonStyle())
                            .disabled(mac.busy)
                    }
                }
                if let n = mac.familyLayerNotice {
                    NoteRow(icon: "checkmark.circle", text: n)
                }
            }
            .alert("Turn off the extra family filter layer?", isPresented: $confirmOff) {
                Button("Start my wait") { mac.setFamilyLayer(false) }
                Button("Keep it on", role: .cancel) {}
            } message: {
                Text(AppSettingsLayout.Line.familyLayerRule)
            }
        }
    }
}

/// v0.8.0: where this Mac keeps the key that undoes Pax. Local is the default;
/// the server path stays for anyone who wants it (iPhones always use a server).
private struct MacKeySettings: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Where this Mac keeps its key").font(Theme.heading(17)).foregroundStyle(Theme.primaryText)
            Picker("", selection: Binding(get: { mac.escrowMode }, set: { mac.escrowMode = $0 })) {
                Text("On this Mac (recommended)").tag(MacEscrowMode.local)
                Text("On a Pax server").tag(MacEscrowMode.server)
            }
            .pickerStyle(.radioGroup)
            .disabled(mac.deviceID != nil)
            Text(mac.escrowMode == .local
                 ? "Pax's background protection keeps the key in a safe only it can open, and hands it over "
                   + "after your turn-off wait. No server, no account."
                 : "The Pax server below keeps the key and releases it after your turn-off wait.")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            if mac.deviceID != nil {
                Text("This Mac is protected, so this can't change until Pax is removed.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            }
            Text("iPhones and iPads always keep their key on a Pax server.")
                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
        }
    }
}

/// v0.8.0: updates can't be switched off; this shows the version and last check.
/// v0.8.23: one line (version · last check) and Update now; About is folded in here.
private struct UpdateSettings: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(AppSettingsLayout.updates).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                Text(versionLine).font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Button("Update now") { mac.updateNow() }
                    .buttonStyle(SecondaryButtonStyle())
                    .disabled(mac.busy || mac.deviceID == nil)
            }
            DetailsDisclosure(title: AppSettingsLayout.about) {
                DetailText("Pax installs updates by itself, signed and checked, so a fix reaches you quickly.")
                AboutDetails()
            }
        }
        .onAppear { if mac.deviceID != nil { mac.refresh() } }
    }

    private var versionLine: String {
        var line = "Version \(Brand.version)"
        if let u = mac.guardStatus?.update {
            line += " · " + (u.last_checked.map {
                "last checked " + Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated,
                                                                                         time: .shortened)
            } ?? "not checked yet")
        }
        return line
    }
}

/// v0.8.0: how pax-guard emails your trusted person on local escrow.
/// v0.8.12 Pax Max after set-up (project decision). On: instant, any time. Off: a
/// loosening, so your trusted person is told first (if that fails, nothing starts),
/// then a fixed hour, cancellable; pax-guard logs it and refuses it offline.
private struct PaxMaxSettings: View {
    @EnvironmentObject var mac: MacProtectModel
    @State private var confirmOn = false
    @State private var confirmOff = false

    private var pm: GuardClient.PaxMaxView? { mac.paxMaxView }
    private var switchable: Bool { pm?.switchable == true && pm?.on != nil }
    private var isOn: Bool { pm?.on ?? mac.paxMax }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // v0.8.23: the folded row above carries the title, state and one line.
            Text(PaxMax.explanation).font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
            NoteRow(icon: "exclamationmark.circle", text: PaxMax.warning)
            if switchable {
                Text(PaxMax.rule).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
                ToggleRow(title: PaxMax.title,
                          detail: PaxMax.status(on: pm?.on, pendingSeconds: pendingSeconds),
                          isOn: Binding(get: { isOn && pm?.pending == nil },
                                        set: { want in
                                            if want { confirmOn = true }
                                            else if pm?.pending == nil { confirmOff = true }
                                        }))
                .disabled(mac.busy)
                if let p = pm?.pending {
                    TimelineView(.periodic(from: .now, by: 30)) { ctx in
                        let left = max(0, p.effective_at - Int(ctx.date.timeIntervalSince1970))
                        Text(p.status == "notifying"
                             ? "Pax is telling your trusted person first. The hour starts once they're told."
                             : "Turns off in \(max(1, (left + 59) / 60)) minute\(left <= 60 ? "" : "s").")
                            .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                    }
                    Button("I've changed my mind") { mac.cancelPaxMaxOff() }
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(mac.busy)
                }
            } else {
                NoteRow(icon: mac.paxMax ? "eye.slash" : "eye",
                        text: PaxMax.status(on: nil, pendingSeconds: nil))
            }
            if let n = mac.paxMaxNotice {
                NoteRow(icon: "checkmark.circle", text: n)
            }
        }
        .alert(PaxMax.confirmOnTitle, isPresented: $confirmOn) {
            Button("Turn on") { mac.turnPaxMaxOn() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(PaxMax.confirmOnMessage)
        }
        .alert(PaxMax.confirmOffTitle, isPresented: $confirmOff) {
            Button("Start the hour") { mac.requestPaxMaxOff() }
            Button("Keep Pax Max on", role: .cancel) {}
        } message: {
            Text(PaxMax.confirmOffMessage)
        }
        .onAppear { mac.refreshPaxMax() }
    }

    private var pendingSeconds: Int? {
        guard let p = pm?.pending else { return nil }
        return max(0, p.effective_at - Int(Date().timeIntervalSince1970))
    }
}

/// v0.8.23 Settings › Accountability partner email: who it is and its state, plus one
/// button. The form (how Pax sends the email, your own address) is in the Change sheet.
/// Rules unchanged: they're told before any turn-off wait starts, and changing or
/// removing them takes the turn-off wait (pax-guard enforces both).
private struct PartnerEmailSettings: View {
    @EnvironmentObject var mac: MacProtectModel
    @State private var showChange = false

    private var available: Bool { mac.isLocal && mac.deviceID != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(AppSettingsLayout.partnerEmail).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            if available {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(PartnerSummary.value(partner: mac.partnerView?.partner))
                        .font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
                        .textSelection(.enabled)
                    Spacer(minLength: 8)
                    Button(PartnerSummary.button(partner: mac.partnerView?.partner)) { showChange = true }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(mac.busy)
                }
            }
            Text(stateLine).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .sheet(isPresented: $showChange) {
            PartnerEmailForm().environmentObject(mac)
        }
    }

    private var stateLine: String {
        let p = mac.partnerView?.pending_partner
        return PartnerSummary.state(
            partner: mac.partnerView?.partner, available: available, pending: p != nil, pendingEmail: p?.email,
            pendingWhen: p.map { Date(timeIntervalSince1970: TimeInterval($0.effective_at))
                .formatted(date: .abbreviated, time: .shortened) },
            queued: mac.partnerView?.queued?.count ?? 0)
    }
}

/// v0.8.23: the former Settings form, unchanged, in a sheet.
private struct PartnerEmailForm: View {
    @EnvironmentObject var mac: MacProtectModel
    @Environment(\.dismiss) private var dismiss
    @State private var useSMTP = false
    @State private var relayURL = ""
    @State private var relayToken = ""
    @State private var host = ""
    @State private var port = "587"
    @State private var ssl = false
    @State private var user = ""
    @State private var password = ""
    @State private var owner = ""
    @State private var partner = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(AppSettingsLayout.partnerEmail).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            Text(PartnerSummary.rule).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Trusted person's email", text: $partner).textFieldStyle(.roundedBorder)
            TextField("Your email (optional, for copies)", text: $owner).textFieldStyle(.roundedBorder)
            if needsOwnerEmail {
                Text("Add your email: Pax's server needs it to send on your behalf.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            }
            if let p = mac.partnerView?.pending_partner {
                Text("Changing to \(p.email ?? "no one") on "
                     + Date(timeIntervalSince1970: TimeInterval(p.effective_at)).formatted(date: .abbreviated,
                                                                                           time: .shortened))
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            }
            DetailsDisclosure(title: "How Pax sends the email") {
                Picker("Send email through", selection: $useSMTP) {
                    Text("A Pax server").tag(false)
                    Text("My own email account").tag(true)
                }
                .pickerStyle(.segmented)
                if useSMTP {
                    TextField("smtp.example.com", text: $host).textFieldStyle(.roundedBorder)
                    HStack {
                        TextField("587", text: $port).textFieldStyle(.roundedBorder).frame(width: 80)
                        Toggle("SSL (port 465)", isOn: $ssl)
                    }
                    TextField("you@example.com", text: $user).textFieldStyle(.roundedBorder)
                    SecureField("App password (kept only by Pax's background protection)", text: $password)
                        .textFieldStyle(.roundedBorder)
                } else {
                    // v0.8.5: the Pax server this app uses relays the emails by default.
                    DetailText("Pax's server sends them (\(mac.escrow.baseURL.host ?? "the Pax server")). To use your own "
                               + "Pax server, enter its address and your account token.")
                    TextField(mac.escrow.baseURL.absoluteString, text: $relayURL).textFieldStyle(.roundedBorder)
                    SecureField("Account token (only for your own server)", text: $relayToken)
                        .textFieldStyle(.roundedBorder)
                }
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.buttonStyle(SecondaryButtonStyle())
                Button("Save") { save(); dismiss() }.buttonStyle(PrimaryButtonStyle(accent: true))
                    .disabled(mac.busy || needsOwnerEmail)
            }
        }
        .padding(24)
        .frame(width: 480)
        .onAppear {
            partner = mac.partnerView?.partner ?? ""
            owner = mac.partnerView?.owner_email ?? ""
            useSMTP = mac.partnerView?.transport?.kind == "smtp"
            if let url = mac.partnerView?.transport?.url, url != mac.escrow.baseURL.absoluteString { relayURL = url }
            host = mac.partnerView?.transport?.host ?? host
        }
    }

    /// The default relay registers an account on the app's server the first
    /// time, which needs an email address.
    private var needsOwnerEmail: Bool {
        guard !useSMTP, relayToken.isEmpty, !mac.hasAccount,
              owner.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        if case .success(let relay) = PartnerRelay.url(typed: relayURL, appServer: mac.escrow.baseURL) {
            return PartnerRelay.usesAppAccount(relay: relay, typedToken: relayToken, appServer: mac.escrow.baseURL)
        }
        return false
    }

    private func save() {
        if useSMTP {
            var t: [String: Any] = ["kind": "smtp", "host": host, "port": Int(port) ?? (ssl ? 465 : 587),
                                    "security": ssl ? "ssl" : "starttls", "username": user, "from": user]
            if !password.isEmpty { t["password"] = password }
            mac.saveEmailSettings(transport: t, ownerEmail: owner, partner: partner)
        } else {
            mac.saveRelayEmailSettings(url: relayURL, token: relayToken, ownerEmail: owner, partner: partner)
        }
        password = ""
        relayToken = ""
    }
}

/// v0.8.18: one "label … value" line in Advanced (like the turn-off wait row).
private struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(label).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            Spacer(minLength: 8)
            Text(value).font(Theme.body(13, weight: .medium)).foregroundStyle(Theme.primaryText)
        }
        .accessibilityElement(children: .combine)
    }
}
