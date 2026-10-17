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

    var body: some View {
        PageColumn(maxWidth: 680) {
            StepHeader(eyebrow: "", title: "Settings", subtitle: "Everything you can change, in plain words. "
                       + "An iPhone's or iPad's own details are on its page.")
            if let failure = mac.failure {
                ErrorCard(error: failure, retry: { mac.refresh() }, details: { mac.supportDetails(failure) })
            }
            // v0.8.18: this Mac's switches and details moved here from Home, grouped simply.
            if mac.deviceID != nil { Card { BlockingSettings() } }
            Card { PaxMaxSettings() }                          // v0.8.12
            Card { TurningOffSettings() }                      // v0.8.16 turn-off wait; v0.8.18 trial, support release
            Card { PartnerEmailSettings() }
            Card { UpdateSettings() }
            Card { GeneralSettings() }                         // About
            Card {
                DisclosureGroup(isExpanded: $showAdvanced) {
                    VStack(alignment: .leading, spacing: 18) {
                        if mac.deviceID != nil {
                            MacDetailsSettings()               // v0.8.18: Support ID, filter, security notices
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

private struct GeneralSettings: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(AppSettingsLayout.about).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            PaxWordmark(size: 32)
            Text(Brand.tagline).font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
            Text("Version \(Brand.version)").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(Brand.principles, id: \.self) { p in
                    NoteRow(icon: "leaf", text: p)
                }
            }
            Text("Free and open source under the GPL-3.0. Your settings stay with you and the server you choose.")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            Link(Brand.site, destination: Brand.siteURL).font(Theme.body(13))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}


/// v0.8.18 Settings › Blocking: this Mac's live switches (they were on Home's "This Mac"
/// card), each with one plain line.
private struct BlockingSettings: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(AppSettingsLayout.blocking).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            switch mac.adblockSwitch {
            case .guardLive:
                ToggleRow(title: "Ads and trackers", detail: AppSettingsLayout.Line.adsLive,
                          isOn: Binding(get: { mac.adblock }, set: { mac.setAdblock($0) }))
            case .server:
                ToggleRow(title: "Ads and trackers", detail: AppSettingsLayout.Line.adsServer,
                          isOn: Binding(get: { mac.adblock }, set: { mac.setAdblock($0) }))
            case .setUpOnly:
                NoteRow(icon: "hand.raised",
                        text: "Ads and trackers: \(mac.adblock ? "blocked" : "allowed"), as chosen at set-up. "
                            + "The switch works here once Pax has finished updating.")
            }
            if mac.canSync && mac.sync != nil {
                Divider().overlay(Theme.border)
                ToggleRow(title: "Sync blocked sites across devices",
                          detail: AppSettingsLayout.Line.sync + " " + ListSyncLinker.detail(mac.sync),
                          isOn: Binding(get: { mac.sync?.enabled ?? true }, set: { mac.setSyncEnabled($0) }))
            }
            if mac.youtubeAvailable {
                Divider().overlay(Theme.border)
                ToggleRow(title: "YouTube Restricted Mode", detail: AppSettingsLayout.Line.youtube,
                          isOn: Binding(get: { mac.youtubeRestricted }, set: { mac.setYouTubeRestricted($0) }))
            }
            Divider().overlay(Theme.border)
            NoteRow(icon: "info.circle", text: AlwaysBlockedMedia.notice)   // v0.8.13: no switch
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// v0.8.18 Settings › Turning Pax off: the turn-off wait, the trial day, and "Allow verified
/// support release" (was Home's Details card).
private struct TurningOffSettings: View {
    @EnvironmentObject var mac: MacProtectModel
    @State private var confirmEndTrial = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(AppSettingsLayout.turningOff).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            if let w = mac.status?.wait_seconds {
                TurnOffWaitRow(seconds: w)
            }
            Text(AppSettingsLayout.Line.turnOffWait + " Each iPhone or iPad shows its own on its page.")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            if let line = TrialDay.settingsLine(mac.status?.trial) {
                NoteRow(icon: "sun.max", text: line)
                if mac.trialActive {
                    Button(TrialDay.startWaitButton) { confirmEndTrial = true }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(mac.busy)
                }
            }
            if let s = mac.status, s.support_id != nil || s.support_release != nil {
                Divider().overlay(Theme.border)
                if let sr = s.support_release {
                    SupportReleaseRow(state: sr, busy: mac.busy, trialActive: mac.trialActive) { mac.setSupportRelease($0) }
                }
                Text(AppSettingsLayout.Line.supportReleaseRule)
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
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

/// v0.8.18 Settings › Advanced: this Mac's Support ID, which filter is answering, and the
/// security notices (were on Home).
private struct MacDetailsSettings: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("This Mac's details").font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            if let id = mac.status?.support_id {
                SupportIDRow(supportID: id)
                Text(AppSettingsLayout.Line.supportID).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            }
            NoteRow(icon: "shield", text: FilterStatusText.line(mac.guardStatus?.dns))
            // v0.8.18: which filter answers, and the backup's reason when it's on.
            if let dns = mac.guardStatus?.dns, dns.filter_mode != nil {
                DetailRow(label: "Filter", value: FilterModeText.label(dns.filter_mode))
                if let line = FilterModeText.fallbackLine(dns) {
                    Text(line).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            FamilyLayerSettings()
            if let t = mac.guardStatus?.tamper, !t.recent.isEmpty {
                Text("Security notices").font(Theme.body(13, weight: .semibold)).foregroundStyle(Theme.primaryText)
                Text(AppSettingsLayout.Line.securityNotices).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                ForEach(Array(t.recent.suffix(5).reversed().enumerated()), id: \.offset) { _, e in
                    NoteRow(icon: "exclamationmark.shield", text: HomeLayout.tamperNotice(kind: e.kind, at: e.ts))
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
            Text("Where this Mac keeps its key").font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
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
private struct UpdateSettings: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(AppSettingsLayout.updates).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            Text("Version \(Brand.version)").font(Theme.body(13)).foregroundStyle(Theme.primaryText)
            if let u = mac.guardStatus?.update {
                Text(u.last_checked.map {
                    "Last checked " + Date(timeIntervalSince1970: TimeInterval($0))
                        .formatted(date: .abbreviated, time: .shortened)
                } ?? "Not checked yet")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
            }
            Button("Update now") { mac.updateNow() }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(mac.busy || mac.deviceID == nil)
            Text("Pax installs updates by itself, signed and checked, so a fix reaches you quickly.")
                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
        }
        .onAppear { if mac.deviceID != nil { mac.refresh() } }
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
            Text(AppSettingsLayout.paxMax).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
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

private struct PartnerEmailSettings: View {
    @EnvironmentObject var mac: MacProtectModel
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
        VStack(alignment: .leading, spacing: 8) {
            Text(AppSettingsLayout.partnerEmail).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            Text("Optional: someone you trust. With someone set, Pax tells them before any turn-off wait starts; "
                 + "if it can't reach them, the wait doesn't start yet. Changing or removing them takes your turn-off wait.")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            if !(mac.isLocal && mac.deviceID != nil) {
                Text("Available once this Mac is protected with its key on this Mac. On the server path, the server "
                     + "emails them.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            } else {
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
                    Text("Pax's server sends them (\(mac.escrow.baseURL.host ?? "the Pax server")). To use your own "
                         + "Pax server, enter its address and your account token there.")
                        .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    TextField(mac.escrow.baseURL.absoluteString, text: $relayURL).textFieldStyle(.roundedBorder)
                    SecureField("Account token (only for your own server)", text: $relayToken)
                        .textFieldStyle(.roundedBorder)
                    if needsOwnerEmail {
                        Text("Add your email below: Pax's server needs it to send on your behalf.")
                            .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    }
                }
                TextField("Your email (optional, for copies)", text: $owner).textFieldStyle(.roundedBorder)
                TextField("Trusted person's email", text: $partner).textFieldStyle(.roundedBorder)
                if let p = mac.partnerView?.pending_partner {
                    Text("Changing to \(p.email ?? "no one") on "
                         + Date(timeIntervalSince1970: TimeInterval(p.effective_at)).formatted(date: .abbreviated,
                                                                                               time: .shortened))
                        .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                }
                Button("Save") { save() }.buttonStyle(PrimaryButtonStyle(accent: true))
                    .disabled(mac.busy || needsOwnerEmail)
                }
        }
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
