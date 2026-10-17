// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

/// Home (v0.7.0) for the device picked in the switcher: its status, your blocked
/// sites (shared by all your devices), and "Request a change" with the turn-off wait countdown.
/// v0.8.14: this is the device's page. Its details and its own switches live here too
/// (they used to be a separate "Settings" screen); app-wide things are in Settings.
struct HomeView: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel
    @EnvironmentObject var blocklist: BlocklistModel
    private var setupPartnerPending: Bool { !(model.config.partnerEmail ?? "").isEmpty }

    var body: some View {
        PageColumn(maxWidth: 680) {
            if let rec = model.selectedRecord {
                PhoneHome(rec: rec)
            } else {
                macHome
            }
            if blocklist.signedIn { BlockedSitesCard() }
            CrisisLines()
        }
        .onAppear {
            if mac.deviceID != nil { mac.refresh() }
            if blocklist.signedIn { blocklist.refresh() }
            Task { await model.refreshPhones() }
        }
    }

    @ViewBuilder private var macHome: some View {
        if mac.phase == .released {
            MacReleasedCard()
        } else if mac.phase == .removed {
            MacRemovedCard()
        } else if mac.deviceID != nil {
            StepHeader(eyebrow: "This Mac", title: "You're protected", subtitle: Brand.tagline)
            Card {
                HStack(spacing: 10) {
                    Circle().fill(Theme.accent).frame(width: 10, height: 10)
                    Text("Protected").font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
                }
                NoteRow(icon: "laptopcomputer", text: "Every browser and app on this Mac.")
                // v0.8.0: which filter is answering (CleanBrowsing, or the AdGuard backup).
                NoteRow(icon: "shield", text: FilterStatusText.line(mac.guardStatus?.dns))
                if let notice = mac.guardStatus?.update?.notice {
                    NoteRow(icon: "arrow.down.circle", text: notice)
                }
                // v0.8.14: an older set-up's Chrome extension list (calm, read-only note).
                if let r = mac.guardStatus?.browser_rules, r.outdated,
                   let note = BrowserRulesNotice.text(browser: r.browser, missing: r.missing) {
                    NoteRow(icon: "puzzlepiece.extension", text: note)
                }
                if let t = mac.guardStatus?.tamper, let last = t.recent.last {
                    NoteRow(icon: "exclamationmark.shield",
                            text: "Pax noticed a change to this Mac's security settings ("
                                + last.kind.replacingOccurrences(of: "changed:", with: "")
                                    .replacingOccurrences(of: "_", with: " ")
                                + ", " + Date(timeIntervalSince1970: TimeInterval(last.ts))
                                    .formatted(date: .abbreviated, time: .shortened) + ").")
                }
                if mac.isLocal, mac.partnerView?.partner == nil, setupPartnerPending {
                    NoteRow(icon: "envelope", text: "To tell your trusted person, set up email in Settings › "
                            + AppSettingsLayout.partnerEmail + ".")
                    Button("Open Settings") { model.screen = .settings }.buttonStyle(.link).font(Theme.body(13))
                }
            }
            if let failure = mac.failure {
                ErrorCard(error: failure, retry: { mac.refresh() }, details: { mac.supportDetails(failure) })
            }
            MacRequestChangeCard()
            // v0.8.14: this Mac's own switches and blocked apps, on its page.
            MacSettingsCard()
            MacBlockedAppsCard()
            MacDetailsCard()      // v0.8.15: Support ID and "Allow verified support release"
        } else {
            StepHeader(eyebrow: "This Mac", title: mac.deviceState == .pending ? "Setting up" : "Not set up yet",
                       subtitle: "Protect every browser and app on this Mac in a few calm steps.")
            Button(mac.deviceState == .pending ? "Continue setting up" : "Protect this Mac") {
                if mac.phase == .intro { mac.step = 0 }
                model.screen = .mac
            }
            .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
        }
    }
}

/// Home for one iPhone or iPad.
struct PhoneHome: View {
    @EnvironmentObject var model: SetupModel
    let rec: PaxDeviceRecord
    @State private var confirmOff = false
    @State private var showEmergency = false
    @State private var supportCode = ""

    var body: some View {
        StepHeader(eyebrow: rec.isIPad ? "iPad" : "iPhone",
                   title: rec.status == .protected ? "You're protected" : "Setting up",
                   subtitle: rec.status == .protected ? Brand.tagline
                       : "Set-up didn't finish on this device yet. Plug it in to carry on.")
        Card {
            HStack(spacing: 10) {
                Circle().fill(rec.status == .protected ? Theme.accent : Theme.mutedText).frame(width: 10, height: 10)
                Text(rec.status == .protected ? "Protected" : "Setting up")
                    .font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            }
            NoteRow(icon: rec.isIPad ? "ipad" : "iphone",
                    text: rec.name + (rec.iosVersion.map { " · iOS \($0)" } ?? ""))
            if rec.status != .protected {
                Button("Carry on setting up") { model.addPhone() }
                    .buttonStyle(PrimaryButtonStyle(accent: true))
            }
        }
        if rec.status == .protected { requestChange }
        if let failure = model.failure, model.screen == .home {
            ErrorCard(error: failure, retry: { model.retry() }, details: { model.supportDetails(failure) })
        }
        PhoneDetailsCard(rec: rec)   // v0.8.14: the device's details, on its page
    }

    @ViewBuilder private var requestChange: some View {
        Card {
            Text("Request a change").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
            if let pw = model.revealedPhonePassword[rec.id] {
                Text("Your turn-off wait is over. To remove Pax from the \(rec.isIPad ? "iPad" : "iPhone"): Settings › General › "
                     + "VPN & Device Management › Pax › Remove Management, then enter this password:")
                    .font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
                Text(pw).font(.system(size: 18, design: .monospaced)).textSelection(.enabled)
            } else if let st = model.phoneStatus[rec.id] {
                if st.in_grace_period {
                    NoteRow(icon: "heart", text: TurnOffWait.firstHour + " That's until "
                            + Date(timeIntervalSince1970: TimeInterval(st.grace_until))
                                .formatted(date: .abbreviated, time: .shortened) + ".")
                }
                if let rr = st.removal_request {
                    // v0.8.16: "Pax turns off in 2 days 14 h · Cancel".
                    TimelineView(.periodic(from: .now, by: 1)) { ctx in
                        TurnOffCountdownRow(seconds: model.phoneRemaining(rec, at: ctx.date),
                                            cancel: rr.status == "pending" ? { model.cancelPhoneRemoval(rec) } : nil)
                    }
                    if rr.can_reveal || model.phoneRemaining(rec, at: Date()) == 0 {
                        Button("Show how to turn Pax off") { model.revealPhonePassword(rec) }
                            .buttonStyle(PrimaryButtonStyle(accent: true))
                    }
                } else {
                    Text("Want to turn Pax off on this \(rec.isIPad ? "iPad" : "iPhone")? Ask here, and it turns off "
                         + "after your turn-off wait. You can cancel any time during the wait.")
                        .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Start the turn-off wait") { confirmOff = true }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(model.busy)
                }
            } else {
                Text(rec.escrowID == nil ? "Pax is looking for this device on your account…" : "Checking…")
                    .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            }
            // v0.8.15: a one-time code from Pax support, for this device only (the server checks it).
            if model.revealedPhonePassword[rec.id] == nil, rec.escrowID != nil {
                DisclosureGroup("In an emergency", isExpanded: $showEmergency) {
                    SupportCodeEntry(code: $supportCode, busy: model.busy,
                                     allowed: model.phoneStatus[rec.id]?.support_release?.allowed) {
                        model.redeemPhoneSupportCode(rec, code: supportCode)
                        supportCode = ""
                    }
                    .padding(.top, 6)
                }
                .font(Theme.body(13))
                .foregroundStyle(Theme.mutedText)
            }
        }
        .alert("Start your turn-off wait?", isPresented: $confirmOff) {
            Button("Start the wait", role: .destructive) { model.requestPhoneRemoval(rec) }
            Button("Keep Pax on", role: .cancel) {}
        } message: {
            Text("Pax stays on until your turn-off wait ends. Your trusted person, if you added one, is told. "
                 + "You can cancel any time during the wait.")
        }
    }
}

/// v0.8.14: one iPhone or iPad's details and actions, on its page (before 0.8.14 this
/// was a separate "Settings" screen). Values wrap instead of being cut off.
struct PhoneDetailsCard: View {
    @EnvironmentObject var model: SetupModel
    let rec: PaxDeviceRecord
    @State private var confirmForget = false
    @State private var showApps = false

    var body: some View {
        Card {
            Text("Details").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
            detail("Status", rec.status == .protected ? "Protected" : "Setting up")
            if let w = model.phoneStatus[rec.id]?.wait_seconds {          // v0.8.16
                detail(TurnOffWait.label, TurnOffWait.duration(seconds: w))
            }
            if let v = rec.iosVersion { detail(rec.isIPad ? "iPadOS" : "iOS", v) }
            if let k = rec.keepData { detail("Set up by", k ? "Keeping everything on it" : "Erasing and setting up fresh") }
            if let f = rec.filter { detail("Filter", f) }
            // v0.8.13: always blocked, no switch; one row for both (v0.8.14).
            detail(DeviceDetails.mediaLabel, DeviceDetails.mediaValue)
            if let note = AlwaysBlockedMedia.legacyNote(xMediaWasOn: rec.blocksXMedia,
                                                        blueskyMediaWasOn: rec.blocksBlueskyMedia,
                                                        usesPaxFilter: rec.usesPaxFilter) {
                Text(note).font(Theme.body(12)).foregroundStyle(Theme.accent)
                    .fixedSize(horizontal: false, vertical: true)
            }
            detail("YouTube Restricted Mode", (rec.youtubeRestricted ?? true) ? "On" : "Off")
            if let apps = rec.blockedAppNames {
                if apps.isEmpty {
                    detail(DeviceDetails.appsLabel, DeviceDetails.appCount(apps))
                } else {
                    DisclosureGroup(isExpanded: $showApps) {
                        Text(DeviceDetails.appList(apps))
                            .font(Theme.body(12.5)).foregroundStyle(Theme.primaryText)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                            .padding(.top, 4)
                    } label: {
                        detail(DeviceDetails.appsLabel, DeviceDetails.appCount(apps))
                    }
                }
            }
            Text(DeviceDetails.setUpChoicesNote)
                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            // v0.8.15 (changeable after set-up): Support ID (with copy) and "Allow verified support release" (kept by the server).
            if let st = model.phoneStatus[rec.id] {
                if let id = st.support_id { SupportIDRow(supportID: id) }
                if let sr = st.support_release {
                    SupportReleaseRow(state: sr, busy: model.busy) { model.setPhoneSupportRelease(rec, $0) }
                }
            }
            HStack(spacing: 12) {
                Button("Set up again") { model.addPhone() }.buttonStyle(SecondaryButtonStyle())
                Button("Remove from this list") { confirmForget = true }.buttonStyle(.link).font(Theme.body(12))
            }
        }
        .alert("Remove \(rec.name) from this list?", isPresented: $confirmForget) {
            Button("Remove", role: .destructive) { model.forgetRecord(rec.id) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This only tidies the list on this Mac. Pax stays on the device.")
        }
    }

    private func detail(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(label).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            Text(value).font(Theme.body(13, weight: .medium)).foregroundStyle(Theme.primaryText)
                .multilineTextAlignment(.trailing)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// "Blocked sites", simplified for Home: add a site, see how many, open the list.
struct BlockedSitesCard: View {
    @EnvironmentObject var blocklist: BlocklistModel
    @EnvironmentObject var model: SetupModel

    var body: some View {
        Card {
            HStack {
                Text("Blocked sites").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
                Spacer()
                Button("See all (\(blocklist.blocked.count))") { model.screen = .blockedSites }
                    .buttonStyle(.link).font(Theme.body(13))
            }
            HStack(spacing: 12) {
                TextField("Add a site, e.g. example.com", text: $blocklist.newSite)
                    .textFieldStyle(.roundedBorder).font(Theme.body(14))
                    .onSubmit { blocklist.add() }
                Button("Block") { blocklist.add() }
                    .buttonStyle(PrimaryButtonStyle(accent: true))
                    .disabled(blocklist.normalisedNewSite == nil || blocklist.busy)
            }
            Text("Blocked straight away. Unblocking one takes \(blocklist.delayText).")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
            let waiting = blocklist.pendingRemovals.count + blocklist.pendingExceptions.count
            if waiting > 0 {
                Button("\(waiting) change\(waiting == 1 ? "" : "s") waiting") { model.screen = .blockedSites }
                    .buttonStyle(.link).font(Theme.body(13))
            }
            if let notice = blocklist.notice {
                NoteRow(icon: "checkmark.circle", text: notice)
            }
            if let error = blocklist.errorMessage {
                NoteRow(icon: "info.circle", text: error)
            }
            if let failure = blocklist.failure {
                ErrorCard(error: failure, retry: { blocklist.retry() },
                          details: { Support.details(failure, log: [], extraRedactions: model.privateNames) })
            }
        }
    }
}
