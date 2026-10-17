// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

/// Home for the device picked in the switcher.
/// v0.8.18 (Ruben: "simplify, simplify, simplify: 1, 2, 3, not option overwhelm"): three
/// calm cards and nothing else.
///   1 Status: one big line ("Protected", or "Pax turns off in 12 h 19 min · Cancel"),
///     the trial-day countdown when there is one, and at most one "1 thing to know" line
///     that opens to the notices.
///   2 What's blocked: sites and apps, a count and one "Add" each.
///   3 Turn off: one button; "In an emergency" tucked inside.
/// Nothing was removed: this Mac's switches (ads, sync, YouTube Restricted Mode, Pax Max,
/// the X/Bluesky line) and its details (turn-off wait, Support ID, verified support release,
/// security notices) are in Settings.
struct HomeView: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel
    @EnvironmentObject var blocklist: BlocklistModel

    var body: some View {
        PageColumn(maxWidth: 680) {
            if let rec = model.selectedRecord {
                PhoneHome(rec: rec)
            } else {
                macHome
            }
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
            MacStatusCard()
            if let failure = mac.failure {
                ErrorCard(error: failure, retry: { mac.refresh() }, details: { mac.supportDetails(failure) })
            }
            WhatsBlockedCard(apps: .mac)
            MacTurnOffCard()
        } else {
            StepHeader(eyebrow: "This Mac", title: mac.deviceState == .pending ? "Setting up" : "Not set up yet",
                       subtitle: "Protect every browser and app on this Mac in three calm steps.")
            Button(mac.deviceState == .pending ? "Continue setting up" : "Protect this Mac") {
                if mac.phase == .intro { mac.step = 0 }
                model.screen = .mac
            }
            .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
        }
    }
}

/// The small numbered label at the top of each Home card: "1  Status".
struct HomeStepLabel: View {
    let n: Int
    let title: String

    var body: some View {
        HStack(spacing: 8) {
            Text("\(n)")
                .font(Theme.body(11, weight: .semibold))
                .frame(width: 20, height: 20)
                .background(Circle().fill(Theme.secondary))
                .foregroundStyle(Theme.primaryText)
            Text(title.uppercased())
                .font(Theme.body(11, weight: .semibold))
                .tracking(1.2)
                .foregroundStyle(Theme.mutedText)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Step \(n): \(title)")
    }
}

/// One quiet notice for "1 thing to know".
struct HomeNotice: Identifiable {
    let id: String
    let icon: String
    let text: String
}

/// The big calm line, shared by the Mac and iPhone status cards.
struct StatusHeadline: View {
    let status: HomeLayout.Status
    var cancel: (() -> Void)?

    var body: some View {
        switch status {
        case .turningOff(let left, false):
            TurnOffCountdownRow(seconds: left, cancel: cancel)
        case .turningOff(_, true), .released:
            Text(HomeLayout.headline(status)).font(Theme.heading(26)).foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
        case .protected, .trial:
            HStack(spacing: 10) {
                Circle().fill(Theme.accent).frame(width: 11, height: 11)
                Text(HomeLayout.headline(status)).font(Theme.heading(30)).foregroundStyle(Theme.primaryText)
            }
        }
    }
}

/// The trial-day lines under "Protected": until when, a gentle countdown, "Start my wait now".
struct TrialDayLines: View {
    let trial: EscrowClient.DeviceStatus.TrialState?
    let now: Date
    let endTrial: () -> Void

    var body: some View {
        if let t = trial, TrialDay.isActive(t, now: now) {
            VStack(alignment: .leading, spacing: 4) {
                Text(TrialDay.homeLine(until: t.until))
                    .font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Text(TrialDay.countdown(secondsLeft: TrialDay.secondsLeft(t, now: now)))
                        .font(Theme.body(13).monospacedDigit()).foregroundStyle(Theme.mutedText)
                    Text("·").font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                    Button(TrialDay.startWaitButton, action: endTrial)
                        .buttonStyle(.link).font(Theme.body(13))
                }
            }
        }
    }
}

/// Card 1 for this Mac.
struct MacStatusCard: View {
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel
    @State private var showNotices = false
    @State private var confirmEndTrial = false

    private var setupPartnerPending: Bool {
        mac.isLocal && mac.partnerView?.partner == nil && !(model.config.partnerEmail ?? "").isEmpty
    }

    /// Everything that used to stack up on Home, now behind one line.
    private var notices: [HomeNotice] {
        var out: [HomeNotice] = []
        let g = mac.guardStatus
        if HomeLayout.filterNeedsNotice(g?.dns) {
            out.append(HomeNotice(id: "filter", icon: "shield", text: FilterStatusText.line(g?.dns)))
        }
        if let notice = g?.update?.notice {
            out.append(HomeNotice(id: "update", icon: "arrow.down.circle", text: notice))
        }
        // v0.8.14: an older set-up's Chrome extension list (calm, read-only note).
        if let r = g?.browser_rules, r.outdated, let note = BrowserRulesNotice.text(browser: r.browser, missing: r.missing) {
            out.append(HomeNotice(id: "browser", icon: "puzzlepiece.extension", text: note))
        }
        // v0.8.23: brief backup-filter episodes aren't notices; no raw log codes.
        if let last = SecurityNotices.visible(g?.tamper?.recent ?? []).last {
            out.append(HomeNotice(id: "tamper", icon: "exclamationmark.shield",
                                  text: last.text + " More in Settings › Advanced."))
        }
        if setupPartnerPending {
            out.append(HomeNotice(id: "partner", icon: "envelope",
                                  text: "To tell your trusted person, set up email in Settings › "
                                      + AppSettingsLayout.partnerEmail + "."))
        }
        return out
    }

    var body: some View {
        Card {
            HomeStepLabel(n: 1, title: HomeLayout.statusTitle)
            if let s = mac.status {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    let st = HomeLayout.status(removalStatus: s.removal_request?.status,
                                               secondsLeft: mac.remaining(at: ctx.date), trial: s.trial, now: ctx.date)
                    VStack(alignment: .leading, spacing: 8) {
                        StatusHeadline(status: st, cancel: { mac.cancelRemoval() })
                        switch st {
                        case .protected:
                            Text("Every browser and app on this Mac.")
                                .font(Theme.body(14)).foregroundStyle(Theme.mutedText)
                            if s.in_grace_period {
                                Text(TurnOffWait.firstHour).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                            }
                        case .trial:
                            TrialDayLines(trial: s.trial, now: ctx.date) { confirmEndTrial = true }
                        case .turningOff(_, let notifying):
                            Text(notifying ? "Your turn-off wait starts once they're told. You can cancel now."
                                           : "Changed your mind? Cancel any time before then.")
                                .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                                .fixedSize(horizontal: false, vertical: true)
                            if notifying {
                                Button("Cancel") { mac.cancelRemoval() }.buttonStyle(.link).font(Theme.body(13))
                            }
                        case .released:
                            EmptyView()
                        }
                    }
                }
            } else {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Checking…").font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                }
            }
            let items = notices
            if let summary = HomeLayout.noticesSummary(count: items.count) {
                DisclosureGroup(isExpanded: $showNotices) {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(items) { n in NoteRow(icon: n.icon, text: n.text) }
                        if items.contains(where: { $0.id == "partner" || $0.id == "tamper" }) {
                            Button("Open Settings") { model.screen = .settings }
                                .buttonStyle(.link).font(Theme.body(13))
                        }
                    }
                    .padding(.top, 6)
                } label: {
                    Label(summary, systemImage: "info.circle").font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                }
            }
        }
        .alert(TrialDay.confirmTitle, isPresented: $confirmEndTrial) {
            Button(TrialDay.startWaitButton, role: .destructive) { mac.endTrial() }
            Button("Not now", role: .cancel) {}
        } message: {
            Text(TrialDay.confirmMessage)
        }
    }
}

/// Card 2: sites and apps, a count and one "Add" each.
struct WhatsBlockedCard: View {
    enum Apps {
        case mac
        /// An iPhone or iPad: the apps chosen at set-up (nil: not known).
        case phone([String]?)
    }

    let apps: Apps
    @EnvironmentObject var blocklist: BlocklistModel
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel
    @State private var addingSite = false
    @State private var showAppPicker = false
    @State private var showApps = false

    var body: some View {
        Card {
            HomeStepLabel(n: 2, title: HomeLayout.blockedTitle)
            if blocklist.signedIn { sitesRow }
            if blocklist.signedIn { Divider().overlay(Theme.border) }
            appsRow
            Text(HomeLayout.blockedFootnote)
                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .sheet(isPresented: $showAppPicker) {
            MacAppPickerSheet(already: Set(mac.blockedApps?.apps.map(\.bundle_id) ?? [])) { path in
                mac.blockApp(path: path)
            }
        }
    }

    private func row(icon: String, title: String, count: String, addTitle: String?, add: @escaping () -> Void,
                     seeAll: (() -> Void)?) -> some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: icon).font(.system(size: 16)).foregroundStyle(Theme.mutedText).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
                if let seeAll {
                    Button(count, action: seeAll).buttonStyle(.link).font(Theme.body(12.5))
                } else {
                    Text(count).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                }
            }
            Spacer()
            if let addTitle {
                Button(addTitle, action: add).buttonStyle(SecondaryButtonStyle())
            }
        }
    }

    @ViewBuilder private var sitesRow: some View {
        row(icon: "globe", title: "Sites", count: HomeLayout.sitesCount(blocklist.blocked.count),
            addTitle: addingSite ? "Close" : "Add", add: { addingSite.toggle() },
            seeAll: { model.screen = .blockedSites })
        if addingSite {
            HStack(spacing: 12) {
                TextField("example.com", text: $blocklist.newSite)
                    .textFieldStyle(.roundedBorder).font(Theme.body(14))
                    .onSubmit { blocklist.add() }
                Button("Block") { blocklist.add() }
                    .buttonStyle(PrimaryButtonStyle(accent: true))
                    .disabled(blocklist.normalisedNewSite == nil || blocklist.busy)
            }
        }
        let waiting = blocklist.pendingRemovals.count + blocklist.pendingExceptions.count
        if waiting > 0 {
            Button("\(waiting) change\(waiting == 1 ? "" : "s") waiting") { model.screen = .blockedSites }
                .buttonStyle(.link).font(Theme.body(13))
        }
        if let notice = blocklist.notice { NoteRow(icon: "checkmark.circle", text: notice) }
        if let error = blocklist.errorMessage { NoteRow(icon: "info.circle", text: error) }
        if let failure = blocklist.failure {
            ErrorCard(error: failure, retry: { blocklist.retry() },
                      details: { Support.details(failure, log: [], extraRedactions: model.privateNames) })
        }
    }

    @ViewBuilder private var appsRow: some View {
        switch apps {
        case .mac:
            if mac.canBlockApps {
                let list = mac.blockedApps?.apps ?? []
                row(icon: "app.badge", title: "Apps", count: HomeLayout.appsCount(list.count),
                    addTitle: "Add", add: { showAppPicker = true },
                    seeAll: list.isEmpty ? nil : { showApps.toggle() })
                if showApps && !list.isEmpty { MacBlockedAppRows() }
            } else {
                row(icon: "app.badge", title: "Apps", count: "Work when this Mac keeps its own key (Settings › Advanced)",
                    addTitle: nil, add: {}, seeAll: nil)
            }
        case .phone(let names):
            if let names {
                row(icon: "app.badge", title: "Apps", count: HomeLayout.appsCount(names.count) + " · chosen at set-up",
                    addTitle: nil, add: {}, seeAll: names.isEmpty ? nil : { showApps.toggle() })
                if showApps && !names.isEmpty {
                    Text(DeviceDetails.appList(names))
                        .font(Theme.body(12.5)).foregroundStyle(Theme.primaryText)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
        }
    }
}

/// Home for one iPhone or iPad: the same three cards.
struct PhoneHome: View {
    @EnvironmentObject var model: SetupModel
    let rec: PaxDeviceRecord
    @State private var confirmOff = false
    @State private var confirmEndTrial = false
    @State private var showEmergency = false
    @State private var showDetails = false
    @State private var supportCode = ""

    private var st: EscrowClient.DeviceStatus? { model.phoneStatus[rec.id] }
    private var trialActive: Bool { TrialDay.isActive(st?.trial) }

    var body: some View {
        statusCard
        if let failure = model.failure, model.screen == .home {
            ErrorCard(error: failure, retry: { model.retry() }, details: { model.supportDetails(failure) })
        }
        if rec.status == .protected {
            WhatsBlockedCard(apps: .phone(rec.blockedAppNames))
            turnOffCard
        }
    }

    // MARK: 1 Status

    private var statusCard: some View {
        Card {
            HomeStepLabel(n: 1, title: HomeLayout.statusTitle)
            if rec.status != .protected {
                HStack(spacing: 10) {
                    Circle().fill(Theme.mutedText).frame(width: 11, height: 11)
                    Text("Setting up").font(Theme.heading(30)).foregroundStyle(Theme.primaryText)
                }
                Text("Set-up didn't finish on this \(rec.isIPad ? "iPad" : "iPhone") yet. Plug it in to carry on.")
                    .font(Theme.body(14)).foregroundStyle(Theme.mutedText)
                Button("Carry on setting up") { model.addPhone() }
                    .buttonStyle(PrimaryButtonStyle(accent: true))
            } else if let s = st {
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    let state = HomeLayout.status(removalStatus: s.removal_request?.status,
                                                  secondsLeft: model.phoneRemaining(rec, at: ctx.date),
                                                  trial: s.trial, now: ctx.date)
                    VStack(alignment: .leading, spacing: 8) {
                        StatusHeadline(status: state,
                                       cancel: s.removal_request?.status == "pending" ? { model.cancelPhoneRemoval(rec) } : nil)
                        switch state {
                        case .protected:
                            Text(rec.name + (rec.iosVersion.map { " · iOS \($0)" } ?? ""))
                                .font(Theme.body(14)).foregroundStyle(Theme.mutedText)
                            if s.in_grace_period {
                                Text(TurnOffWait.firstHour).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                            }
                        case .trial:
                            TrialDayLines(trial: s.trial, now: ctx.date) { confirmEndTrial = true }
                        default:
                            EmptyView()
                        }
                    }
                }
            } else {
                Text(rec.escrowID == nil ? "Pax is looking for this device on your account…" : "Checking…")
                    .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            }
        }
        .alert(TrialDay.confirmTitle, isPresented: $confirmEndTrial) {
            Button(TrialDay.startWaitButton, role: .destructive) { model.endPhoneTrial(rec) }
            Button("Not now", role: .cancel) {}
        } message: {
            Text(TrialDay.confirmMessage)
        }
    }

    // MARK: 3 Turn off

    private var turnOffCard: some View {
        Card {
            HomeStepLabel(n: 3, title: HomeLayout.turnOffTitle)
            if let pw = model.revealedPhonePassword[rec.id] {
                Text("Your turn-off wait is over. To remove Pax from the \(rec.isIPad ? "iPad" : "iPhone"): Settings › General › "
                     + "VPN & Device Management › Pax › Remove Management, then enter this password:")
                    .font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
                Text(pw).font(.system(size: 18, design: .monospaced)).textSelection(.enabled)
            } else if let s = st {
                if let rr = s.removal_request {
                    if rr.can_reveal || model.phoneRemaining(rec, at: Date()) == 0 {
                        Button("Show how to turn Pax off") { model.revealPhonePassword(rec) }
                            .buttonStyle(PrimaryButtonStyle(accent: true))
                    } else {
                        Text("Pax turns off when the wait ends. Cancel any time from Status above.")
                            .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                    }
                } else {
                    Text(HomeLayout.turnOffCaption(waitSeconds: s.wait_seconds, trialActive: trialActive))
                        .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    Button(HomeLayout.turnOffButton(trialActive: trialActive)) { confirmOff = true }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(model.busy)
                }
            }
            // v0.8.15: a one-time code from Pax support, for this device only (the server checks it).
            if model.revealedPhonePassword[rec.id] == nil, rec.escrowID != nil {
                DisclosureGroup("In an emergency", isExpanded: $showEmergency) {
                    SupportCodeEntry(code: $supportCode, busy: model.busy, allowed: st?.support_release?.allowed) {
                        model.redeemPhoneSupportCode(rec, code: supportCode)
                        supportCode = ""
                    }
                    .padding(.top, 6)
                }
                .font(Theme.body(13))
                .foregroundStyle(Theme.mutedText)
            }
            // v0.8.18: this device's details, folded away (they were a full card on Home).
            DisclosureGroup("Device details", isExpanded: $showDetails) {
                PhoneDetailsList(rec: rec).padding(.top, 6)
            }
            .font(Theme.body(13))
            .foregroundStyle(Theme.mutedText)
        }
        .alert(trialActive ? "Turn Pax off now?" : "Start your turn-off wait?", isPresented: $confirmOff) {
            Button(trialActive ? "Turn off" : "Start the wait", role: .destructive) { model.requestPhoneRemoval(rec) }
            Button("Keep Pax on", role: .cancel) {}
        } message: {
            Text(trialActive
                 ? "It's your trial day, so there's no wait. Your trusted person, if you added one, is told."
                 : "Pax stays on until your turn-off wait ends. Your trusted person, if you added one, is told. "
                     + "You can cancel any time during the wait.")
        }
    }
}

/// v0.8.14: one iPhone or iPad's details and actions (v0.8.18: inside "Device details" on
/// its Turn off card). Values wrap instead of being cut off.
struct PhoneDetailsList: View {
    @EnvironmentObject var model: SetupModel
    let rec: PaxDeviceRecord
    @State private var confirmForget = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
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
            Text(DeviceDetails.setUpChoicesNote)
                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            // v0.8.15 (changeable after set-up): Support ID (with copy) and "Allow verified support release" (kept by the server).
            if let st = model.phoneStatus[rec.id] {
                if let id = st.support_id { SupportIDRow(supportID: id) }
                if let sr = st.support_release {
                    SupportReleaseRow(state: sr, busy: model.busy, trialActive: TrialDay.isActive(st.trial)) {
                        model.setPhoneSupportRelease(rec, $0)
                    }
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
