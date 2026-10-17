// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

/// Mac path (v0.7.0): 1 Choose what to block, 2 Turn-off wait, 3 Lock it in.
/// Every check from v0.6 is still made (password, administrator accounts, a leftover
/// Pax account, FileVault recovery key, backup, profile approval); the technical
/// steps run underneath one progress bar, with the log under "Details".
struct ProtectMacView: View {
    @EnvironmentObject var mac: MacProtectModel
    @EnvironmentObject var model: SetupModel

    private let titles = ["What to block", TurnOffWait.stepTitle, "Lock it in"]

    var body: some View {
        PageColumn {
            if mac.phase == .intro || mac.phase == .checked {
                StepProgress(titles: titles, current: mac.step)
            }
            switch mac.phase {
            case .intro, .checked:
                switch mac.step {
                case 0:
                    ChooseBlocksStep(platform: .mac, choices: $model.choices,
                                     filter: $model.config.dnsFilter) { mac.step = 1 }
                    BackLink { model.startOver() }
                case 1:
                    WaitStep(localMac: mac.isLocal) {
                        if mac.isLocal { mac.step = 2 } else { model.saveWaitAndAccount { mac.step = 2 } }
                    }
                    BackLink { mac.step = 0 }
                default:
                    if mac.phase == .checked { checked } else { lockIn }
                }
            case .running:
                running
            case .approveProfile:
                approve
            case .protected:
                // Home takes over (RootView switches screens); keep something calm here.
                StepHeader(eyebrow: "", title: "You're protected", subtitle: Brand.tagline)
            case .released:
                MacReleasedCard()
            case .removed:
                MacRemovedCard()
            }
        }
        .onAppear { mac.checkAccount() }
    }

    // MARK: Step 3: Lock it in

    private var waitText: String {
        TurnOffWait.duration(days: model.config.waitDays)
    }

    private var summary: some View {
        Card {
            Text("Here's what Pax will do").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
            NoteRow(icon: "checkmark.shield", text: "Block unwanted content in every browser and app on this Mac.")
            if model.choices.adblock { NoteRow(icon: "hand.raised", text: "Block ads and trackers.") }
            NoteRow(icon: "photo", text: AlwaysBlockedMedia.planLine)   // v0.8.13: always
            if model.choices.youtubeRestricted {
                NoteRow(icon: "play.rectangle", text: "Turn on YouTube Restricted Mode.")
            }
            if model.choices.paxMax {
                NoteRow(icon: "eye.slash", text: "Blur pictures and video in Firefox until they look safe (Pax Max). "
                        + "It can sometimes blur ordinary ones too; turning it off later takes 1 hour.")
            }
            if !model.choices.extraSites.isEmpty {
                NoteRow(icon: "nosign", text: "Block your \(model.choices.extraSites.count) "
                        + "site\(model.choices.extraSites.count == 1 ? "" : "s") on this Mac.")
            }
            NoteRow(icon: "hourglass", text: "Set your turn-off wait to \(waitText): if you ask to turn Pax off, or to "
                    + "unblock something, it happens \(waitText) later. You can cancel any time during the wait.")
            NoteRow(icon: "heart", text: TurnOffWait.firstHour)
            NoteRow(icon: "person.crop.circle", text: "Make your account a standard account. Pax keeps the key "
                    + "to undo this until your turn-off wait ends.")
            NoteRow(icon: "lock.open", text: "Private windows still work, and they're filtered too.")
        }
    }

    private var lockIn: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Lock it in", subtitle: "One last look, then one button.")
            summary
            Card {
                Text("Before you start").font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
                CheckRow(isOn: $mac.agreed,
                         text: "I'm 18 or over, this is my Mac, and I understand that turning Pax off takes "
                             + "my turn-off wait (\(waitText)).")
                CheckRow(isOn: $mac.madeBackup, text: "I have a recent backup of this Mac (Time Machine or iCloud).")
                NoteRow(icon: "key", text: "If FileVault is on, keep its recovery key somewhere outside this Mac, "
                        + "or with someone you trust. It's your way back in if anything goes wrong.")
            }
            Card {
                Text("Your Mac password").font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
                SecureField("Password for \(NSUserName())", text: $mac.password)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 340)
                    .onSubmit { if canProtect { mac.checkAndProtect() } }
                Text("Used once to set up the key Pax keeps for you. Never stored.")
                    .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
            }
            if let failure = mac.failure {
                ErrorCard(error: failure, retry: { mac.retry() }, details: { mac.supportDetails(failure) })
            }
            HStack(spacing: 14) {
                Button("Protect my Mac") { mac.checkAndProtect() }
                    .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                    .disabled(!canProtect)
                if mac.busy { ProgressView().controlSize(.small) }
            }
            BackLink { mac.step = 1 }
        }
    }

    private var canProtect: Bool {
        mac.consentComplete && mac.madeBackup && !mac.password.isEmpty && !mac.busy
    }

    /// Preflight passed but something needs the user's eyes: the FileVault recovery
    /// key, a warning (FileVault off, test mode), or v0.8.10's other administrators.
    private var checked: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Your Mac is ready",
                       subtitle: "Just one thing to check before Pax locks it in.")
            if let pre = mac.preflight {
                Card {
                    ForEach(mac.importantWarnings(pre), id: \.self) { w in
                        NoteRow(icon: "exclamationmark.triangle", text: w)
                    }
                    if !pre.otherAdmins.isEmpty {
                        // v0.8.10: one plain OK; Pax does the rest in the background.
                        CheckRow(isOn: $mac.demoteOtherAdmins,
                                 text: "Also make these standard accounts: \(pre.otherAdmins.joined(separator: ", "))")
                        NoteRow(icon: "person.2", text: mac.demoteOtherAdmins
                                ? "They keep their files and can still log in. Removing Pax properly makes them "
                                    + "administrators again."
                                : "While another account is an administrator it could undo Pax, so Pax can't "
                                    + "protect this Mac.")
                    }
                    if pre.fileVaultOn {
                        CheckRow(isOn: $mac.savedRecoveryKey,
                                 text: "I've saved my FileVault recovery key outside this Mac (or given it to "
                                     + "someone I trust).")
                    }
                    CheckRow(isOn: $mac.madeBackup, text: "I have a recent backup of this Mac.")
                }
            }
            if let failure = mac.failure {
                ErrorCard(error: failure, retry: { mac.retry() }, details: { mac.supportDetails(failure) })
            }
            HStack(spacing: 14) {
                Button("Protect my Mac") { mac.protect() }
                    .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                    .disabled(!mac.confirmationsComplete || mac.busy || mac.password.isEmpty)
                Button("Back") { mac.phase = .intro }
                    .buttonStyle(SecondaryButtonStyle())
            }
        }
    }

    private var running: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Protecting your Mac",
                       subtitle: "This takes a minute or two. Keep Pax open. If anything goes wrong, Pax puts "
                           + "everything back.")
            Card {
                FriendlyProgress(fraction: mac.progress.0, status: mac.progress.1, log: mac.log)
            }
        }
    }

    private var approve: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "One thing for you",
                       subtitle: "macOS asks you to approve Pax's settings yourself. System Settings is open.")
            Card {
                InstructionRow(n: 1, text: "Go to General › Device Management (on older macOS: Privacy & "
                               + "Security › Profiles).")
                InstructionRow(n: 2, text: "Double-click “Pax (this Mac)”, click Install, and enter your password.")
                InstructionRow(n: 3, text: "Come back here and click “I've installed it”.")
            }
            Card {
                FriendlyProgress(fraction: mac.progress.0, status: "Waiting for your approval…", log: mac.log)
            }
            HStack(spacing: 14) {
                Button("I've installed it") { mac.profileApproved(true) }
                    .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                Button("Stop and undo") { mac.profileApproved(false) }
                    .buttonStyle(SecondaryButtonStyle())
            }
        }
    }
}

struct InstructionRow: View {
    let n: Int
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(n)")
                .font(Theme.body(12, weight: .semibold))
                .frame(width: 22, height: 22)
                .background(Circle().fill(Theme.secondary))
                .foregroundStyle(Theme.primaryText)
            Text(text)
                .font(Theme.body(14))
                .foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Home cards for this Mac

/// "This Mac": live switches that still make sense after set-up.
struct MacSettingsCard: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        Card {
            HStack {
                Label("This Mac", systemImage: "laptopcomputer").font(Theme.body(15, weight: .semibold))
                    .foregroundStyle(Theme.primaryText)
                Spacer()
            }
            switch mac.adblockSwitch {
            case .guardLive:
                ToggleRow(title: "Ads and trackers",
                          detail: "Switches straight away, for every app and browser. "
                              + "Restricted content stays blocked either way.",
                          isOn: Binding(get: { mac.adblock }, set: { mac.setAdblock($0) }))
            case .server:
                ToggleRow(title: "Ads and trackers", detail: "Switches within a minute, for every app and browser.",
                          isOn: Binding(get: { mac.adblock }, set: { mac.setAdblock($0) }))
            case .setUpOnly:
                NoteRow(icon: "hand.raised",
                        text: "Ads and trackers: \(mac.adblock ? "blocked" : "allowed"), as chosen at set-up. "
                            + "The switch works here once Pax has finished updating.")
            }
            if mac.canSync && mac.sync != nil {
                ToggleRow(title: "Sync blocked sites across devices",
                          detail: ListSyncLinker.detail(mac.sync),
                          isOn: Binding(get: { mac.sync?.enabled ?? true }, set: { mac.setSyncEnabled($0) }))
            }
            if mac.youtubeAvailable {
                ToggleRow(title: "YouTube Restricted Mode",   // v0.8.13: a plain switch again
                          detail: "Hides videos YouTube marks as mature. Switches straight away; "
                              + "SafeSearch and everything else stay on.",
                          isOn: Binding(get: { mac.youtubeRestricted }, set: { mac.setYouTubeRestricted($0) }))
            }
            NoteRow(icon: "info.circle", text: AlwaysBlockedMedia.notice)   // v0.8.13
            NoteRow(icon: mac.paxMax ? "eye.slash" : "eye",
                    text: (mac.paxMax ? "Pax Max is on: images are blurred until they look safe."
                                      : "Pax Max is off.")
                        + (mac.paxMaxView?.switchable == true ? " Change it in Settings › Pax Max."
                                                              : " It's chosen when you set up Pax."))
        }
    }
}

/// "Request a change": turning Pax off on this Mac, with the turn-off wait countdown.
struct MacRequestChangeCard: View {
    @EnvironmentObject var mac: MacProtectModel
    @State private var confirmOff = false
    @State private var showEmergency = false

    var body: some View {
        Card {
            Text("Request a change").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
            if let s = mac.status {
                if s.in_grace_period {
                    NoteRow(icon: "heart", text: TurnOffWait.firstHour + " That's until "
                            + Date(timeIntervalSince1970: TimeInterval(s.grace_until))
                                .formatted(date: .abbreviated, time: .shortened) + ".")
                }
                if let rr = s.removal_request {
                    let cancellable = rr.status == "pending" || rr.status == "notifying"
                    // v0.8.16: "Pax turns off in 2 days 14 h · Cancel".
                    TimelineView(.periodic(from: .now, by: 1)) { ctx in
                        TurnOffCountdownRow(seconds: mac.remaining(at: ctx.date),
                                            cancel: cancellable ? { mac.cancelRemoval() } : nil)
                    }
                    if rr.can_reveal || mac.remaining(at: Date()) == 0 {
                        Button("Turn Pax off on this Mac") { mac.reveal() }
                            .buttonStyle(PrimaryButtonStyle(accent: true))
                    }
                    if rr.status == "notifying" {
                        NoteRow(icon: "envelope", text: "Pax is telling your trusted person first. Your turn-off wait "
                                + "starts once they're told.")
                    }
                } else {
                    Text("Want to turn Pax off on this Mac? Ask here, and it turns off after your turn-off wait. "
                         + "You can cancel any time during the wait.")
                        .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Start the turn-off wait") { confirmOff = true }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(mac.busy)
                    if mac.isLocal {
                        Button("I'm locked out of this Mac") { mac.requestRemoval(reason: "locked_out") }
                            .buttonStyle(.link).font(Theme.body(12))
                        Text("Releases the disk recovery key Pax keeps (and, on Intel Macs, the startup password) "
                             + "after the same turn-off wait.")
                            .font(Theme.body(11.5)).foregroundStyle(Theme.mutedText)
                    }
                }
                if let r = mac.released, r.removal_password == nil {
                    Card {
                        Text("Your turn-off wait is over. To get back in:").font(Theme.body(13, weight: .medium))
                        if let key = r.recovery_key {
                            Text("FileVault recovery key").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                            Text(key).font(.system(size: 15, design: .monospaced)).textSelection(.enabled)
                        }
                        if let fw = r.firmware_password {
                            Text("Startup (firmware) password").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                            Text(fw).font(.system(size: 15, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }
            } else {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Checking…").font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                }
            }
            DisclosureGroup("In an emergency", isExpanded: $showEmergency) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("For a genuine emergency: a short cooling-off instead of your turn-off wait, once every 90 days. "
                         + "Your trusted person is told.")
                        .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    TextField("What's happening?", text: $mac.emergencyReason).textFieldStyle(.roundedBorder)
                    Button("Ask for an emergency release") { mac.emergency() }
                        .buttonStyle(SecondaryButtonStyle())
                        .disabled(mac.emergencyReason.count < 10 || mac.busy)
                    // v0.8.15: a one-time code from Pax support, for this Mac only.
                    Divider().overlay(Theme.border).padding(.vertical, 4)
                    SupportCodeEntry(code: $mac.supportCode, busy: mac.busy,
                                     allowed: mac.status?.support_release?.allowed) { mac.redeemSupportCode() }
                }
                .padding(.top, 6)
            }
            .font(Theme.body(13))
            .foregroundStyle(Theme.mutedText)
        }
        .alert("Start your turn-off wait?", isPresented: $confirmOff) {
            Button("Start the wait", role: .destructive) { mac.requestRemoval() }
            Button("Keep Pax on", role: .cancel) {}
        } message: {
            Text("Pax stays on until your turn-off wait ends. Your trusted person, if you added one, is told. "
                 + "You can cancel any time during the wait.")
        }
    }
}

struct MacReleasedCard: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            StepHeader(eyebrow: "", title: "Your turn-off wait is over",
                       subtitle: "Pax can remove itself from this Mac now. Your trusted person has been told.")
            if let pw = mac.revealedPassword {
                DisclosureGroup("Show the key Pax kept") {
                    Card {
                        Text("Account: \(paxAdminUser)").font(Theme.body(13))
                        Text(pw).font(.system(size: 18, design: .monospaced)).textSelection(.enabled)
                        Text("You only need this to remove Pax by hand (see paxpeace.com).")
                            .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                        if let key = mac.released?.recovery_key {
                            Text("FileVault recovery key (Pax replaced yours)").font(Theme.body(12))
                                .foregroundStyle(Theme.mutedText)
                            Text(key).font(.system(size: 15, design: .monospaced)).textSelection(.enabled)
                        }
                        if let fw = mac.released?.firmware_password {
                            Text("Startup (firmware) password: removed with Pax").font(Theme.body(12))
                                .foregroundStyle(Theme.mutedText)
                            Text(fw).font(.system(size: 15, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                    .padding(.top, 6)
                }
                .font(Theme.body(13))
            }
            if let failure = mac.failure {
                ErrorCard(error: failure, retry: { mac.retry() }, details: { mac.supportDetails(failure) })
            }
            Button("Remove Pax from this Mac") { mac.removePax() }
                .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                .disabled(mac.busy)
            if mac.busy || !mac.log.isEmpty {
                FriendlyProgress(fraction: mac.busy ? 0.5 : 1, status: mac.busy ? "Removing Pax…" : "Done.",
                                 log: mac.log)
            }
        }
    }
}

struct MacRemovedCard: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            StepHeader(eyebrow: "", title: "Pax is removed from this Mac",
                       subtitle: "Your account has full control again. Log out and back in so every app sees it.")
            FriendlyProgress(fraction: 1, status: "Done.", log: mac.log)
        }
    }
}
