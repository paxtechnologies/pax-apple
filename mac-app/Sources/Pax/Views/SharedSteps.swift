// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

enum PaxPlatform { case mac, iphone }

/// A centred, scrolling column with generous spacing, used by every screen.
struct PageColumn<Content: View>: View {
    var maxWidth: CGFloat = 640
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) { content }
                .padding(.horizontal, 36)
                .padding(.top, 12)
                .padding(.bottom, 40)
                .frame(maxWidth: maxWidth, alignment: .leading)
                .frame(maxWidth: .infinity)
        }
    }
}

/// "Choose what to block" (Mac step 1, iPhone step 2).
struct ChooseBlocksStep: View {
    let platform: PaxPlatform
    @Binding var choices: BlockChoices
    @Binding var filter: DNSFilter
    let onContinue: () -> Void
    @State private var showAdvanced = false
    @State private var showImport = false

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            StepHeader(eyebrow: "", title: "Choose what to block",
                       subtitle: "Sensible choices are already made. Change anything you like.")
            Card {
                ToggleRow(title: "Restricted content", detail: "Sites Pax always blocks, in every browser and app.",
                          isOn: .constant(true), locked: true)
                Divider().overlay(Theme.border)
                if platform == .mac {
                    ToggleRow(title: "Ads and trackers",
                              detail: "Fewer distractions and less tracking, across the whole Mac.",
                              isOn: $choices.adblock)
                    Divider().overlay(Theme.border)
                }
                // v0.8.13: YouTube Restricted Mode is a plain switch again (its rules unchanged).
                ToggleRow(title: "YouTube Restricted Mode",
                          detail: platform == .mac
                              ? "Hides videos YouTube marks as mature. You can switch it in Settings any time."
                              : "Hides videos YouTube marks as mature. On iPhone this stays as chosen "
                                  + "until Pax is set up again.",
                          isOn: $choices.youtubeRestricted)
                Divider().overlay(Theme.border)
                // v0.8.13: no switch. Shown before anything is locked so it's known up front.
                NoteRow(icon: "info.circle", text: AlwaysBlockedMedia.notice)
                    .padding(.vertical, 4)
                if platform == .mac {
                    Divider().overlay(Theme.border)
                    ToggleRow(title: PaxMax.title,
                              detail: PaxMax.setUpDetail,     // v0.8.12: what it does, and that it isn't perfect
                              isOn: $choices.paxMax)
                }
            }
            if platform == .iphone {
                NoteRow(icon: "info.circle", text: "Ad blocking and Pax Max work on the Mac for now.")
                IPhoneAppsCard(choices: $choices)       // v0.8.7
            }
            Card {
                Text("Your own sites (optional)").font(Theme.body(15, weight: .medium))
                    .foregroundStyle(Theme.primaryText)
                GrowingTextField("For example: reddit.com, example.com", text: $choices.extraSitesText)
                    .textFieldStyle(.roundedBorder)
                    .font(Theme.body(14))
                Text("Anything that pulls you in. Unblocking one later takes your turn-off wait.")
                    .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
                if !choices.unreadableSites.isEmpty {
                    Text("Pax can't read \(choices.unreadableSites.prefix(5).joined(separator: ", ")) as a website.")
                        .font(Theme.body(12.5)).foregroundStyle(Theme.warning)
                }
                HStack(spacing: 12) {
                    Button("Import list…") { showImport = true }.buttonStyle(SecondaryButtonStyle())
                    if !choices.extraSites.isEmpty {
                        Text("\(choices.extraSites.count) site\(choices.extraSites.count == 1 ? "" : "s")")
                            .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    }
                }
                if platform == .iphone && choices.extraSites.count > BulkSiteImport.iosCustomLimit {
                    Text("Your iPhone's own web filter keeps the first \(BulkSiteImport.iosCustomLimit). The rest "
                         + "are still blocked through Pax's filter once it's running.")
                        .font(Theme.body(12.5)).foregroundStyle(Theme.accent)
                }
            }
            .sheet(isPresented: $showImport) {
                ImportListSheet(alreadyBlocked: Set(choices.extraSites), cap: BulkSiteImport.maxPerImport,
                                forIPhoneProfile: platform == .iphone) { sites, _ in
                    let joined = sites.joined(separator: "\n")
                    choices.extraSitesText += (choices.extraSitesText.isEmpty ? "" : "\n") + joined
                }
            }
            DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
                Picker("Filter strength", selection: $filter) {
                    Text("Family (recommended): restricted content, proxies and VPN sites, Reddit; safe search on")
                        .tag(DNSFilter.family)
                    Text("Core: restricted content only; Reddit and VPN sites stay reachable")
                        .tag(DNSFilter.core)
                }
                .pickerStyle(.radioGroup)
                .font(Theme.body(13))
                .padding(.top, 8)
            }
            .font(Theme.body(13))
            .foregroundStyle(Theme.mutedText)
            Button("Continue", action: onContinue)
                .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
        }
    }
}

/// "How long should turning Pax off take?", the turn-off wait (Mac step 2, iPhone step 3), plus the account email the
/// first time (Pax writes only when someone asks to change or turn off Pax).
struct WaitStep: View {
    @EnvironmentObject var model: SetupModel
    /// v0.8.0: a Mac on local escrow needs no account email (nothing goes to a server).
    var localMac: Bool = false
    let onContinue: () -> Void
    @State private var showAdvanced = false
    @State private var partner = ""

    /// v0.8.9: only waits the path in use accepts (a Mac's own key: 24 h to 365 days;
    /// the server: what its /v1/health says).
    private var limits: WaitLimits { localMac ? .standard : model.waitLimits }

    private var canContinue: Bool {
        !model.busy && (localMac || model.hasAccount || model.emailLooksValid)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            // v0.8.16: says what the wait is for, in plain words.
            StepHeader(eyebrow: "", title: TurnOffWait.setupTitle, subtitle: TurnOffWait.setupHelp)
            HStack(spacing: 14) {
                ForEach(WaitChoice.allCases.filter { limits.allows(days: $0.rawValue) }) { choice in
                    ChoiceCard(icon: choice == .day ? "sunrise" : choice == .threeDays ? "moon.stars" : "calendar",
                               title: choice.title,
                               detail: choice == .threeDays ? "Recommended" : " ",
                               selected: model.config.waitDays == choice.rawValue) {
                        model.config.waitDays = choice.rawValue
                    }
                }
            }
            Text(TurnOffWait.setupAlsoApplies)
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
                VStack(alignment: .leading, spacing: 10) {
                    Stepper(value: $model.config.waitDays, in: limits.dayRange) {
                        Text("Custom: \(model.config.waitDays) day\(model.config.waitDays == 1 ? "" : "s")")
                            .font(Theme.body(13, weight: .medium)).foregroundStyle(Theme.primaryText)
                    }
                    .frame(maxWidth: 280)
                    Text("You can make it longer any time. Making it shorter only counts once your current "
                         + "turn-off wait has passed.")
                        .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                }
                .padding(.top, 8)
            }
            .font(Theme.body(13))
            .foregroundStyle(Theme.mutedText)
            Card {
                if !model.hasAccount && !localMac {
                    Text("Your email").font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
                    TextField("you@example.com", text: $model.config.email)
                        .textFieldStyle(.roundedBorder).font(Theme.body(14))
                    Text("Pax writes only when someone asks to change or turn off Pax. Nothing else.")
                        .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                    if let sentTo = model.signInCodeSentTo {
                        Text("\(sentTo) already has a Pax account. We emailed it a code: enter it to use the "
                             + "same account, so your devices share one list.")
                            .font(Theme.body(12.5)).foregroundStyle(Theme.primaryText)
                            .fixedSize(horizontal: false, vertical: true)
                        TextField("6-digit code", text: $model.signInCode)
                            .textFieldStyle(.roundedBorder).font(Theme.body(14)).frame(maxWidth: 200)
                    }
                    Divider().overlay(Theme.border)
                }
                Text("Someone you trust (optional)").font(Theme.body(15, weight: .medium))
                    .foregroundStyle(Theme.primaryText)
                TextField("friend@example.com", text: $partner)
                    .textFieldStyle(.roundedBorder).font(Theme.body(14))
                Text(localMac
                     ? "They're told if you ask to turn Pax off. After set-up, choose how Pax sends that email "
                       + "in Settings › Accountability partner email. With no one here, everything stays on this Mac."
                     : "They're told if you ask to turn Pax off. They never have to approve anything.")
                    .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // v0.8.18: the trial day (replaces "For your first hour…") and a clear, ticked-by-default
            // choice for verified support release (it was a switch). Changeable later in Settings.
            NoteRow(icon: "sun.max", text: TrialDay.setUpLine)
            Card {
                CheckRow(isOn: $model.config.supportRelease, text: VerifiedSupportRelease.setUpCheckbox)
                Text(VerifiedSupportRelease.setUpDetail)
                    .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.leading, 22)
            }
            if let failure = model.failure {
                ErrorCard(error: failure, retry: { model.retry() },
                          details: { model.supportDetails(failure) })
            }
            HStack(spacing: 14) {
                Button("Continue") {
                    model.config.partnerEmail = partner.isEmpty ? nil : partner
                    onContinue()
                }
                .buttonStyle(PrimaryButtonStyle(accent: true, large: true))
                .disabled(!canContinue)
                if model.busy { ProgressView().controlSize(.small) }
            }
        }
        .onAppear {
            partner = model.config.partnerEmail ?? ""
            if localMac {
                model.config.waitDays = WaitLimits.standard.clamp(days: model.config.waitDays)
            } else {
                model.loadWaitLimits()
            }
        }
    }
}

/// "Back" link used under the step content.
struct BackLink: View {
    var title: String = "Back"
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Label(title, systemImage: "chevron.left").font(Theme.body(13))
        }
        .buttonStyle(.plain)
        .foregroundStyle(Theme.mutedText)
    }
}

/// Crisis lines, shown quietly on Done and Home.
struct CrisisLines: View {
    var body: some View {
        Text("If you're ever struggling: Samaritans (UK & Ireland) 116 123 · 988 Suicide & Crisis Lifeline "
             + "(US): call or text 988")
            .font(Theme.body(11.5)).foregroundStyle(Theme.mutedText)
            .fixedSize(horizontal: false, vertical: true)
    }
}
