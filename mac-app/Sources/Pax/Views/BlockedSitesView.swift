// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import PaxCore

/// "Blocked sites": the user's own blocklist, synced to every device through pax-dns.
/// Adding is instant. Removing waits (default 72 h) and shows a live countdown with Cancel.
/// v0.7.0: calmer layout; exceptions and the remote-desktop switch sit under "More options".
struct BlockedSitesView: View {
    @EnvironmentObject var blocklist: BlocklistModel
    @State private var exceptionSite = ""
    @State private var confirmRemoval: BlockedSite?
    @State private var confirmRemoteDesktopOff = false
    @State private var showMore = false
    @State private var showImport = false
    @EnvironmentObject var model: SetupModel
    @EnvironmentObject var mac: MacProtectModel
    @State private var showAppPicker = false

    /// v0.8.21: the device this page is about (the one picked in the sidebar).
    /// v0.8.27: only a device Pax is still on (server status, as on Home): a turned-off,
    /// retired or not-found phone is skipped, and this Mac once its wait is over or Pax is
    /// removed. With none left the page shows a plain empty state.
    private var subject: BlockedPage.Subject { model.blockedPageSubject(macShown: mac.shownOnBlockedPage) }
    private var phone: PaxDeviceRecord? { model.record(for: subject) }
    private var macIsSubject: Bool { subject == .mac }
    private var deviceName: String? { phone?.name ?? Host.current().localizedName ?? "this Mac" }
    private var reach: BlockedPage.SitesReach {
        BlockedPage.sitesReach(phoneSelected: phone != nil,
                               macLocalList: mac.shownOnBlockedPage && mac.isLocal,
                               macSyncOn: mac.canSync ? mac.sync?.enabled : nil)
    }

    /// v0.8.27: no device left, so no stale lines or lists.
    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(BlockedPage.emptyTitle).font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
            Text(BlockedPage.emptyLine).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 12) {
                Button("Protect this Mac") { model.screen = mac.deviceID != nil ? .home : .mac }
                    .buttonStyle(SecondaryButtonStyle())
                Button("Protect an iPhone or iPad") { model.addPhone() }
                    .buttonStyle(SecondaryButtonStyle())
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius).stroke(Theme.border))
    }

    /// "Blocking on Ruben's MacBook Air", then where sites and apps apply.
    private var scopeCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Image(systemName: phone == nil ? "laptopcomputer" : (phone!.isIPad ? "ipad" : "iphone"))
                    .font(.system(size: 14, weight: .light)).foregroundStyle(Theme.accent)
                Text(BlockedPage.deviceLine(name: deviceName))
                    .font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
            }
            Text(BlockedPage.sitesLine(reach) + " " + BlockedPage.appsLine(phone: phone != nil, isIPad: phone?.isIPad ?? false))
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius).stroke(Theme.border))
    }

    /// v0.8.21: the apps for this device, on the same page as its sites.
    @ViewBuilder private var appsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let rec = phone {
                let names = rec.blockedAppNames ?? []
                SectionTitle("Apps (\(names.count))")
                Text(names.isEmpty ? "No apps chosen at set-up." : DeviceDetails.appList(names))
                    .font(Theme.body(13)).foregroundStyle(names.isEmpty ? Theme.mutedText : Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                Text("These were chosen when this \(rec.isIPad ? "iPad" : "iPhone") was set up. To change them, set it up again.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            } else if macIsSubject, mac.canBlockApps {
                let list = mac.blockedApps?.apps ?? []
                HStack {
                    SectionTitle("Apps (\(list.count))")
                    Spacer()
                    Button("Add") { showAppPicker = true }.buttonStyle(SecondaryButtonStyle()).disabled(mac.busy)
                }
                if list.isEmpty {
                    Text("No apps yet.").font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                } else {
                    MacBlockedAppRows()
                }
            } else if macIsSubject {
                SectionTitle("Apps")
                Text("Blocking apps works when this Mac keeps its own key (Settings › Advanced).")
                    .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .sheet(isPresented: $showAppPicker) {
            MacAppPickerSheet(already: Set(mac.blockedApps?.apps.map(\.bundle_id) ?? [])) { path in
                mac.blockApp(path: path)
            }
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                BackLink(title: AppNav.backToHome) { model.screen = .home }
                if subject == .noDevice {
                    StepHeader(eyebrow: "", title: AppNav.blockedTitle, subtitle: nil)
                    emptyState
                } else {
                    scopeCard   // v0.8.21: which device, and how far its blocks reach
                    StepHeader(eyebrow: "", title: AppNav.blockedTitle,
                               subtitle: blocklist.scopeText + " Removing one takes \(blocklist.delayText), "
                                   + "and you can change your mind until then.")
                    addCard
                    if let notice = blocklist.notice {
                        NoticeBanner(text: notice)
                    }
                    if let error = blocklist.errorMessage {
                        NoticeBanner(text: error, isError: true)
                    }
                    if let failure = blocklist.failure {
                        ErrorCard(error: failure, retry: { blocklist.retry() },
                                  details: { Support.details(failure, log: [], extraRedactions: model.privateNames) })
                    }
                    if !blocklist.pendingRemovals.isEmpty || !blocklist.pendingExceptions.isEmpty {
                        pendingSection
                    }
                    listSection
                    appsSection
                    DisclosureGroup("More options", isExpanded: $showMore) {
                        VStack(alignment: .leading, spacing: 24) {
                            exceptionsSection
                            if blocklist.remoteDesktop != nil {
                                categoriesSection
                            }
                        }
                        .padding(.top, 10)
                    }
                    .font(Theme.body(13))
                }
            }
            .padding(.horizontal, 36)
            .padding(.top, 12)
            .padding(.bottom, 40)
            .frame(maxWidth: 680, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .onAppear {
            blocklist.refresh()
            // v0.8.27: the same quiet server refresh as Home, so turned-off phones drop out here too.
            if mac.deviceID != nil { mac.refresh() }
            Task { await model.refreshPhones(quiet: true) }
        }
        .onChange(of: subject) { _ in blocklist.refresh() }   // its list follows the device (guard or account)
        .alert(item: $confirmRemoval) { site in
            Alert(title: Text("Remove \(site.display_domain)?"),
                  message: Text("It stays blocked for \(blocklist.delayText). Your trusted person, "
                                + "if you have one, will be told. You can cancel any time before then."),
                  primaryButton: .destructive(Text("Start \(blocklist.delayText) wait")) {
                      blocklist.requestRemoval(site)
                  },
                  secondaryButton: .cancel(Text("Keep it blocked")))
        }
    }

    /// v0.5: always-on bypass category + the remote-desktop switch (off waits).
    private var categoriesSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle("Always blocked")
            Card {
                Text("Cloud PCs, remote browsers and web proxies")
                    .font(Theme.body(14, weight: .semibold)).foregroundStyle(Theme.primaryText)
                Text("Services that run a computer or browser somewhere else, where Pax can't filter. "
                     + "Always on.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            }
            if let rd = blocklist.remoteDesktop {
                Card {
                    Toggle(isOn: Binding(
                        get: { rd.enabled },
                        set: { on in
                            if on { blocklist.setRemoteDesktop(blocked: true) } else { confirmRemoteDesktopOff = true }
                        })) {
                        Text("Block remote desktop and work virtual desktops")
                            .font(Theme.body(14, weight: .semibold)).foregroundStyle(Theme.primaryText)
                    }
                    .disabled(blocklist.busy || rd.pending != nil)
                    Text("Chrome Remote Desktop, AnyDesk, TeamViewer, Parsec, RustDesk, Splashtop, Windows 365, "
                         + "Amazon WorkSpaces and similar. Turning this off takes \(blocklist.delayText); "
                         + "turning it back on is instant.")
                        .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    if let r = rd.pending {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            PendingRow(title: "Stop blocking remote desktop",
                                       remaining: blocklist.remainingCategory(r, at: context.date)) {
                                blocklist.cancelCategoryRequest(r)
                            }
                        }
                    }
                }
            }
        }
        .alert(isPresented: $confirmRemoteDesktopOff) {
            Alert(title: Text("Stop blocking remote desktop?"),
                  message: Text("Remote desktop stays blocked for \(blocklist.delayText). Your trusted "
                                + "person, if you have one, will be told. You can cancel any time before then."),
                  primaryButton: .destructive(Text("Start \(blocklist.delayText) wait")) {
                      blocklist.setRemoteDesktop(blocked: false)
                  },
                  secondaryButton: .cancel(Text("Keep it blocked")))
        }
    }

    private var addCard: some View {
        Card {
            Text("Add a site").font(Theme.body(14, weight: .semibold)).foregroundStyle(Theme.primaryText)
            HStack(spacing: 12) {
                TextField("example.com", text: $blocklist.newSite)
                    .textFieldStyle(.roundedBorder)
                    .font(Theme.body(14))
                    .onSubmit { blocklist.add() }
                Button("Block now") { blocklist.add() }
                    .buttonStyle(PrimaryButtonStyle(accent: true))
                    .disabled(blocklist.normalisedNewSite == nil || blocklist.busy)
            }
            Text("Covers every subdomain too: blocking example.com also blocks www.example.com and "
                 + "m.example.com. Takes effect straight away.")
                .font(Theme.body(12))
                .foregroundStyle(Theme.mutedText)
            HStack(spacing: 12) {
                Button("Import list…") { showImport = true }
                    .buttonStyle(SecondaryButtonStyle())
                    .disabled(blocklist.busy)
                if blocklist.importTotal > 0 {
                    ProgressView(value: Double(blocklist.importDone), total: Double(max(1, blocklist.importTotal)))
                        .tint(Theme.accent)
                        .frame(maxWidth: 200)
                    Text("\(blocklist.importDone) of \(blocklist.importTotal)")
                        .font(Theme.body(12).monospacedDigit()).foregroundStyle(Theme.mutedText)
                }
            }
            .sheet(isPresented: $showImport) {
                ImportListSheet(alreadyBlocked: blocklist.blockedDomains, cap: blocklist.importCap,
                                forIPhoneProfile: false) { sites, skipped in
                    blocklist.importSites(sites, skipped: skipped)
                }
            }
        }
    }

    private var pendingSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle("Waiting")
            TimelineView(.periodic(from: .now, by: 1)) { context in
                VStack(spacing: 8) {
                    ForEach(blocklist.pendingRemovals) { r in
                        PendingRow(title: "Remove \(r.display_domain ?? r.domain ?? "")",
                                   remaining: blocklist.remaining(r, at: context.date)) { blocklist.cancel(r) }
                    }
                    ForEach(blocklist.pendingExceptions) { r in
                        PendingRow(title: "Allow \(r.display_domain ?? r.domain ?? "")",
                                   remaining: blocklist.remaining(r, at: context.date)) { blocklist.cancel(r) }
                    }
                }
            }
        }
    }

    private var listSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle("Blocked (\(blocklist.blocked.count))")
            if blocklist.blocked.isEmpty {
                Text("No sites yet. Explicit content is already blocked; add anything else that pulls you in.")
                    .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            } else {
                VStack(spacing: 0) {
                    ForEach(blocklist.blocked) { site in
                        HStack {
                            Text(site.display_domain).font(Theme.body(14)).foregroundStyle(Theme.primaryText)
                            Spacer()
                            if site.pending_removal != nil {
                                Text("Removal pending").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                            } else {
                                Button("Remove") { confirmRemoval = site }
                                    .buttonStyle(SecondaryButtonStyle())
                                    .disabled(blocklist.busy)
                            }
                        }
                        .padding(.vertical, 10)
                        .padding(.horizontal, 14)
                        Divider().overlay(Theme.border)
                    }
                }
                .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card))
                .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius).stroke(Theme.border))
            }
        }
    }

    private var exceptionsSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionTitle("Exceptions")
            Text("If Pax blocks a site you need, you can ask for an exception. Like a removal, "
                 + "it takes \(blocklist.delayText). Removing an exception is instant. Some categories, "
                 + "such as explicit content, media converters and remote AI browsers, can't be excepted.")
                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 12) {
                TextField("site the filter blocks", text: $exceptionSite)
                    .textFieldStyle(.roundedBorder)
                    .font(Theme.body(14))
                Button("Ask for exception") {
                    blocklist.requestException(exceptionSite)
                    exceptionSite = ""
                }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(DomainInput.normalise(exceptionSite) == nil || blocklist.busy)
            }
            ForEach(blocklist.allowed) { site in
                HStack {
                    Text(site.display_domain).font(Theme.body(14)).foregroundStyle(Theme.primaryText)
                    Spacer()
                    Button("Remove exception") { blocklist.removeException(site) }
                        .buttonStyle(SecondaryButtonStyle())
                }
            }
        }
    }
}

private struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }

    var body: some View {
        Text(text.uppercased())
            .font(Theme.body(11, weight: .semibold))
            .tracking(1.2)
            .foregroundStyle(Theme.mutedText)
    }
}

private struct PendingRow: View {
    let title: String
    let remaining: Int
    let cancel: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "hourglass").foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
                Text(remaining > 0 ? "Takes effect in \(Countdown.string(seconds: remaining))" : "Taking effect…")
                    .font(Theme.body(12).monospacedDigit())
                    .foregroundStyle(Theme.mutedText)
            }
            Spacer()
            Button("Cancel", action: cancel)
                .buttonStyle(PrimaryButtonStyle())
                .disabled(remaining == 0)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.accent.opacity(0.06)))
        .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius).stroke(Theme.accent.opacity(0.3)))
    }
}

private struct NoticeBanner: View {
    let text: String
    var isError = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: isError ? "exclamationmark.circle" : "checkmark.circle")
                .foregroundStyle(isError ? Theme.warning : Theme.primaryText)
            Text(text).font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.section))
        .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius).stroke(Theme.border))
    }
}
