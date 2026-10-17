// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import AppKit
import PaxCore

// v0.8.7: the user's own blocked apps.

/// iPhone set-up ("Choose what to block"): the apps chosen so far and the picker.
struct IPhoneAppsCard: View {
    @EnvironmentObject var model: SetupModel
    @Binding var choices: BlockChoices
    @State private var showPicker = false

    var body: some View {
        Card {
            Text("Apps (optional)").font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
            Text("Pick apps on this iPhone to block, or type an app's ID. They're chosen now, at set-up: "
                 + "to change the list later you set the iPhone up again.")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            if !choices.blockedApps.isEmpty {
                Text(choices.blockedApps.map { choices.blockedAppNames[$0] ?? $0 }.joined(separator: ", "))
                    .font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                    .lineLimit(3)
            }
            Button(choices.blockedApps.isEmpty ? "Choose apps…" : "Change apps (\(choices.blockedApps.count))…") {
                showPicker = true
            }
            .buttonStyle(SecondaryButtonStyle())
        }
        .sheet(isPresented: $showPicker) {
            IPhoneAppPickerSheet(choices: $choices)
                .environmentObject(model)
        }
    }
}

struct IPhoneAppPickerSheet: View {
    @EnvironmentObject var model: SetupModel
    @Environment(\.dismiss) private var dismiss
    @Binding var choices: BlockChoices
    @State private var list: IPhoneAppList?
    @State private var loading = false
    @State private var loadError: String?
    @State private var query = ""
    @State private var typed = ""
    @State private var typedProblem: String?

    private var paxBlocked: [String] { list?.paxBlocked ?? [] }
    private var cap: Int { list?.maxCustom ?? AppBlockRules.maxCustomIPhoneApps }
    private var count: Int { AppBlockRules.customCount(choices.blockedApps, paxBlocked: paxBlocked) }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Block apps on this iPhone").font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            NoteRow(icon: "lock", text: "Chosen at set-up only. Once the iPhone is protected, this list stays "
                    + "as it is until you set the iPhone up again. Apple's own apps and password managers "
                    + "can't be blocked.")
            TextField("Search apps", text: $query).textFieldStyle(.roundedBorder)
            Group {
                if loading {
                    ProgressView("Reading the apps on the iPhone…").frame(maxWidth: .infinity, minHeight: 200)
                } else if let list {
                    List(list.filtered(query)) { app in row(app) }
                        .frame(minHeight: 280)
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(loadError ?? (model.canListIPhoneApps
                             ? "Pax can list this iPhone's apps."
                             : "Plug in and unlock the iPhone to see its apps, or type an app's ID below."))
                            .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                        if model.canListIPhoneApps {
                            Button("Show the iPhone's apps") { load() }.buttonStyle(SecondaryButtonStyle())
                        }
                    }
                    .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
                }
            }
            HStack {
                TextField("Or type an app ID, for example com.example.app", text: $typed)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(addTyped)
                Button("Add", action: addTyped).buttonStyle(SecondaryButtonStyle())
                    .disabled(typed.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if let typedProblem {
                Text(typedProblem).font(Theme.body(12.5)).foregroundStyle(Theme.warning)
            }
            HStack {
                Text("\(count) of \(cap) chosen").font(Theme.body(12.5)).foregroundStyle(
                    count > cap ? Theme.warning : Theme.mutedText)
                Spacer()
                Button("Done") { dismiss() }.buttonStyle(PrimaryButtonStyle(accent: true))
                    .disabled(count > cap)
            }
        }
        .padding(24)
        .frame(width: 560, height: 620)
        .onAppear { if list == nil && model.canListIPhoneApps { load() } }
    }

    @ViewBuilder private func row(_ app: IPhoneApp) -> some View {
        HStack(spacing: 10) {
            if let path = app.iconPath, let img = NSImage(contentsOfFile: path) {
                Image(nsImage: img).resizable().frame(width: 28, height: 28).clipShape(RoundedRectangle(cornerRadius: 6))
            } else {
                RoundedRectangle(cornerRadius: 6).fill(Theme.border).frame(width: 28, height: 28)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(app.name).font(Theme.body(13.5)).foregroundStyle(Theme.primaryText)
                Text(app.paxBlocks ? "Pax blocks this anyway" : (app.canBlock ? app.bundleID : "Can't be blocked: \(app.whyNot)"))
                    .font(Theme.body(11.5)).foregroundStyle(Theme.mutedText)
            }
            Spacer()
            if app.paxBlocks {
                Image(systemName: "checkmark.shield").foregroundStyle(Theme.mutedText)
            } else if app.canBlock {
                Toggle("", isOn: Binding(get: { choices.blockedApps.contains(app.bundleID) },
                                         set: { _ in choices.toggleApp(app.bundleID, name: app.name) }))
                    .labelsHidden()
                    .disabled(!choices.blockedApps.contains(app.bundleID) && count >= cap)
            }
        }
    }

    private func load() {
        loading = true
        loadError = nil
        Task { @MainActor in
            do {
                list = try await model.loadIPhoneApps()
            } catch {
                let coded = PaxErrorClassifier.classify(error)
                loadError = "\(coded.info.message) (\(coded.code))"
            }
            loading = false
        }
    }

    private func addTyped() {
        switch AppBlockRules.checkTyped(typed) {
        case .success(let bid):
            if paxBlocked.contains(where: { $0.caseInsensitiveCompare(bid) == .orderedSame }) {
                typedProblem = "Pax blocks that app anyway."
            } else if choices.blockedApps.contains(bid) {
                typedProblem = nil
            } else if count >= cap {
                typedProblem = "You've chosen the most Pax allows (\(cap))."
            } else {
                choices.toggleApp(bid, name: list?.apps.first { $0.bundleID == bid }?.name ?? bid)
                typedProblem = nil
            }
            typed = ""
        case .failure(let problem):
            typedProblem = problem.message
        }
    }
}

/// This Mac's page: Blocked apps (pax-guard keeps and enforces them).
struct MacBlockedAppsCard: View {
    @EnvironmentObject var mac: MacProtectModel
    @State private var showPicker = false

    var body: some View {
        Card {
            HStack {
                Text("Blocked apps").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
                Spacer()
                if mac.canBlockApps {
                    Button("Add app…") { showPicker = true }.buttonStyle(SecondaryButtonStyle())
                }
            }
            if !mac.canBlockApps {
                NoteRow(icon: "info.circle", text: "Blocked apps work when this Mac keeps its own key "
                        + "(Settings › Advanced).")
            } else if let view = mac.blockedApps, !view.apps.isEmpty {
                ForEach(view.apps) { app in
                    HStack {
                        Text(app.name).font(Theme.body(14)).foregroundStyle(Theme.primaryText)
                        Spacer()
                        if let r = app.pending_removal {
                            Text(r.status == "notifying" ? "Telling your partner first"
                                 : "Unblocks in \(Self.duration(r.seconds_remaining))")
                                .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                            Button("Cancel") { mac.cancelAppRequest(r.request_id) }.buttonStyle(.link)
                        } else {
                            Button("Unblock…") { mac.unblockApp(app.bundle_id) }.buttonStyle(.link)
                        }
                    }
                }
                Text("Blocking is instant. Unblocking takes your turn-off wait, and your partner is told first.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            } else {
                Text("No apps yet. A blocked app is closed and put away, even if it's renamed or copied.")
                    .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
            }
        }
        .sheet(isPresented: $showPicker) {
            MacAppPickerSheet(already: Set(mac.blockedApps?.apps.map(\.bundle_id) ?? [])) { path in
                mac.blockApp(path: path)
            }
        }
    }

    static func duration(_ seconds: Int) -> String {
        if seconds >= 86_400 { return "\(seconds / 86_400) d \((seconds % 86_400) / 3600) h" }
        if seconds >= 3600 { return "\(seconds / 3600) h \((seconds % 3600) / 60) min" }
        return "\(max(1, seconds / 60)) min"
    }
}

struct MacAppPickerSheet: View {
    let already: Set<String>
    let onPick: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var apps: [InstalledMacApp] = []
    @State private var query = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Block an app").font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            Text("Pax closes it straight away and keeps it closed. Pax itself, Apple's apps and password "
                 + "managers can't be blocked.")
                .font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Search Applications", text: $query).textFieldStyle(.roundedBorder)
            List(filtered) { app in
                HStack(spacing: 10) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                        .resizable().frame(width: 26, height: 26)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(app.name).font(Theme.body(13.5)).foregroundStyle(Theme.primaryText)
                        if let why = app.whyNot {
                            Text("Can't be blocked: \(why)").font(Theme.body(11.5)).foregroundStyle(Theme.mutedText)
                        }
                    }
                    Spacer()
                    if already.contains(app.bundleID) {
                        Text("Blocked").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    } else if app.whyNot == nil {
                        Button("Block") { onPick(app.path); dismiss() }.buttonStyle(SecondaryButtonStyle())
                    }
                }
            }
            .frame(minHeight: 320)
            HStack { Spacer(); Button("Close") { dismiss() }.buttonStyle(SecondaryButtonStyle()) }
        }
        .padding(24)
        .frame(width: 520, height: 560)
        .onAppear { apps = MacAppScanner.installedApps() }
    }

    private var filtered: [InstalledMacApp] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return q.isEmpty ? apps : apps.filter { $0.name.lowercased().contains(q) || $0.bundleID.lowercased().contains(q) }
    }
}
