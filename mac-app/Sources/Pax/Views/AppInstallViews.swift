// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import AppKit
import UniformTypeIdentifiers
import PaxCore

// v0.8.33: Settings › Updates › "Install or update an app". pax-guard (root) checks and
// installs; this screen only hands it a path and shows what happened.

/// The row inside the Updates card.
struct AppInstallRow: View {
    @EnvironmentObject var mac: MacProtectModel
    @EnvironmentObject var updates: AppUpdatesModel
    @State private var open = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(AppInstallText.rowTitle).font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
                Text(AppInstallText.rowLine).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button(AppInstallText.open) { open = true }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(mac.deviceID == nil)
        }
        .sheet(isPresented: $open) { AppInstallSheet() }
        // v0.8.34: "Open Pax" from the panel beside macOS's administrator dialog lands here.
        .onReceive(updates.$installerRequested) { requested in
            guard requested else { return }
            DispatchQueue.main.async {
                updates.installerRequested = false
                if mac.deviceID != nil && updates.pending == nil { open = true }
            }
        }
    }
}

struct AppInstallSheet: View {
    @Environment(\.dismiss) private var dismiss
    private let client = GuardClient()
    @State private var job: GuardClient.InstallJob?
    @State private var lastPath: String?
    @State private var failure: PaxError?
    @State private var targeted = false
    @State private var downloaded: [GuardClient.DownloadedUpdate] = []
    @State private var system: GuardClient.SystemUpdates?
    @State private var systemFailure: PaxError?

    private var working: Bool { job?.isWorking == true }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text(AppInstallText.sheetTitle).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
                dropZone
                jobView
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(AppInstallText.rules, id: \.self) { NoteRow(icon: "checkmark.shield", text: $0) }
                }
                if !downloaded.isEmpty { downloadedView }
                Divider().overlay(Theme.border)
                systemView
                HStack { Spacer(); Button(AppInstallText.close) { dismiss() }.buttonStyle(PrimaryButtonStyle()) }
            }
            .padding(24)
        }
        .frame(width: 560, height: 640)
        .task {
            job = try? await client.installStatus()
            if job?.isWorking == true { await follow() } else { job = nil }
            downloaded = (try? await client.downloadedUpdates()) ?? []
            system = try? await client.systemUpdates()
        }
    }

    // MARK: drop target

    private var dropZone: some View {
        VStack(spacing: 10) {
            Image(systemName: "square.and.arrow.down").font(.system(size: 28)).foregroundStyle(Theme.mutedText)
            Text(AppInstallText.dropHint).font(Theme.body(14)).foregroundStyle(Theme.primaryText)
            Button(AppInstallText.choose, action: pick).buttonStyle(SecondaryButtonStyle()).disabled(working)
        }
        .frame(maxWidth: .infinity, minHeight: 150)
        .background(RoundedRectangle(cornerRadius: Theme.smallRadius)
            .fill(targeted ? Theme.accent.opacity(0.08) : Theme.card))
        .overlay(RoundedRectangle(cornerRadius: Theme.smallRadius)
            .stroke(targeted ? Theme.accent : Theme.border, style: StrokeStyle(lineWidth: 1.5, dash: [6, 4])))
        .onDrop(of: [UTType.fileURL], isTargeted: $targeted) { providers in
            guard !working, let p = providers.first else { return false }
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                guard let url, AppInstallRules.isInstallable(url) else { return }
                Task { @MainActor in start(url.path) }
            }
            return true
        }
    }

    private func pick() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false
        var types: [UTType] = [.applicationBundle, .diskImage]
        if let pkg = UTType("com.apple.installer-package-archive") { types.append(pkg) }
        panel.allowedContentTypes = types
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        if panel.runModal() == .OK, let url = panel.url, AppInstallRules.isInstallable(url) {
            start(url.path)
        }
    }

    // MARK: the job

    @ViewBuilder private var jobView: some View {
        if let failure {
            ErrorCard(error: failure, retry: nil, details: { Support.details(failure, log: []) })
        } else if let job {
            if job.isWorking {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(AppInstallText.step(job.step)).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                }
            } else if job.succeeded {
                NoteRow(icon: "checkmark.circle", text: AppInstallText.done(job))
            } else if job.code == "PAX-MAC-025", let options = job.options, !options.isEmpty, let path = lastPath {
                VStack(alignment: .leading, spacing: 8) {
                    Text(AppInstallText.chooseOne).font(Theme.body(13, weight: .medium)).foregroundStyle(Theme.primaryText)
                    ForEach(options, id: \.self) { name in
                        Button(name) { start(path, choice: name) }.buttonStyle(.link)
                    }
                }
            } else {
                let p = AppInstallText.problem(job)
                VStack(alignment: .leading, spacing: 6) {
                    if job.code == "PAX-MAC-021" {
                        Text(p.message).font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    ErrorCard(error: PaxError(p.code, technical: job.error ?? ""), retry: nil,
                              details: { Support.details(PaxError(p.code, technical: job.error ?? ""), log: []) })
                }
            }
        }
    }

    private func start(_ path: String, choice: String? = nil, updateOnly: Bool = false) {
        failure = nil
        lastPath = path
        Task {
            do {
                job = try await client.startInstall(path: path, choice: choice, updateOnly: updateOnly)
                await follow()
                downloaded = (try? await client.downloadedUpdates()) ?? downloaded
            } catch {
                failure = PaxErrorClassifier.classify(error)
            }
        }
    }

    /// Polls pax-guard once a second until the job finishes (copying a large app takes a while).
    private func follow() async {
        while job?.isWorking == true {
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            if let j = try? await client.installStatus() { job = j }
        }
    }

    // MARK: updates the apps downloaded themselves

    private var downloadedView: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(AppInstallText.downloadedTitle).font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
            Text(AppInstallText.downloadedLine).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
            ForEach(downloaded) { u in
                HStack {
                    Text("\(u.name) \(u.version)").font(Theme.body(13.5)).foregroundStyle(Theme.primaryText)
                    Text("you have \(u.installed_version)").font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    Spacer()
                    Button(AppInstallText.installButton) { start(u.path, updateOnly: true) }
                        .buttonStyle(SecondaryButtonStyle()).disabled(working)
                }
            }
        }
    }

    // MARK: Apple software updates

    private var systemView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(AppInstallText.systemTitle).font(Theme.body(15, weight: .medium))
                        .foregroundStyle(Theme.primaryText)
                    Text(AppInstallText.systemLine).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Button(AppInstallText.systemCheck) { checkSystem() }
                    .buttonStyle(SecondaryButtonStyle()).disabled(system?.isBusy == true)
            }
            if let systemFailure {
                ErrorCard(error: systemFailure, retry: nil, details: { Support.details(systemFailure, log: []) })
            }
            if let s = system {
                if s.state == "checking" {
                    HStack(spacing: 10) { ProgressView().controlSize(.small); Text(AppInstallText.systemChecking) }
                        .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                } else if s.state == "installing" {
                    HStack(spacing: 10) { ProgressView().controlSize(.small); Text(AppInstallText.systemInstalling) }
                        .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                }
                if let code = s.code, !s.isBusy {
                    ErrorCard(error: PaxError(code, technical: s.error ?? ""), retry: nil,
                              details: { Support.details(PaxError(code, technical: s.error ?? ""), log: []) })
                }
                if s.checked_at != nil && (s.updates ?? []).isEmpty && !s.isBusy && s.code == nil {
                    NoteRow(icon: "checkmark.circle", text: AppInstallText.systemNone)
                }
                ForEach(s.updates ?? []) { u in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(u.title).font(Theme.body(13.5)).foregroundStyle(Theme.primaryText)
                            let line = AppInstallText.systemRow(u)
                            if !line.isEmpty {
                                Text(line).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                            }
                        }
                        Spacer()
                        Button(AppInstallText.installButton) { installSystem(u.label) }
                            .buttonStyle(SecondaryButtonStyle()).disabled(s.isBusy)
                    }
                }
                if s.restart_needed == true {
                    NoteRow(icon: "arrow.clockwise", text: AppInstallText.systemRestart)
                }
            }
        }
    }

    private func checkSystem() {
        systemFailure = nil
        Task {
            do {
                system = try await client.checkSystemUpdates()
                await followSystem()
            } catch { systemFailure = PaxErrorClassifier.classify(error) }
        }
    }

    private func installSystem(_ label: String) {
        systemFailure = nil
        Task {
            do {
                system = try await client.installSystemUpdate(label: label)
                await followSystem()
            } catch { systemFailure = PaxErrorClassifier.classify(error) }
        }
    }

    private func followSystem() async {
        while system?.isBusy == true {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if let s = try? await client.systemUpdates() { system = s }
        }
    }
}

// MARK: v0.8.33 one-button confirmation (Home card, notification, Open With, drops)

/// "Update Writer?" / "Install Writer?" with one primary button. pax-guard does every check;
/// a refusal or failure shows the usual calm error card.
struct AppInstallConfirmSheet: View {
    let request: AppInstallRequest
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject var updates: AppUpdatesModel
    private let client = GuardClient()
    @State private var job: GuardClient.InstallJob?
    @State private var failure: PaxError?
    @State private var started = false

    private var working: Bool { job?.isWorking == true }
    private var finished: Bool { job != nil && !working }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(request.title).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            result
            HStack {
                Spacer()
                if finished || failure != nil {
                    Button(AppInstallText.close) { dismiss() }.buttonStyle(PrimaryButtonStyle())
                } else {
                    Button("Cancel") { dismiss() }.buttonStyle(SecondaryButtonStyle()).disabled(working)
                    Button(request.button) { start(choice: nil) }
                        .buttonStyle(PrimaryButtonStyle(accent: true)).disabled(started)
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(24)
        .frame(width: 460)
    }

    @ViewBuilder private var result: some View {
        if let failure {
            ErrorCard(error: failure, retry: nil, details: { Support.details(failure, log: []) })
        } else if let job {
            if job.isWorking {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(AppInstallText.step(job.step)).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                }
            } else if job.succeeded {
                NoteRow(icon: "checkmark.circle", text: AppInstallText.done(job))
            } else if job.code == "PAX-MAC-025", let options = job.options, !options.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text(AppInstallText.chooseOne).font(Theme.body(13, weight: .medium))
                        .foregroundStyle(Theme.primaryText)
                    ForEach(options, id: \.self) { name in
                        Button(name) { start(choice: name) }.buttonStyle(.link)
                    }
                }
            } else {
                let p = AppInstallText.problem(job)
                VStack(alignment: .leading, spacing: 6) {
                    if job.code == "PAX-MAC-021" {
                        Text(p.message).font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    ErrorCard(error: PaxError(p.code, technical: job.error ?? ""), retry: nil,
                              details: { Support.details(PaxError(p.code, technical: job.error ?? ""), log: []) })
                }
            }
        }
    }

    private func start(choice: String?) {
        failure = nil
        started = true
        Task {
            do {
                job = try await client.startInstall(path: request.path, choice: choice,
                                                    updateOnly: request.updateOnly)
                while job?.isWorking == true {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    if let j = try? await client.installStatus() { job = j }
                }
            } catch {
                failure = PaxErrorClassifier.classify(error)
            }
            updates.finished(request.path)
        }
    }
}

/// Home: "App update ready: Writer 3.2" with one Update button (at most three).
struct AppUpdateReadyCards: View {
    @EnvironmentObject var updates: AppUpdatesModel

    var body: some View {
        ForEach(updates.cards) { u in
            Card {
                HStack(alignment: .center, spacing: 12) {
                    Image(systemName: "arrow.down.circle").font(.system(size: 18)).foregroundStyle(Theme.mutedText)
                    Text(AppUpdatePrompts.cardTitle(u)).font(Theme.body(14, weight: .medium))
                        .foregroundStyle(Theme.primaryText)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    Button(AppUpdatePrompts.cardButton) { updates.update(u) }
                        .buttonStyle(SecondaryButtonStyle())
                }
            }
        }
    }
}
