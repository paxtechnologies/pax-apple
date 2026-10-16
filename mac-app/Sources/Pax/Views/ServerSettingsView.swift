// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import SwiftUI
import PaxCore

/// v0.5 Settings: the escrow server address, so a tester can point Pax at a
/// hosted server. Saved in UserDefaults (ServerURLSetting.defaultsKey) and used
/// from the next launch. Locked while this Mac is protected, because the Mac's
/// escrowed password and pax-guard's token live on the current server.
@MainActor
struct ServerSettingsView: View {
    let current: URL
    @State private var text = ""
    @State private var message: String?
    @State private var isError = false
    @State private var saved = false
    @State private var testing = false

    private var protectedMac: Bool { UserDefaults.standard.string(forKey: "pax.mac.deviceID") != nil }
    private var envOverride: String? {
        let v = ProcessInfo.processInfo.environment["PAX_SERVER_URL"]
        return (v?.isEmpty ?? true) ? nil : v
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Pax server").font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
            Text("Pax's own server (\(ServerURLSetting.defaultURL.absoluteString)) is used unless you run your own. "
                 + "It keeps your iPhone's key and releases it after your wait, and sends partner emails. "
                 + "To self-host, enter your server here: https:// for a server on the internet, plain "
                 + "http:// only for this Mac or your own network.")
                .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            Text("Using now: \(current.absoluteString)")
                .font(Theme.body(12, weight: .semibold)).foregroundStyle(Theme.primaryText)
            if let env = envOverride {
                Text("PAX_SERVER_URL is set (\(env)), so it wins over this setting.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            }
            TextField(ServerURLSetting.defaultURL.absoluteString, text: $text)
                .textFieldStyle(.roundedBorder)
                .font(Theme.body(14))
                .disabled(protectedMac)
            HStack(spacing: 10) {
                Button("Test") { test() }
                    .buttonStyle(SecondaryButtonStyle())
                    .disabled(protectedMac || testing || text.isEmpty)
                Button("Use the default") {
                    text = ServerURLSetting.defaultURL.absoluteString
                    save()
                }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(protectedMac)
                Spacer()
                Button("Save") { save() }
                    .buttonStyle(PrimaryButtonStyle(accent: true))
                    .disabled(protectedMac || text.isEmpty)
            }
            if protectedMac {
                Text("This Mac is protected through the current server, so the address can't change "
                     + "until Pax is removed from this Mac.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
            }
            if let message {
                Text(message).font(Theme.body(12))
                    .foregroundStyle(isError ? Theme.accent : Theme.primaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if saved {
                Button("Quit Pax now") { NSApp.terminate(nil) }
                    .buttonStyle(SecondaryButtonStyle())
            }
        }
        .onAppear {
            text = UserDefaults.standard.string(forKey: ServerURLSetting.defaultsKey) ?? current.absoluteString
        }
    }

    private func save() {
        switch ServerURLSetting.validate(text) {
        case .success(let url):
            UserDefaults.standard.set(url.absoluteString, forKey: ServerURLSetting.defaultsKey)
            text = url.absoluteString
            isError = false
            saved = url != current
            message = saved ? "Saved. Quit and reopen Pax to use \(url.absoluteString). Your sign-in for "
                + "each server is kept separately." : "Saved."
        case .failure(let problem):
            isError = true
            message = problem.errorDescription
        }
    }

    private func test() {
        guard case .success(let url) = ServerURLSetting.validate(text) else {
            save()
            return
        }
        testing = true
        message = "Checking \(url.absoluteString)…"
        isError = false
        Task {
            do {
                _ = try await EscrowClient(baseURL: url).health()
                message = "A Pax server answered at \(url.absoluteString)."
                isError = false
            } catch {
                message = "No Pax server answered: \(error.localizedDescription)"
                isError = true
            }
            testing = false
        }
    }
}
