// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import SwiftUI
import PaxCore

/// v0.8.15: the device's Support ID with a copy button (Details card).
struct SupportIDRow: View {
    let supportID: String
    @State private var copied = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(VerifiedSupportRelease.supportIDLabel).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            Spacer(minLength: 8)
            Text(supportID).font(.system(size: 13, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.primaryText).textSelection(.enabled)
            Button(copied ? "Copied" : "Copy") {
                let pb = NSPasteboard.general
                pb.clearContents()
                pb.setString(supportID, forType: .string)
                copied = true
            }
            .buttonStyle(.link).font(Theme.body(12))
        }
    }
}

/// v0.8.15: "Allow verified support release" on a device's Details card. Off applies
/// straight away; on takes the full wait and the trusted person is told first.
struct SupportReleaseRow: View {
    let state: EscrowClient.DeviceStatus.SupportReleaseState
    let busy: Bool
    let change: (Bool) -> Void

    var body: some View {
        ToggleRow(title: VerifiedSupportRelease.title,
                  detail: VerifiedSupportRelease.detail(allowed: state.allowed, pendingOnAt: state.pending_on_at,
                                                        tellingPartner: state.telling_partner ?? false),
                  isOn: Binding(get: { state.allowed || state.pending_on_at != nil },
                                set: { on in if !busy { change(on) } }))
    }
}

/// v0.8.15: "I have a support code", inside "In an emergency".
struct SupportCodeEntry: View {
    @Binding var code: String
    let busy: Bool
    let allowed: Bool?
    let redeem: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(VerifiedSupportRelease.codeFieldTitle).font(Theme.body(13, weight: .medium))
                .foregroundStyle(Theme.primaryText)
            Text(VerifiedSupportRelease.codeExplainer).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
            if allowed == false {
                Text("Verified support release is off on this device, so codes don't work here.")
                    .font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            TextField(VerifiedSupportRelease.codePlaceholder, text: $code, axis: .vertical)
                .lineLimit(1...4)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, design: .monospaced))
            Button("Use support code", action: redeem)
                .buttonStyle(SecondaryButtonStyle())
                .disabled(busy || !VerifiedSupportRelease.looksComplete(code))
        }
    }
}

/// v0.8.16: "Turn-off wait   7 days" on a Details card.
struct TurnOffWaitRow: View {
    let seconds: Int

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(TurnOffWait.label).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            Spacer(minLength: 8)
            Text(TurnOffWait.duration(seconds: seconds)).font(Theme.body(13, weight: .medium))
                .foregroundStyle(Theme.primaryText)
        }
        .accessibilityElement(children: .combine)
    }
}

/// v0.8.15: this Mac's Details card (its Support ID and the support-release switch).
struct MacDetailsCard: View {
    @EnvironmentObject var mac: MacProtectModel

    var body: some View {
        if let s = mac.status, s.support_id != nil || s.support_release != nil || s.wait_seconds != nil {
            Card {
                Text("Details").font(Theme.heading(20)).foregroundStyle(Theme.primaryText)
                if let w = s.wait_seconds { TurnOffWaitRow(seconds: w) }     // v0.8.16
                if let id = s.support_id { SupportIDRow(supportID: id) }
                if let sr = s.support_release {
                    SupportReleaseRow(state: sr, busy: mac.busy) { mac.setSupportRelease($0) }
                }
            }
        }
    }
}
