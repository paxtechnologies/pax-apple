// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import SwiftUI
import PaxCore

/// v0.8.15: the device's Support ID with a copy button.
/// v0.8.27: "Support ID: XXXX" + Copy and one plain line, in the turn-off area (Settings ›
/// Turning Pax off for this Mac; each iPhone's or iPad's Turn off card). Callers show it only
/// when SupportIDPlacement.visibleID returns an ID (switch on, device not turned off).
struct SupportIDRow: View {
    let supportID: String
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(SupportIDPlacement.label(supportID))
                    .font(.system(size: 13, weight: .medium, design: .monospaced))
                    .foregroundStyle(Theme.primaryText).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                Button(copied ? "Copied" : "Copy") {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(supportID, forType: .string)
                    copied = true
                }
                .buttonStyle(.link).font(Theme.body(12))
            }
            Text(VerifiedSupportRelease.supportIDLine).font(Theme.body(12)).foregroundStyle(Theme.mutedText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// v0.8.15: "Allow verified support release" on a device's Details card. Off applies
/// straight away; on takes the full wait and the trusted person is told first.
struct SupportReleaseRow: View {
    let state: EscrowClient.DeviceStatus.SupportReleaseState
    let busy: Bool
    /// v0.8.18: during the trial day turning it on is instant.
    var trialActive = false
    let change: (Bool) -> Void

    var body: some View {
        ToggleRow(title: VerifiedSupportRelease.title,
                  detail: VerifiedSupportRelease.detail(allowed: state.allowed, pendingOnAt: state.pending_on_at,
                                                        tellingPartner: state.telling_partner ?? false,
                                                        trialActive: trialActive),
                  isOn: Binding(get: { state.allowed || state.pending_on_at != nil },
                                set: { on in if !busy { change(on) } }))
    }
}

/// v0.8.15: "I have a support code", inside "In an emergency".
/// v0.8.27 (paste was slow): the draft lives here, in this view's own state, not in a
/// model every screen observes, so typing or pasting re-renders only this small view.
/// The field is a plain AppKit text field (no growing multi-line SwiftUI field, no spell
/// checking or autocorrect on a 150-letter code). The code is tidied once, when it's
/// sent (or when the field loses focus), and checked only on "Use support code".
struct SupportCodeEntry: View {
    let busy: Bool
    let allowed: Bool?
    let redeem: (String) -> Void
    @State private var draft = ""

    var body: some View {
        let complete = VerifiedSupportRelease.looksComplete(draft)
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
            SupportCodeField(placeholder: VerifiedSupportRelease.codePlaceholder, text: $draft) {
                if complete && !busy { submit() }
            }
            .frame(height: 22)
            Button("Use support code") { submit() }
                .buttonStyle(SecondaryButtonStyle())
                .disabled(busy || !complete)
        }
    }

    private func submit() {
        let code = VerifiedSupportRelease.cleaned(draft)
        guard VerifiedSupportRelease.looksComplete(code) else { return }
        redeem(code)
    }
}

/// v0.8.27: a one-line AppKit text field for the support code (macOS 12+). Text flows to
/// SwiftUI only when it actually changed, and SwiftUI writes back only when it differs, so
/// there's no update loop and the cursor never jumps. Spell checking, autocorrect, smart
/// dashes/quotes and text replacement are off in its editor. Return submits.
struct SupportCodeField: NSViewRepresentable {
    let placeholder: String
    @Binding var text: String
    let onSubmit: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    func makeNSView(context: Context) -> NSTextField {
        let f = NSTextField(string: text)
        f.placeholderString = placeholder
        f.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        f.isBezeled = true
        f.bezelStyle = .roundedBezel
        f.usesSingleLineMode = true
        f.lineBreakMode = .byTruncatingTail
        f.cell?.isScrollable = true
        f.cell?.wraps = false
        f.delegate = context.coordinator
        f.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        return f
    }

    func updateNSView(_ nsView: NSTextField, context: Context) {
        context.coordinator.parent = self
        if nsView.stringValue != text { nsView.stringValue = text }
    }

    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: SupportCodeField
        init(_ parent: SupportCodeField) { self.parent = parent }

        func controlTextDidBeginEditing(_ obj: Notification) {
            guard let editor = obj.userInfo?["NSFieldEditor"] as? NSTextView else { return }
            editor.isContinuousSpellCheckingEnabled = false
            editor.isGrammarCheckingEnabled = false
            editor.isAutomaticSpellingCorrectionEnabled = false
            editor.isAutomaticTextReplacementEnabled = false
            editor.isAutomaticDashSubstitutionEnabled = false
            editor.isAutomaticQuoteSubstitutionEnabled = false
            editor.isAutomaticTextCompletionEnabled = false
        }

        func controlTextDidChange(_ obj: Notification) {
            guard let f = obj.object as? NSTextField else { return }
            let value = f.stringValue
            if value != parent.text { parent.text = value }
        }

        /// Tidy once when the field is left (upper case, no spaces or line breaks).
        func controlTextDidEndEditing(_ obj: Notification) {
            guard let f = obj.object as? NSTextField else { return }
            let tidy = VerifiedSupportRelease.cleaned(f.stringValue)
            if tidy != f.stringValue { f.stringValue = tidy }
            if tidy != parent.text { parent.text = tidy }
        }

        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            if selector == #selector(NSResponder.insertNewline(_:)) {
                parent.onSubmit()
                return true
            }
            return false
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
