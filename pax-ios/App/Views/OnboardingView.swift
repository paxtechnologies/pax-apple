// SPDX-License-Identifier: GPL-3.0-only
// One-tap set-up (1.2): Welcome ("Turn Pax on") → your email → the 6-digit code → Apple's Screen
// Time sheet → Done. Every Pax account has a verified email, so a lost or replaced phone never
// means a lost account. "Setting up for a child?" uses the same email and code, with the parent's
// email. An email that already has an account shows "Welcome back" (what's already set) first.
// After the code everything happens quietly in AppModel.turnOn, escrow first: if the server can't
// be reached nothing is switched on and a calm "Try again" is shown.
import SwiftUI
import UIKit

struct OnboardingView: View {
    @EnvironmentObject var model: AppModel
    @State private var step: SetupStep = .welcome
    @State private var child = false
    @State private var email = ""
    @State private var code = ""
    @State private var resent = false
    @State private var started = false

    private var isPad: Bool { model.isPad }

    var body: some View {
        PaxPage {
            HStack {
                if let back = SetupRules.back(from: step) {
                    Button { go(back) } label: {
                        Label("Back", systemImage: "chevron.left")
                            .font(PaxFont.body(16, weight: .medium, relativeTo: .callout))
                    }
                    .foregroundStyle(Palette.accent)
                }
                Spacer()
            }
            .frame(minHeight: 24)
            PaxLogo(height: 54)
            content
            if step != .retry && step != .denied { MessageText(text: model.message) }
        }
        .disabled(model.busy)
        .overlay { if model.busy && step != .turningOn { ProgressView().controlSize(.large) } }
        .onAppear {
            guard !started else { return }
            started = true
            step = SetupRules.resume(isActive: model.policy.isActive)
            #if DEBUG
            if let s = ScreenshotMode.step { step = s; if s == .childEmail { child = true } }   // App Store screenshots only
            #endif
        }
    }

    private func go(_ s: SetupStep) { model.message = nil; resent = false; step = s }

    /// Screen Time sheet (once), then the quiet work.
    private func turnOn() {
        model.message = nil
        step = .turningOn
        Task {
            let outcome = await model.turnOn(child: child)
            step = SetupRules.after(outcome, child: child)
            if outcome == .signedOut { code = "" }
        }
    }

    @ViewBuilder private var content: some View {
        switch step {
        case .welcome: welcome
        case .childEmail: emailStep(title: PaxCopy.childTitle, body: PaxCopy.childBody(isPad: isPad),
                                    note: PaxCopy.childWaitNote)
        case .email: emailStep(title: PaxCopy.emailTitle, body: PaxCopy.emailBody(isPad: isPad), note: nil)
        case .childCode, .code: codeStep
        case .welcomeBack: welcomeBack
        case .turningOn: turningOn
        case .retry: retry(body: PaxCopy.retryBody)
        case .denied: retry(body: PaxCopy.accessDenied)
        case .done: done
        }
    }

    // MARK: steps

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 22) {
            Text(PaxCopy.welcomeTitle)
                .font(PaxFont.heading(34, relativeTo: .largeTitle))
                .foregroundStyle(Palette.ink)
                .fixedSize(horizontal: false, vertical: true)
            BodyText(PaxCopy.welcomeBody(isPad: isPad))
            BodyText(PaxCopy.welcomeFree, small: true)
            Spacer(minLength: 8)
            Button(PaxCopy.turnOn) { child = false; go(.email) }
                .buttonStyle(PaxBigButton())
                .accessibilityHint(PaxCopy.turnOnNote(isPad: isPad))
            BodyText(PaxCopy.turnOnNote(isPad: isPad), small: true)
                .frame(maxWidth: .infinity, alignment: .center)
                .multilineTextAlignment(.center)
            Button(PaxCopy.childLink) { child = true; email = ""; go(.childEmail) }
                .font(PaxFont.body(16, weight: .medium, relativeTo: .callout))
                .foregroundStyle(Palette.accent)
                .frame(maxWidth: .infinity, alignment: .center)
        }
    }

    private func emailStep(title: String, body: String, note: String?) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(title)
            BodyText(body)
            if let note { BodyText(note, small: true) }
            PaxTextField(placeholder: PaxCopy.emailPlaceholder, text: $email, email: true)
            Button(PaxCopy.sendCode) {
                Task { if await model.sendCode(email: email) { code = ""; go(SetupRules.codeStep(child: child)) } }
            }
            .buttonStyle(PaxPrimaryButton())
            .disabled(!SetupRules.isEmail(email))
        }
    }

    private var codeStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.codeTitle)
            BodyText(PaxCopy.codeBody(email: SetupRules.normaliseEmail(email)))
            TextField("123456", text: $code)
                .keyboardType(.numberPad)
                .textContentType(.oneTimeCode)
                .font(.system(size: 28, weight: .semibold, design: .rounded))
                .padding(14)
                .background(RoundedRectangle(cornerRadius: 14).fill(Palette.card))
            Button(PaxCopy.codeContinue) {
                Task {
                    let v = await model.verifyCode(email: email, code: code)
                    guard let next = SetupRules.after(v, child: child) else { return }
                    if next == .welcomeBack {
                        go(.welcomeBack)
                        _ = await model.loadExisting(child: child)
                    } else {
                        turnOn()
                    }
                }
            }
            .buttonStyle(PaxPrimaryButton())
            .disabled(!SetupRules.isCode(code))
            BodyText(resent ? PaxCopy.codeSent : PaxCopy.codeResendNote, small: true)
            Button(PaxCopy.codeResend) {
                Task { if await model.sendCode(email: email) { code = ""; resent = true } }
            }
            .buttonStyle(PaxSecondaryButton())
        }
    }

    /// The email already had an account: show what's set there (never treated as fresh).
    private var welcomeBack: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.welcomeBackTitle)
            BodyText(PaxCopy.welcomeBackBody(isPad: isPad))
            if let a = model.existing {
                PaxCard { BulletList(lines: PaxCopy.welcomeBackLines(a)) }
                BodyText(PaxCopy.welcomeBackNote, small: true)
                Button(PaxCopy.welcomeBackContinue) { turnOn() }.buttonStyle(PaxPrimaryButton())
            } else if !model.busy {
                Button(PaxCopy.retryButton) { Task { _ = await model.loadExisting(child: child) } }
                    .buttonStyle(PaxPrimaryButton())
            }
        }
    }

    private var turningOn: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.turningOnTitle)
            BodyText(PaxCopy.turningOnBody(isPad: isPad))
            ProgressView().controlSize(.large).frame(maxWidth: .infinity).padding(.top, 12)
        }
    }

    private func retry(body: String) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.retryTitle)
            BodyText(body)
            Button(PaxCopy.retryButton) { turnOn() }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var done: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(Palette.good)
                    .accessibilityHidden(true)
                SectionTitle(PaxCopy.doneTitle)
            }
            PaxCard {
                BulletList(lines: PaxCopy.doneLines(isPad: isPad, waitDays: model.policy.waitDays))
            }
            BodyText(PaxCopy.doneNext)
            Button(PaxCopy.doneButton) { model.finishSetUp() }.buttonStyle(PaxPrimaryButton())
        }
    }
}

/// Signing in again on a device Pax is already on (the Keychain sign-in was lost): the same
/// email and code. Only the account this device was set up with is accepted.
struct SignInAgainView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var email = ""
    @State private var code = ""
    @State private var sent = false
    @State private var resent = false

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.signInAgainTitle)
                BodyText(PaxCopy.signInAgainBody(isPad: model.isPad))
                PaxTextField(placeholder: PaxCopy.emailPlaceholder, text: $email, email: true)
                    .disabled(sent)
                if !sent {
                    Button(PaxCopy.sendCode) {
                        Task { if await model.sendCode(email: email) { code = ""; sent = true } }
                    }
                    .buttonStyle(PaxPrimaryButton())
                    .disabled(!SetupRules.isEmail(email))
                } else {
                    BodyText(PaxCopy.codeBody(email: SetupRules.normaliseEmail(email)))
                    TextField("123456", text: $code)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                        .font(.system(size: 28, weight: .semibold, design: .rounded))
                        .padding(14)
                        .background(RoundedRectangle(cornerRadius: 14).fill(Palette.card))
                    Button(PaxCopy.signInButton) {
                        Task {
                            let v = await model.verifyCode(email: email, code: code, again: true)
                            if v != .failed {
                                await model.onActive()
                                model.message = PaxCopy.signedIn
                                dismiss()
                            }
                        }
                    }
                    .buttonStyle(PaxPrimaryButton())
                    .disabled(!SetupRules.isCode(code))
                    BodyText(resent ? PaxCopy.codeSent : PaxCopy.codeResendNote, small: true)
                    Button(PaxCopy.codeResend) {
                        Task { if await model.sendCode(email: email) { code = ""; resent = true } }
                    }
                    .buttonStyle(PaxSecondaryButton())
                }
                MessageText(text: model.message)
            }
            .disabled(model.busy)
            .overlay { if model.busy { ProgressView().controlSize(.large) } }
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Close") { dismiss() } }
            }
            .onAppear { email = model.policy.accountEmail ?? ""; model.message = nil }
        }
        .navigationViewStyle(.stack)
    }
}

/// A text field in the app's style.
struct PaxTextField: View {
    let placeholder: String
    @Binding var text: String
    var email = false

    var body: some View {
        TextField(placeholder, text: $text)
            .keyboardType(email ? .emailAddress : .default)
            .textContentType(email ? UITextContentType.emailAddress : UITextContentType.givenName)
            .textInputAutocapitalization(email ? .never : .words)
            .autocorrectionDisabled()
            .font(PaxFont.body(18))
            .padding(14)
            .background(RoundedRectangle(cornerRadius: 14).fill(Palette.haze.opacity(0.35)))
    }
}
