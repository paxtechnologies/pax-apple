// SPDX-License-Identifier: GPL-3.0-only
// One-tap set-up (1.2): Welcome ("Turn Pax on") → Apple's Screen Time sheet → Done.
// "Setting up for a child?" keeps the parent's email and code. Everything else happens quietly
// in AppModel.turnOn, escrow first: if the server can't be reached nothing is switched on and
// a calm "Try again" is shown. Servers that can't make a private account yet ask for an email
// and a code after the Screen Time sheet, then carry on.
import SwiftUI
import UIKit

struct OnboardingView: View {
    @EnvironmentObject var model: AppModel
    @State private var step: SetupStep = .welcome
    @State private var child = false
    @State private var email = ""
    @State private var code = ""
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
            if step != .retry { MessageText(text: model.message) }
        }
        .disabled(model.busy)
        .overlay { if model.busy && step != .turningOn { ProgressView().controlSize(.large) } }
        .onAppear {
            guard !started else { return }
            started = true
            step = SetupRules.resume(isActive: model.policy.isActive)
            #if DEBUG
            if let s = ScreenshotMode.step { step = s }      // App Store screenshots only
            #endif
        }
    }

    private func go(_ s: SetupStep) { model.message = nil; step = s }

    /// Screen Time sheet (once), then the quiet work.
    private func turnOn() {
        model.message = nil
        step = .turningOn
        Task {
            let outcome = await model.turnOn(child: child)
            step = SetupRules.after(outcome)
            if outcome == .needsEmail { code = "" }
        }
    }

    @ViewBuilder private var content: some View {
        switch step {
        case .welcome: welcome
        case .childEmail: emailStep(title: PaxCopy.childTitle, body: PaxCopy.childBody(isPad: isPad),
                                    note: PaxCopy.childWaitNote, next: .childCode)
        case .childCode: codeStep
        case .turningOn: turningOn
        case .email: emailStep(title: PaxCopy.emailTitle, body: PaxCopy.emailBody, note: nil, next: .code)
        case .code: codeStep
        case .retry: retry
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
            Button(PaxCopy.turnOn) { child = false; turnOn() }
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

    private func emailStep(title: String, body: String, note: String?, next: SetupStep) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(title)
            BodyText(body)
            if let note { BodyText(note, small: true) }
            PaxTextField(placeholder: PaxCopy.emailPlaceholder, text: $email, email: true)
            Button(PaxCopy.sendCode) {
                Task { if await model.sendCode(email: email) { code = ""; go(next) } }
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
                Task { if await model.verifyCode(email: email, code: code) { turnOn() } }
            }
            .buttonStyle(PaxPrimaryButton())
            .disabled(!SetupRules.isCode(code))
            Button(PaxCopy.codeResend) { Task { _ = await model.sendCode(email: email) } }
                .buttonStyle(PaxSecondaryButton())
        }
    }

    private var turningOn: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.turningOnTitle)
            BodyText(PaxCopy.turningOnBody)
            ProgressView().controlSize(.large).frame(maxWidth: .infinity).padding(.top, 12)
        }
    }

    private var retry: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.retryTitle)
            BodyText(PaxCopy.retryBody)
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
