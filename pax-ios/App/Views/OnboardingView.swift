// SPDX-License-Identifier: GPL-3.0-only
// The whole set-up on the phone, no Mac: welcome → who it's for → email → code →
// someone you trust → turn-off wait → Screen Time access → apps to keep closed →
// Pax passcode → switch on → type the passcode → encrypted DNS → done.
// Nothing is switched on until the escrow is saved on the server (fail closed), and
// after that there's no way back through the steps, only forward.
import SwiftUI
import UIKit
import FamilyControls

struct OnboardingView: View {
    @EnvironmentObject var model: AppModel
    @State private var step: SetupStep = .welcome
    @State private var audience: PaxAudience = .me
    @State private var email = ""
    @State private var code = ""
    @State private var account: PaxAPI.AccountStatus?
    @State private var trusted = ""
    @State private var trustedError: String?
    @State private var waitDays = Pax.defaultWaitDays
    @State private var pickerShown = false
    @State private var usePasscode = true
    @State private var passcode: String?
    @State private var shownDigit: Int?
    @State private var started = false

    private var isPad: Bool { model.isPad }

    var body: some View {
        PaxPage {
            HStack {
                if let back = SetupRules.back(from: step) {
                    Button { model.message = nil; step = back } label: {
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
            MessageText(text: model.message)
        }
        .disabled(model.busy)
        .overlay { if model.busy { ProgressView().controlSize(.large) } }
        .familyActivityPicker(isPresented: $pickerShown, selection: $model.selection)
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
    private func next() { go(SetupRules.next(after: step, passcode: usePasscode)) }

    @ViewBuilder private var content: some View {
        switch step {
        case .welcome: welcome
        case .audience: audienceStep
        case .email: emailStep
        case .code: codeStep
        case .trusted: trustedStep
        case .wait: waitStep
        case .access: accessStep
        case .apps: appsStep
        case .passcodeChoice: passcodeChoice
        case .lockIn: lockInStep
        case .passcodeType: passcodeType
        case .dns: dnsStep
        case .done: doneStep
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
            MacNoteCard(isPad: isPad)
            Button(PaxCopy.begin) { next() }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var audienceStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.audienceTitle)
            choice(PaxCopy.audienceMe, PaxCopy.audienceMeDetail(isPad: isPad), selected: audience == .me) {
                audience = .me
            }
            choice(PaxCopy.audienceChild, PaxCopy.audienceChildDetail(isPad: isPad), selected: audience == .child) {
                audience = .child
            }
            Button("Continue") {
                waitDays = SetupRules.defaultWait(for: audience)
                next()
            }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var emailStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.emailTitle(audience))
            BodyText(PaxCopy.emailBody(audience))
            field("you@example.com", text: $email, email: true)
            Button(PaxCopy.sendCode) {
                Task { if await model.sendCode(email: email) { code = ""; next() } }
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
                    if let a = await model.verifyCode(email: email, code: code) {
                        account = a
                        trusted = a.partner_email ?? ""
                        next()
                    }
                }
            }
            .buttonStyle(PaxPrimaryButton())
            .disabled(!SetupRules.isCode(code))
            Button(PaxCopy.codeResend) { Task { _ = await model.sendCode(email: email) } }
                .buttonStyle(PaxSecondaryButton())
        }
    }

    private var trustedStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.trustedTitle(audience))
            BodyText(PaxCopy.trustedBody(audience))
            if let existing = account?.partner_email, !existing.isEmpty {
                BodyText(PaxCopy.trustedExisting(existing))
            } else {
                field("Their email (optional)", text: $trusted, email: true)
            }
            BodyText(PaxCopy.trustedWitness, small: true)
            MessageText(text: trustedError)
            Button("Continue") {
                trustedError = SetupRules.trustedProblem(trusted, account: email)
                guard trustedError == nil else { return }
                Task { if await model.saveTrusted(trusted, existing: account?.partner_email) { next() } }
            }.buttonStyle(PaxPrimaryButton())
            if (account?.partner_email ?? "").isEmpty {
                Button(PaxCopy.trustedSkip) {
                    trusted = ""
                    trustedError = nil
                    Task { if await model.saveTrusted("", existing: nil) { next() } }
                }.buttonStyle(PaxSecondaryButton())
            }
        }
    }

    private var waitStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.waitTitle)
            BodyText(PaxCopy.waitBody)
            PaxCard {
                ForEach(Pax.waitChoices, id: \.self) { d in
                    Button { waitDays = d } label: {
                        HStack {
                            Text(TurnOffRules.waitLabel(days: d))
                                .font(PaxFont.body(18, weight: waitDays == d ? .semibold : .regular))
                                .foregroundStyle(Palette.ink)
                            Spacer()
                            if waitDays == d {
                                Image(systemName: "checkmark").foregroundStyle(Palette.accent)
                            }
                        }
                        .contentShape(Rectangle())
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.plain)
                    .accessibilityAddTraits(waitDays == d ? .isSelected : [])
                }
            }
            BodyText(PaxCopy.waitGrace, small: true)
            Button("Continue") {
                Task { if await model.saveWait(days: waitDays, currentSeconds: account?.wait_seconds) { next() } }
            }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var accessStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.accessTitle)
            BodyText(PaxCopy.accessBody(isPad: isPad))
            Button(model.authorized ? "Continue" : PaxCopy.accessButton) {
                Task {
                    await model.authorize()
                    if model.authorized { next() }
                }
            }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var appsStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.appsTitle)
            BodyText(PaxCopy.appsBody)
            BodyText(PaxCopy.appsBrowsers, small: true)
            Button(PaxCopy.appsChoose) { pickerShown = true }.buttonStyle(PaxSecondaryButton())
            BodyText(PaxCopy.appsChosen(model.selection.applicationTokens.count
                                        + model.selection.webDomainTokens.count
                                        + model.selection.categoryTokens.count), small: true)
            Button("Continue") { model.saveSelection(); next() }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var passcodeChoice: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.passcodeTitle)
            BodyText(PaxCopy.passcodeBody)
            PaxCard {
                Toggle(PaxCopy.passcodeToggle, isOn: $usePasscode)
                    .font(PaxFont.body(17, weight: .medium))
                    .tint(Palette.accent)
                if !usePasscode { MessageText(text: PaxCopy.passcodeSkipWarning) }
            }
            Button("Continue") { next() }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var lockInStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.lockTitle)
            PaxCard {
                BulletList(lines: PaxCopy.lockLines(isPad: isPad, trusted: model.policy.hasTrustedPerson,
                                                    waitDays: model.policy.waitDays))
            }
            PaxCard {
                Text(PaxCopy.limitsTitle)
                    .font(PaxFont.body(15, weight: .semibold, relativeTo: .subheadline))
                    .foregroundStyle(Palette.accent)
                BulletList(lines: PaxCopy.limits(isPad: isPad, passcode: usePasscode))
            }
            Button(PaxCopy.lockButton) {
                Task {
                    if let p = await model.lockIn(passcode: usePasscode, audience: audience) {
                        passcode = p.isEmpty ? nil : p
                        next()
                    }
                }
            }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var passcodeType: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.passcodeTitle)
            PaxCard {
                ForEach(Array(PaxCopy.passcodeSteps(isPad: isPad).enumerated()), id: \.offset) { i, line in
                    HStack(alignment: .firstTextBaseline, spacing: 10) {
                        Text("\(i + 1).").font(PaxFont.body(17, weight: .semibold)).foregroundStyle(Palette.accent)
                        BodyText(line)
                    }
                }
                if let code = passcode {
                    HStack(spacing: 12) {
                        ForEach(0..<code.count, id: \.self) { i in
                            Text(shownDigit == i ? String(Array(code)[i]) : "•")
                                .font(.system(size: 34, weight: .semibold, design: .rounded))
                                .foregroundStyle(Palette.ink)
                                .frame(width: 58, height: 66)
                                .background(RoundedRectangle(cornerRadius: 14).fill(Palette.haze.opacity(0.45)))
                                .onLongPressGesture(minimumDuration: 0.05, perform: {},
                                                    onPressingChanged: { p in shownDigit = p ? i : nil })
                                .accessibilityLabel("Digit \(i + 1)")
                                .accessibilityValue(shownDigit == i ? String(Array(code)[i]) : "hidden")
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                }
            }
            BodyText(PaxCopy.passcodeAfter, small: true)
            Button(PaxCopy.passcodeDone) {
                passcode = nil          // wiped from memory
                shownDigit = nil
                next()
            }.buttonStyle(PaxPrimaryButton())
        }
    }

    private var dnsStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.dnsTitle)
            BodyText(PaxCopy.dnsBody)
            BodyText(PaxCopy.dnsHonest(trusted: model.policy.hasTrustedPerson), small: true)
            if model.policy.dnsInstalled {
                StatusRow(text: model.dnsOn == true ? PaxCopy.homeDNSOn : PaxCopy.homeDNSOff,
                          symbol: model.dnsOn == true ? "checkmark.circle" : "exclamationmark.circle",
                          good: model.dnsOn == true)
                Button(PaxCopy.dnsOpenSettings) {
                    if let u = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(u) }
                }.buttonStyle(PaxSecondaryButton())
                Button("Continue") { next() }.buttonStyle(PaxPrimaryButton())
            } else {
                Button(PaxCopy.dnsAdd) { Task { _ = await model.installDNS() } }
                    .buttonStyle(PaxPrimaryButton())
                Button(PaxCopy.dnsSkip) { next() }.buttonStyle(PaxSecondaryButton())
            }
        }
    }

    private var doneStep: some View {
        VStack(alignment: .leading, spacing: 18) {
            SectionTitle(PaxCopy.doneTitle)
            PaxCard {
                BulletList(lines: PaxCopy.lockLines(isPad: isPad, trusted: model.policy.hasTrustedPerson,
                                                    waitDays: model.policy.waitDays))
            }
            PaxCard {
                Text(PaxCopy.limitsTitle)
                    .font(PaxFont.body(15, weight: .semibold, relativeTo: .subheadline))
                    .foregroundStyle(Palette.accent)
                BulletList(lines: PaxCopy.limits(isPad: isPad, passcode: model.policy.passcodeEscrowed))
            }
            MacNoteCard(isPad: isPad)
            Button(PaxCopy.doneButton) { model.finishSetUp() }.buttonStyle(PaxPrimaryButton())
        }
    }

    // MARK: pieces

    private func choice(_ title: String, _ detail: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .font(.system(size: 22))
                    .foregroundStyle(Palette.accent)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(PaxFont.body(19, weight: .semibold)).foregroundStyle(Palette.ink)
                    BodyText(detail)
                }
                Spacer(minLength: 0)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 22, style: .continuous).fill(Palette.card))
            .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous)
                .stroke(selected ? Palette.accent : Color.clear, lineWidth: 2))
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private func field(_ placeholder: String, text: Binding<String>, email: Bool) -> some View {
        TextField(placeholder, text: text)
            .keyboardType(email ? .emailAddress : .default)
            .textContentType(email ? UITextContentType.emailAddress : nil)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .font(PaxFont.body(18))
            .padding(14)
            .background(RoundedRectangle(cornerRadius: 14).fill(Palette.card))
    }
}
