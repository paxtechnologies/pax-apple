// SPDX-License-Identifier: GPL-3.0-only
// About five minutes, no Mac. Order: why → account + partner → wait → Screen Time access
// → apps to keep closed → passcode (recommended) → DNS → done. Nothing is switched on
// until the escrow is saved on the server (fail closed).
import SwiftUI
import FamilyControls

struct OnboardingView: View {
    @EnvironmentObject var model: AppModel
    enum Step: Int, CaseIterable { case welcome, account, wait, access, apps, passcode, dns, done }
    @State private var step: Step = .welcome
    @State private var email = ""
    @State private var partner = ""
    @State private var waitDays = Pax.defaultWaitDays
    @State private var pickerShown = false
    @State private var escrowPasscode = true

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                PaxLogo().padding(.top, 32)
                content
                if let m = model.message {
                    Text(m).font(.footnote).foregroundColor(.paxSlate).multilineTextAlignment(.center)
                }
            }
            .padding(24)
            .frame(maxWidth: 560)
            .frame(maxWidth: .infinity)
        }
        .disabled(model.busy)
        .familyActivityPicker(isPresented: $pickerShown, selection: $model.selection)
    }

    @ViewBuilder private var content: some View {
        switch step {
        case .welcome:
            PaxCard {
                Text("Less scrolling. More living.").font(.paxHeading(26)).foregroundColor(.paxNavy)
                Text("Pax blocks explicit content on this iPhone or iPad, for you, because you chose it. Turning it off is always possible. It just takes a wait you pick now, so the calm version of you makes the call.")
                    .foregroundColor(.paxSlate)
                Text("Pax is free and open source. It never keeps your browsing history.")
                    .font(.footnote).foregroundColor(.paxSlate)
            }
            Button("Begin") { step = .account }.buttonStyle(PaxPillButtonStyle())

        case .account:
            PaxCard {
                Text("Your email").font(.paxHeading(22)).foregroundColor(.paxNavy)
                TextField("you@example.com", text: $email)
                    .textContentType(.emailAddress).keyboardType(.emailAddress)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Text("A partner, if you'd like one").font(.paxHeading(22)).foregroundColor(.paxNavy)
                TextField("Their email (optional)", text: $partner)
                    .keyboardType(.emailAddress).textInputAutocapitalization(.never).autocorrectionDisabled()
                Text("Your partner is told by email if you ask to turn Pax off or make it weaker. They can't approve or stop anything. If the email can't be sent, nothing is turned off.")
                    .font(.footnote).foregroundColor(.paxSlate)
            }
            Button("Continue") { step = .wait }
                .buttonStyle(PaxPillButtonStyle()).disabled(!email.contains("@"))

        case .wait:
            PaxCard {
                Text("Your turn-off wait").font(.paxHeading(22)).foregroundColor(.paxNavy)
                Stepper(value: $waitDays, in: Pax.minWaitDays...Pax.maxWaitDays) {
                    Text("\(waitDays) days").font(.title3.weight(.semibold))
                }
                Text("If you ask to turn Pax off, it happens after this wait. For the first hour after set-up there's no wait, in case you change your mind.")
                    .font(.footnote).foregroundColor(.paxSlate)
            }
            Button("Continue") {
                Task {
                    if await model.createAccount(email: email, partner: partner.isEmpty ? nil : partner,
                                                 waitDays: waitDays) { step = .access }
                }
            }.buttonStyle(PaxPillButtonStyle())

        case .access:
            PaxCard {
                Text("Screen Time access").font(.paxHeading(22)).foregroundColor(.paxNavy)
                Text("iPhone asks once, with Face ID. This lets Pax switch on the adult-website filter and stop itself being deleted.")
                    .foregroundColor(.paxSlate)
            }
            Button(model.authorized ? "Continue" : "Allow with Face ID") {
                Task { await model.authorize(); if model.authorized { step = .apps } }
            }.buttonStyle(PaxPillButtonStyle())

        case .apps:
            PaxCard {
                Text("Apps and sites to keep closed").font(.paxHeading(22)).foregroundColor(.paxNavy)
                Text("Choose any you'd like closed, such as X, Bluesky or browsers you don't trust. Pax only sees an anonymous token, never what you picked.")
                    .foregroundColor(.paxSlate)
                Button("Choose") { pickerShown = true }.buttonStyle(PaxPillButtonStyle(filled: false))
            }
            Button("Continue") { step = .passcode }.buttonStyle(PaxPillButtonStyle())

        case .passcode:
            PasscodeEscrowView(enabled: $escrowPasscode) { step = .dns }

        case .dns:
            PaxCard {
                Text("Encrypted DNS").font(.paxHeading(22)).foregroundColor(.paxNavy)
                Text("An extra layer that filters apps as well as websites. After this step, open Settings › General › VPN & Device Management › DNS and choose Pax.")
                    .foregroundColor(.paxSlate)
                Text("iPhone lets anyone switch this layer off in Settings. If it's off, Pax tells your partner.")
                    .font(.footnote).foregroundColor(.paxSlate)
            }
            Button("Finish set-up") {
                Task { if await model.finishSetUp(passcodeEscrow: escrowPasscode) { step = .done } }
            }.buttonStyle(PaxPillButtonStyle())

        case .done:
            EmptyView()   // RootView switches to HomeView once the policy is active.
        }
    }
}
