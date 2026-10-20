// SPDX-License-Identifier: GPL-3.0-only
// Pax for iPhone and iPad (App Store). Set-up on the phone, then Home.
import SwiftUI

@main
struct PaxApp: App {
    @StateObject private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .onChange(of: scenePhase) { phase in
                    if phase == .active { Task { await model.onActive() } }
                }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Group {
            if model.policy.isActive && model.policy.setUpFinished {
                HomeView()
            } else {
                OnboardingView()
            }
        }
        .tint(Palette.accent)
        .task { await model.onActive() }
        .sheet(isPresented: Binding(get: { model.revealedPasscode != nil },
                                    set: { if !$0 { model.revealedPasscode = nil } })) {
            ReleasedView(passcode: model.revealedPasscode ?? "") { model.revealedPasscode = nil }
        }
    }
}

/// Shown once, after the server released the secret and Pax removed its settings.
struct ReleasedView: View {
    let passcode: String
    var onDone: () -> Void

    var body: some View {
        PaxPage {
            SectionTitle(PaxCopy.releasedTitle)
            if passcode.isEmpty {
                BodyText(PaxCopy.releasedNoPasscode)
            } else {
                BodyText(PaxCopy.releasedPasscode)
                Text(passcode)
                    .font(.system(size: 48, weight: .semibold, design: .rounded))
                    .foregroundStyle(Palette.ink)
                    .tracking(8)
                    .frame(maxWidth: .infinity)
                    .textSelection(.enabled)
                BodyText(PaxCopy.releasedHowTo)
                BodyText(PaxCopy.releasedNoPasscode, small: true)
            }
            Button(PaxCopy.doneButton, action: onDone).buttonStyle(PaxPrimaryButton())
        }
        .interactiveDismissDisabled()
    }
}
