// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI

@main
struct PaxApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .task { await model.onLaunch() }
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        ZStack {
            PaxBackground()
            if model.policy.isActive { HomeView() } else { OnboardingView() }
        }
        .tint(Color.paxNavy)
    }
}
