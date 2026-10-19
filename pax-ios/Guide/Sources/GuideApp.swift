// SPDX-License-Identifier: GPL-3.0-only
// Pax for iPhone and iPad, interim guide (v1.0.0). Shows how to protect this device
// with Pax Strict from a Mac, and checks whether it is protected. No accounts, no
// tracking, no entitlements. The full Screen Time app (pax-ios/) replaces it later
// under the same bundle id, org.paxpeace.pax.
import SwiftUI

@main
struct PaxGuideApp: App {
    var body: some Scene {
        WindowGroup {
            GuideView()
        }
    }
}
