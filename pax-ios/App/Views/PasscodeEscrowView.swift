// SPDX-License-Identifier: GPL-3.0-only
// Recommended step: Pax makes up a Screen Time passcode, the person types it into
// Settings, and Pax keeps it on the server until the turn-off wait ends. Without it,
// Face ID alone can switch Pax's Screen Time access off (hardware test T1).
import SwiftUI

struct PasscodeEscrowView: View {
    @EnvironmentObject var model: AppModel
    @Binding var enabled: Bool
    var onDone: () -> Void
    @State private var code: String?
    @State private var shownIndex: Int?

    var body: some View {
        PaxCard {
            Text("Lock Screen Time").font(.paxHeading(22)).foregroundColor(.paxNavy)
            Text("This is what makes Pax hard to remove. Pax makes up a Screen Time passcode, you type it into Settings once, and Pax keeps it safe until your turn-off wait ends.")
                .foregroundColor(.paxSlate)
            Toggle("Use a Pax passcode (recommended)", isOn: $enabled)
            if !enabled {
                Text("Without this, Face ID can switch Pax off at any time.")
                    .font(.footnote).foregroundColor(.paxSlate)
            }
        }
        if enabled {
            PaxCard {
                Text("1. Open Settings › Screen Time › Lock Screen Time Settings.")
                Text("2. Type the digits below, one at a time. Hold a box to see its digit.")
                Text("3. When iPhone asks for an Apple Account for recovery, tap Cancel. Otherwise the passcode could be reset.")
                if let code {
                    HStack(spacing: 12) {
                        ForEach(0..<code.count, id: \.self) { i in
                            Text(shownIndex == i ? String(Array(code)[i]) : "•")
                                .font(.system(size: 34, weight: .semibold, design: .rounded))
                                .frame(width: 56, height: 64)
                                .background(RoundedRectangle(cornerRadius: 14).fill(Color.paxHaze.opacity(0.45)))
                                .onLongPressGesture(minimumDuration: 0.05, perform: {}, onPressingChanged: { p in shownIndex = p ? i : nil })
                        }
                    }.frame(maxWidth: .infinity)
                } else {
                    Button("Show my passcode") { code = model.preparePasscode() }
                        .buttonStyle(PaxPillButtonStyle(filled: false))
                }
            }
            .foregroundColor(.paxSlate)
        }
        Button("Continue") { onDone() }
            .buttonStyle(PaxPillButtonStyle())
            .disabled(enabled && code == nil)
    }
}
