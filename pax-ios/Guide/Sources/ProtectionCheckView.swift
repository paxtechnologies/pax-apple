// SPDX-License-Identifier: GPL-3.0-only
// Step 9: "Check you're protected". Runs ProtectionCheck and shows one of
// Protected by Pax / Not protected / Couldn't check. Nothing is stored.
import SwiftUI
import UIKit

struct ProtectionCheckView: View {
    let isPad: Bool
    @State private var running = false
    @State private var outcome: ProtectionCheck.Outcome?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let outcome {
                result(outcome)
            }
            Button {
                Task { await check() }
            } label: {
                HStack(spacing: 10) {
                    if running { ProgressView().tint(Palette.buttonText) }
                    Text(running ? GuideCopy.checking : (outcome == nil ? GuideCopy.checkButton : GuideCopy.checkAgain))
                }
            }
            .buttonStyle(PaxPrimaryButton())
            .disabled(running)
            Text(GuideCopy.checkPrivacy)
                .font(PaxFont.body(14, relativeTo: .footnote))
                .foregroundStyle(Palette.body.opacity(0.85))
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, 4)
        .task {
            // CI screenshots only: `-PaxRunCheck` runs the check once on launch.
            if ProcessInfo.processInfo.arguments.contains("-PaxRunCheck"), outcome == nil { await check() }
        }
    }

    @MainActor private func check() async {
        running = true
        let o = await ProtectionCheck.run()
        withAnimation(.easeOut(duration: 0.25)) {
            outcome = o
            running = false
        }
        UIAccessibility.post(notification: .announcement, argument: GuideCopy.resultTitle(o))
    }

    private func result(_ o: ProtectionCheck.Outcome) -> some View {
        let (icon, tint): (String, Color) = {
            switch o {
            case .protected: return ("checkmark.shield", Palette.good)
            case .notProtected: return ("shield.slash", Palette.caution)
            case .couldNotCheck: return ("wifi.exclamationmark", Palette.accent)
            }
        }()
        return HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 28, weight: .regular))
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text(GuideCopy.resultTitle(o))
                    .font(PaxFont.heading(24, relativeTo: .title2))
                    .foregroundStyle(Palette.ink)
                Text(GuideCopy.resultDetail(o, isPad: isPad))
                    .font(PaxFont.body(17, relativeTo: .body))
                    .foregroundStyle(Palette.body)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(tint.opacity(0.10)))
        .accessibilityElement(children: .combine)
    }
}
