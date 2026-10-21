// SPDX-License-Identifier: GPL-3.0-only
// "Make Pax unremovable": the Mac steps sheet opened from Home's last "Make Pax stronger"
// card, with the same steps as the guide app (Guide/Sources/Core/GuideCopy.swift).
import SwiftUI
import UIKit

struct MacSetupView: View {
    let isPad: Bool
    @Environment(\.dismiss) private var dismiss
    @State private var copied = false

    /// The guide's steps without its last one (the guide app's own check).
    private var steps: [GuideStep] { GuideCopy.steps(isPad: isPad).filter { $0.id < 9 } }

    var body: some View {
        NavigationView {
            PaxPage {
                SectionTitle(PaxCopy.macSheetTitle)
                BodyText(PaxCopy.macSheetIntro(isPad: isPad))
                PaxCard {
                    Text(GuideCopy.needTitle)
                        .font(PaxFont.body(15, weight: .semibold, relativeTo: .subheadline))
                        .foregroundStyle(Palette.accent)
                        .textCase(.uppercase)
                        .tracking(1.2)
                    BulletList(lines: GuideCopy.needs(isPad: isPad))
                }
                ForEach(steps) { step in
                    PaxCard {
                        HStack(alignment: .top, spacing: 16) {
                            Text("\(step.id)")
                                .font(PaxFont.heading(22, relativeTo: .title2))
                                .foregroundStyle(Palette.accent)
                                .frame(width: 40, height: 40)
                                .background(Circle().fill(Palette.haze.opacity(0.45)))
                                .accessibilityHidden(true)
                            VStack(alignment: .leading, spacing: 6) {
                                Text(step.title)
                                    .font(PaxFont.body(19, weight: .semibold, relativeTo: .title3))
                                    .foregroundStyle(Palette.ink)
                                    .fixedSize(horizontal: false, vertical: true)
                                if let d = step.detail { BodyText(d) }
                            }
                            .padding(.top, 6)
                        }
                        if step.id == 1 {
                            ShareLink(item: PaxLinks.macDownload, subject: Text("Pax for Mac"),
                                      message: Text(PaxLinks.shareText)) {
                                Label(GuideCopy.sendToMac, systemImage: "square.and.arrow.up")
                            }
                            .buttonStyle(PaxPrimaryButton())
                            Button {
                                UIPasteboard.general.string = PaxLinks.macDownload.absoluteString
                                copied = true
                            } label: {
                                Label(copied ? GuideCopy.copied : GuideCopy.copyLink,
                                      systemImage: copied ? "checkmark" : "doc.on.doc")
                            }
                            .buttonStyle(PaxSecondaryButton())
                        }
                    }
                }
                Link(PaxCopy.macSheetMore, destination: Pax.siteURL)
                    .font(PaxFont.body(16, weight: .medium, relativeTo: .callout))
                    .foregroundStyle(Palette.accent)
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .navigationViewStyle(.stack)
    }
}
