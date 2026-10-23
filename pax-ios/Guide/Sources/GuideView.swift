// SPDX-License-Identifier: GPL-3.0-only
// The home screen IS the guide: a short welcome, what you'll need, nine numbered
// steps (one action each, the last runs the protection check), then the quieter
// extras (good to know, Pax without a Mac, links) at the bottom.
import SwiftUI
import UIKit

struct GuideView: View {
    private var isPad: Bool { UIDevice.current.userInterfaceIdiom == .pad }

    /// CI screenshots only: `-PaxScrollToStep 6` opens the guide scrolled to step 6.
    private var scrollTarget: String? {
        let args = ProcessInfo.processInfo.arguments
        guard let i = args.firstIndex(of: "-PaxScrollToStep"), i + 1 < args.count else { return nil }
        return "step-\(args[i + 1])"
    }

    var body: some View {
        PaxPage(scrollTo: scrollTarget) {
            header
            needs
            VStack(alignment: .leading, spacing: 14) {
                ForEach(GuideCopy.steps(isPad: isPad)) { step in
                    StepCard(step: step) {
                        if step.id == 1 { DownloadButtons() }
                        if step.id == GuideCopy.steps(isPad: isPad).count { ProtectionCheckView(isPad: isPad) }
                    }
                    .id("step-\(step.id)")
                }
            }
            Divider().overlay(Palette.haze).padding(.vertical, 8)
            SecondaryInfo(isPad: isPad)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 18) {
            PaxLogo(height: 58)
                .padding(.bottom, 6)
            Text(GuideCopy.tagline(isPad: isPad))
                .font(PaxFont.body(17, relativeTo: .body))
                .foregroundStyle(Palette.body)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                Text(GuideCopy.title(isPad: isPad))
                    .font(PaxFont.heading(36, relativeTo: .largeTitle))
                    .foregroundStyle(Palette.ink)
                    .accessibilityAddTraits(.isHeader)
                Text(GuideCopy.subtitle)
                    .font(PaxFont.accent(21, relativeTo: .title3))
                    .foregroundStyle(Palette.accent)
            }
        }
        .padding(.top, 8)
    }

    private var needs: some View {
        PaxCard {
            Text(GuideCopy.needTitle)
                .font(PaxFont.body(15, weight: .semibold, relativeTo: .subheadline))
                .foregroundStyle(Palette.accent)
                .textCase(.uppercase)
                .tracking(1.2)
                .accessibilityAddTraits(.isHeader)
            ForEach(Array(GuideCopy.needs(isPad: isPad).enumerated()), id: \.offset) { i, line in
                HStack(alignment: .firstTextBaseline, spacing: 14) {
                    Image(systemName: ["laptopcomputer", "cable.connector", "externaldrive"][min(i, 2)])
                        .font(.system(size: 18, weight: .regular))
                        .foregroundStyle(Palette.accent)
                        .frame(width: 26)
                        .accessibilityHidden(true)
                    Text(line)
                        .font(PaxFont.body(18, relativeTo: .body))
                        .foregroundStyle(Palette.ink)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

/// One numbered step: a big number, one short action, an optional line, and an
/// optional control (download buttons, the check).
struct StepCard<Extra: View>: View {
    let step: GuideStep
    @ViewBuilder var extra: Extra

    var body: some View {
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
                        .font(PaxFont.body(20, weight: .semibold, relativeTo: .title3))
                        .foregroundStyle(Palette.ink)
                        .fixedSize(horizontal: false, vertical: true)
                    if let detail = step.detail {
                        Text(detail)
                            .font(PaxFont.body(17, relativeTo: .body))
                            .foregroundStyle(Palette.body)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(.top, 6)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Step \(step.id). \(step.title) \(step.detail ?? "")")
            }
            extra
        }
    }
}

/// Step 1: send the Mac download link to the Mac (AirDrop, Messages, Mail…) or copy it.
struct DownloadButtons: View {
    @State private var copied = false

    var body: some View {
        VStack(spacing: 10) {
            ShareLink(item: PaxLinks.macDownload,
                      subject: Text("Pax for Mac"),
                      message: Text(PaxLinks.shareText)) {
                Label(GuideCopy.sendToMac, systemImage: "square.and.arrow.up")
            }
            .buttonStyle(PaxPrimaryButton())
            Button {
                UIPasteboard.general.string = PaxLinks.macDownload.absoluteString
                copied = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
            } label: {
                Label(copied ? GuideCopy.copied : GuideCopy.copyLink,
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(PaxSecondaryButton())
        }
        .padding(.top, 4)
    }
}

/// The quieter part at the bottom: Pax without a Mac, links. (No "Good to know": 1.2, Ruben 23 Oct 2026.)
struct SecondaryInfo: View {
    let isPad: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            section(GuideCopy.comingTitle) {
                Text(GuideCopy.comingBody).fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 12) {
                Link("paxpeace.com", destination: PaxLinks.site)
                Link("Help: \(PaxLinks.supportEmail)", destination: PaxLinks.support)
                Link("Privacy", destination: PaxLinks.privacy)
                Link("Source code (GPL-3.0)", destination: PaxLinks.source)
            }
            .font(PaxFont.body(16, weight: .medium, relativeTo: .callout))
            .foregroundStyle(Palette.accent)
            .tint(Palette.accent)
            Text("Pax is free, with no ads and no accounts in this app. Nothing you do here is stored or sent.")
                .font(PaxFont.body(14, relativeTo: .footnote))
                .foregroundStyle(Palette.body.opacity(0.8))
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func section<C: View>(_ title: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(PaxFont.heading(22, relativeTo: .title3))
                .foregroundStyle(Palette.ink)
                .accessibilityAddTraits(.isHeader)
            VStack(alignment: .leading, spacing: 8) { content() }
                .font(PaxFont.body(16, relativeTo: .callout))
                .foregroundStyle(Palette.body)
        }
    }
}
