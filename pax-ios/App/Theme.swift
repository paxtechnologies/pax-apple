// SPDX-License-Identifier: GPL-3.0-only
// Brand v2 "Dusk/Air" (same as the guide app): Mist, Navy, Dusk, Haze, Slate. Lots of
// space, white rounded cards, navy pill buttons. Dark Mode uses the same palette the
// other way round. Fonts (SIL OFL, Resources/Fonts/OFL.txt): Pax Fraunces Soft
// (headings), Pax Accent (Playfair Display Italic), Pax Inter (body), bundled.
import SwiftUI
import UIKit

enum Palette {
    static let mistHex: UInt32 = 0xF7F9FB
    static let navyHex: UInt32 = 0x1E2A38
    static let duskHex: UInt32 = 0x6E8BA8
    static let hazeHex: UInt32 = 0xC9D4DF
    static let slateHex: UInt32 = 0x3B4654

    static func ui(_ hex: UInt32, _ alpha: CGFloat = 1) -> UIColor {
        UIColor(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
    }
    static func dynamic(light: UIColor, dark: UIColor) -> Color {
        Color(UIColor { $0.userInterfaceStyle == .dark ? dark : light })
    }

    /// Page background: Mist by day, Navy at night.
    static let background = dynamic(light: ui(mistHex), dark: ui(navyHex))
    /// Cards: white by day, a Slate tint over Navy at night.
    static let card = dynamic(light: .white, dark: ui(0x28343F))
    /// Headings and main text.
    static let ink = dynamic(light: ui(navyHex), dark: ui(mistHex))
    /// Body text.
    static let body = dynamic(light: ui(slateHex), dark: ui(hazeHex))
    /// Accent (numbers, "peace", links).
    static let accent = dynamic(light: ui(duskHex), dark: ui(0x9DB3C8))
    /// Soft fills and borders.
    static let haze = dynamic(light: ui(hazeHex), dark: ui(slateHex))
    /// Primary button fill and its text.
    static let buttonFill = dynamic(light: ui(navyHex), dark: ui(mistHex))
    static let buttonText = dynamic(light: .white, dark: ui(navyHex))
    /// The dusk wash at the top of the page.
    static let wash = dynamic(light: ui(duskHex, 0.20), dark: ui(duskHex, 0.22))
    /// Result colours, kept calm.
    static let good = dynamic(light: ui(0x3E7A5E), dark: ui(0x8CC7A8))
    static let caution = dynamic(light: ui(0x9A6A2F), dark: ui(0xE2B77C))
}

enum PaxFont {
    static let heading = "PaxFrauncesSoft-Regular"
    static let accent = "PaxAccent-Italic"
    static let regular = "PaxInter-Regular"
    static let medium = "PaxInter-Medium"
    static let semibold = "PaxInter-SemiBold"

    static func has(_ name: String) -> Bool { UIFont(name: name, size: 12) != nil }

    static func heading(_ size: CGFloat, relativeTo style: Font.TextStyle = .title) -> Font {
        has(heading) ? .custom(heading, size: size, relativeTo: style)
                     : .system(style, design: .serif)
    }
    static func accent(_ size: CGFloat, relativeTo style: Font.TextStyle = .title3) -> Font {
        has(accent) ? .custom(accent, size: size, relativeTo: style)
                    : .system(style, design: .serif).italic()
    }
    static func body(_ size: CGFloat = 17, weight: Font.Weight = .regular,
                     relativeTo style: Font.TextStyle = .body) -> Font {
        let name: String
        switch weight {
        case .semibold, .bold, .heavy, .black: name = semibold
        case .medium: name = medium
        default: name = regular
        }
        return has(name) ? .custom(name, size: size, relativeTo: style)
                         : .system(style).weight(weight)
    }
}

struct PaxPage<Content: View>: View {
    /// A view id to scroll to on appear.
    var scrollTo: String? = nil
    @ViewBuilder var content: Content
    var body: some View {
        ZStack(alignment: .top) {
            Palette.background.ignoresSafeArea()
            LinearGradient(colors: [Palette.wash, .clear], startPoint: .top, endPoint: .bottom)
                .frame(height: 360)
                .ignoresSafeArea()
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 28) { content }
                        .padding(.horizontal, 24)
                        .padding(.top, 20)
                        .padding(.bottom, 48)
                        .frame(maxWidth: 620)
                        .frame(maxWidth: .infinity)
                }
                .onAppear {
                    guard let target = scrollTo else { return }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { proxy.scrollTo(target, anchor: .top) }
                }
            }
        }
    }
}

struct PaxCard<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) { content }
            .padding(22)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 24, style: .continuous).fill(Palette.card))
            .shadow(color: Color.black.opacity(0.05), radius: 16, y: 6)
    }
}

struct PaxPrimaryButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(PaxFont.body(17, weight: .semibold, relativeTo: .headline))
            .padding(.vertical, 15).padding(.horizontal, 22)
            .frame(maxWidth: .infinity)
            .foregroundStyle(Palette.buttonText)
            .background(Capsule().fill(Palette.buttonFill))
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}

/// The one big button on Welcome ("Turn Pax on").
struct PaxBigButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(PaxFont.body(20, weight: .semibold, relativeTo: .title3))
            .padding(.vertical, 22).padding(.horizontal, 24)
            .frame(maxWidth: .infinity, minHeight: 68)
            .foregroundStyle(Palette.buttonText)
            .background(Capsule().fill(Palette.buttonFill))
            .shadow(color: Color.black.opacity(0.12), radius: 14, y: 6)
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
    }
}

struct PaxSecondaryButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(PaxFont.body(17, weight: .medium, relativeTo: .headline))
            .padding(.vertical, 15).padding(.horizontal, 22)
            .frame(maxWidth: .infinity)
            .foregroundStyle(Palette.ink)
            .background(Capsule().fill(Palette.haze.opacity(0.55)))
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}

/// The stacked "pax / peace" logo from the brand kit (navy by day, white at night).
struct PaxLogo: View {
    var height: CGFloat = 64
    var body: some View {
        Image("Logo")
            .resizable()
            .scaledToFit()
            .frame(height: height)
            .accessibilityLabel("Pax Peace")
    }
}


// MARK: small pieces used across the app

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(PaxFont.heading(26, relativeTo: .title2))
            .foregroundStyle(Palette.ink)
            .fixedSize(horizontal: false, vertical: true)
            .accessibilityAddTraits(.isHeader)
    }
}

struct BodyText: View {
    let text: String
    var small = false
    init(_ text: String, small: Bool = false) { self.text = text; self.small = small }
    var body: some View {
        Text(text)
            .font(PaxFont.body(small ? 15 : 17, relativeTo: small ? .footnote : .body))
            .foregroundStyle(Palette.body)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// A status line with an SF Symbol.
struct StatusRow: View {
    let text: String
    let symbol: String
    var good = true
    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: symbol)
                .foregroundStyle(good ? Palette.good : Palette.caution)
                .frame(width: 22)
                .accessibilityHidden(true)
            Text(text)
                .font(PaxFont.body(16, relativeTo: .callout))
                .foregroundStyle(Palette.ink)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A bulleted list of short lines.
struct BulletList: View {
    let lines: [String]
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Circle().fill(Palette.accent).frame(width: 6, height: 6).accessibilityHidden(true)
                    BodyText(line)
                }
            }
        }
    }
}

/// The message line under a step (errors, notes), kept calm.
struct MessageText: View {
    let text: String?
    var body: some View {
        if let text, !text.isEmpty {
            Text(text)
                .font(PaxFont.body(15, relativeTo: .footnote))
                .foregroundStyle(Palette.caution)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
