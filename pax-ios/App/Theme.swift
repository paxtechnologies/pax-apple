// SPDX-License-Identifier: GPL-3.0-only
// Dusk/Air: white space, a soft blue-hour wash, navy pill buttons, white rounded cards.
// Fonts: Fraunces (headings), Playfair Display Italic (accents), Inter (body) are to be
// bundled (OFL); until then the system serif and sans stand in.
import SwiftUI

extension Color {
    static let paxMist  = Color(PaxColor.mist)
    static let paxNavy  = Color(PaxColor.navy)
    static let paxDusk  = Color(PaxColor.dusk)
    static let paxHaze  = Color(PaxColor.haze)
    static let paxSlate = Color(PaxColor.slate)
    static let paxPeach = Color(red: 0xF6/255, green: 0xE7/255, blue: 0xDE/255)
}

extension Font {
    static func paxHeading(_ size: CGFloat) -> Font { .system(size: size, weight: .regular, design: .serif) }
    static func paxAccent(_ size: CGFloat) -> Font { .system(size: size, weight: .regular, design: .serif).italic() }
    static let paxBody = Font.system(.body)
}

struct PaxBackground: View {
    var body: some View {
        LinearGradient(colors: [Color.paxDusk.opacity(0.22), Color.paxMist, Color.paxPeach.opacity(0.45)],
                       startPoint: .top, endPoint: .bottom)
            .ignoresSafeArea()
    }
}

struct PaxLogo: View {
    var body: some View {
        VStack(spacing: -6) {
            Text("pax").font(.paxHeading(44)).foregroundColor(.paxNavy)
            Text("peace").font(.paxAccent(22)).foregroundColor(.paxDusk)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Pax Peace")
    }
}

struct PaxCard<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 22, style: .continuous).fill(Color.white))
            .shadow(color: Color.paxNavy.opacity(0.06), radius: 16, y: 6)
    }
}

struct PaxPillButtonStyle: ButtonStyle {
    var filled = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .padding(.vertical, 14).frame(maxWidth: .infinity)
            .foregroundColor(filled ? .white : .paxNavy)
            .background(Capsule().fill(filled ? Color.paxNavy : Color.paxHaze.opacity(0.5)))
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}
