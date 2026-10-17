// SPDX-License-Identifier: GPL-3.0-only
//
// Pax Peace brand (paxpeace.com): "Less scrolling. More living."
// Logo: lowercase "pax" in a serif with a solid terracotta full stop, and a small,
// widely spaced "PEACE" underneath. Calm, warm, never preachy.
// Decentralised, open source, free for everyone, power at the local level.
import SwiftUI
import AppKit
import PaxCore

enum Brand {
    static let name = "Pax"
    static let fullName = "Pax Peace"
    static let site = "paxpeace.com"
    static let siteURL = URL(string: "https://paxpeace.com")!
    static let tagline = "Less scrolling. More living."
    static let principles = ["Decentralised", "Open source", "Free for everyone", "Power at the local level"]
    /// CFBundleShortVersionString when bundled (build-dmg.sh sets it), else this.
    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.8.15"
    }
}

extension Color {
    /// Hex initialiser, e.g. Color(hex: 0xE85830).
    init(hex: UInt32, opacity: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: opacity)
    }

    /// A colour that switches between light and dark appearance.
    static func adaptive(light: UInt32, dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let hex = isDark ? dark : light
            return NSColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
                           green: CGFloat((hex >> 8) & 0xFF) / 255,
                           blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
        })
    }
}

enum Theme {
    // Brand palette (v0.7.0)
    static let creamHex: UInt32 = 0xF8F6F1
    static let inkHex: UInt32 = 0x192124
    static let terracottaHex: UInt32 = 0xE85830
    static let darkHex: UInt32 = 0x120F0D
    // Supporting tones
    static let cardHex: UInt32 = 0xFFFFFF
    static let mutedHex: UInt32 = 0x6F6A64
    static let borderHex: UInt32 = 0xE7E2DA
    static let darkCardHex: UInt32 = 0x1E1A17
    static let darkBorderHex: UInt32 = 0x34302B

    // Semantic colours (light / dark)
    /// Window background: cream, warm dark at night.
    static let background = Color.adaptive(light: creamHex, dark: darkHex)
    /// Cards sit on the cream.
    static let card = Color.adaptive(light: cardHex, dark: darkCardHex)
    /// Kept for older call sites: a quiet fill.
    static let section = Color.adaptive(light: 0xF1EEE7, dark: darkCardHex)
    static let primaryText = Color.adaptive(light: inkHex, dark: creamHex)
    static let mutedText = Color.adaptive(light: mutedHex, dark: 0xA8A29B)
    static let border = Color.adaptive(light: borderHex, dark: darkBorderHex)
    static let secondary = Color.adaptive(light: 0xEDE9E1, dark: darkBorderHex)
    /// Primary buttons: ink on light, cream on dark.
    static let buttonFill = Color.adaptive(light: inkHex, dark: creamHex)
    static let buttonText = Color.adaptive(light: creamHex, dark: inkHex)
    /// Terracotta: the full stop, the main call to action, progress. Use sparingly.
    static let accent = Color(hex: terracottaHex)

    static let cornerRadius: CGFloat = 18
    static let smallRadius: CGFloat = 12
    static let spacing: CGFloat = 20

    // Typography. Headings use New York (the system serif) because Playfair Display
    // isn't bundled; if Playfair is installed on the Mac it's used instead.
    static func heading(_ size: CGFloat = 30) -> Font {
        if NSFont(name: "PlayfairDisplay-Regular", size: size) != nil {
            return .custom("PlayfairDisplay-Regular", size: size)
        }
        return .system(size: size, weight: .regular, design: .serif)
    }

    static func body(_ size: CGFloat = 14, weight: Font.Weight = .regular) -> Font {
        for name in ["Inter-Regular", "DMSans-Regular"] where NSFont(name: name, size: size) != nil {
            return .custom(name, size: size).weight(weight)
        }
        return .system(size: size, weight: weight)
    }
}

// MARK: - Logo

/// "pax." in the serif with the terracotta full stop, and optionally "PEACE" under it.
struct PaxWordmark: View {
    var size: CGFloat = 30
    var showPeace = true

    var body: some View {
        VStack(alignment: .leading, spacing: size * 0.02) {
            HStack(alignment: .lastTextBaseline, spacing: size * 0.04) {
                Text("pax")
                    .font(Theme.heading(size))
                    .foregroundStyle(Theme.primaryText)
                Circle()
                    .fill(Theme.accent)
                    .frame(width: size * 0.2, height: size * 0.2)
                    .alignmentGuide(.lastTextBaseline) { d in d[.bottom] }
            }
            if showPeace {
                Text("PEACE")
                    .font(Theme.body(max(8, size * 0.24), weight: .medium))
                    .tracking(size * 0.16)
                    .foregroundStyle(Theme.mutedText)
                    .padding(.leading, size * 0.04)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Pax Peace")
    }
}

/// The header every screen shares: wordmark on the left, optional trailing items.
struct ScreenHeader<Trailing: View>: View {
    var onLogoTap: (() -> Void)?
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .center) {
            Button { onLogoTap?() } label: { PaxWordmark(size: 26) }
                .buttonStyle(.plain)
                .disabled(onLogoTap == nil)
            Spacer()
            trailing
        }
        .padding(.horizontal, 36)
        .padding(.top, 22)
        .padding(.bottom, 12)
    }
}

extension ScreenHeader where Trailing == EmptyView {
    init(onLogoTap: (() -> Void)? = nil) {
        self.onLogoTap = onLogoTap
        self.trailing = EmptyView()
    }
}

// MARK: - Components

struct PrimaryButtonStyle: ButtonStyle {
    var accent = false
    var large = false
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Theme.body(large ? 16 : 14, weight: .semibold))
            .padding(.horizontal, large ? 28 : 20)
            .padding(.vertical, large ? 14 : 10)
            .frame(minWidth: large ? 220 : nil)
            .foregroundStyle(accent ? Color.white : Theme.buttonText)
            .background(
                Capsule().fill(accent ? Theme.accent : Theme.buttonFill)
            )
            .opacity(isEnabled ? (configuration.isPressed ? 0.85 : 1) : 0.4)
            .contentShape(Capsule())
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Theme.body(14, weight: .medium))
            .padding(.horizontal, 18)
            .padding(.vertical, 9)
            .foregroundStyle(Theme.primaryText)
            .background(Capsule().stroke(Theme.border, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.7 : 1)
            .contentShape(Capsule())
    }
}

struct Card<Content: View>: View {
    var padding: CGFloat = Theme.spacing
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card))
            .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius).stroke(Theme.border, lineWidth: 1))
    }
}

struct StepHeader: View {
    let eyebrow: String
    let title: String
    let subtitle: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if !eyebrow.isEmpty {
                Text(eyebrow.uppercased())
                    .font(Theme.body(11, weight: .semibold))
                    .tracking(1.4)
                    .foregroundStyle(Theme.accent)
            }
            Text(title)
                .font(Theme.heading(32))
                .foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
            if let subtitle {
                Text(subtitle)
                    .font(Theme.body(15))
                    .foregroundStyle(Theme.mutedText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct CheckRow: View {
    @Binding var isOn: Bool
    let text: String

    var body: some View {
        Toggle(isOn: $isOn) {
            Text(text)
                .font(Theme.body(14))
                .foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
        .toggleStyle(.checkbox)
        .tint(Theme.accent)
    }
}

/// A switch with a title and a one-line explanation.
struct ToggleRow: View {
    let title: String
    let detail: String?
    @Binding var isOn: Bool
    var locked = false

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(Theme.body(15, weight: .medium)).foregroundStyle(Theme.primaryText)
                if let detail {
                    Text(detail).font(Theme.body(12.5)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 12)
            if locked {
                Label("Always on", systemImage: "lock.fill")
                    .labelStyle(.titleAndIcon)
                    .font(Theme.body(12, weight: .medium))
                    .foregroundStyle(Theme.mutedText)
            } else {
                Toggle("", isOn: $isOn).labelsHidden().toggleStyle(.switch).tint(Theme.accent)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Slim numbered progress: ① — ② — ③.
struct StepProgress: View {
    let titles: [String]
    let current: Int   // 0-based

    var body: some View {
        HStack(spacing: 10) {
            ForEach(Array(titles.enumerated()), id: \.offset) { i, title in
                HStack(spacing: 8) {
                    ZStack {
                        Circle()
                            .fill(i <= current ? Theme.accent : Color.clear)
                            .overlay(Circle().stroke(i <= current ? Theme.accent : Theme.border, lineWidth: 1.5))
                        if i < current {
                            Image(systemName: "checkmark").font(.system(size: 10, weight: .bold))
                                .foregroundStyle(.white)
                        } else {
                            Text("\(i + 1)").font(Theme.body(11, weight: .semibold))
                                .foregroundStyle(i == current ? Color.white : Theme.mutedText)
                        }
                    }
                    .frame(width: 22, height: 22)
                    Text(title)
                        .font(Theme.body(12.5, weight: i == current ? .semibold : .regular))
                        .foregroundStyle(i <= current ? Theme.primaryText : Theme.mutedText)
                        .lineLimit(1)
                }
                if i < titles.count - 1 {
                    Capsule().fill(i < current ? Theme.accent : Theme.border).frame(height: 2)
                        .frame(minWidth: 16, maxWidth: 60)
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Step \(current + 1) of \(titles.count): \(titles[min(current, titles.count - 1)])")
    }
}

/// A big, tappable choice card (Welcome: This Mac / iPhone or iPad; wait times).
struct ChoiceCard: View {
    let icon: String
    let title: String
    let detail: String
    var selected = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 10) {
                Image(systemName: icon)
                    .font(.system(size: 30, weight: .light))
                    .foregroundStyle(selected ? Theme.accent : Theme.primaryText)
                Text(title).font(Theme.heading(22)).foregroundStyle(Theme.primaryText)
                Text(detail).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(24)
            .frame(maxWidth: .infinity, minHeight: 170, alignment: .topLeading)
            .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card))
            .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius)
                .stroke(selected ? Theme.accent : Theme.border, lineWidth: selected ? 2 : 1))
            .contentShape(RoundedRectangle(cornerRadius: Theme.cornerRadius))
        }
        .buttonStyle(.plain)
    }
}

/// A single calm progress bar with a friendly status line, and the technical log
/// folded away under "Details".
struct FriendlyProgress: View {
    let fraction: Double
    let status: String
    let log: [String]
    @State private var showDetails = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            ProgressView(value: min(max(fraction, 0.02), 1))
                .progressViewStyle(.linear)
                .tint(Theme.accent)
            Text(status).font(Theme.body(14)).foregroundStyle(Theme.primaryText)
            if !log.isEmpty {
                DisclosureGroup("Details", isExpanded: $showDetails) {
                    VStack(alignment: .leading, spacing: 3) {
                        ForEach(Array(log.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Theme.mutedText)
                                .textSelection(.enabled)
                        }
                    }
                    .padding(.top, 6)
                }
                .font(Theme.body(12))
                .foregroundStyle(Theme.mutedText)
            }
        }
    }
}

/// v0.7.0 error display: one plain sentence, what to try, "Try again", and the
/// support code small and muted with "Copy details".
struct ErrorCard: View {
    let error: PaxError
    var retry: (() -> Void)?
    /// Builds the text "Copy details" puts on the clipboard (sanitised).
    let details: () -> String
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "exclamationmark.circle").foregroundStyle(Theme.accent)
                VStack(alignment: .leading, spacing: 4) {
                    Text(error.info.message)
                        .font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(error.info.action)
                        .font(Theme.body(13)).foregroundStyle(Theme.mutedText)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            HStack(spacing: 12) {
                if let retry {
                    Button("Try again", action: retry).buttonStyle(PrimaryButtonStyle())
                }
                Button(copied ? "Copied" : "Copy details") {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(details(), forType: .string)
                    copied = true
                }
                .buttonStyle(.link)
                .font(Theme.body(12))
                Spacer()
                Text("Code \(error.code)")
                    .font(Theme.body(11).monospacedDigit())
                    .foregroundStyle(Theme.mutedText)
                    .textSelection(.enabled)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: Theme.smallRadius).fill(Theme.accent.opacity(0.07)))
        .overlay(RoundedRectangle(cornerRadius: Theme.smallRadius).stroke(Theme.accent.opacity(0.3)))
        .onChange(of: error) { _ in copied = false }
    }
}

/// Short, plain note (no error).
struct NoteRow: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(Theme.mutedText).frame(width: 18)
            Text(text).font(Theme.body(13)).foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

enum Support {
    /// "Copy details" text for an error, with the Mac's account and computer name removed.
    static func details(_ error: PaxError, log: [String], deviceOS: String? = nil,
                        extraRedactions: [String] = []) -> String {
        var redact = [NSUserName(), NSFullUserName()] + extraRedactions
        if let host = Host.current().localizedName { redact.append(host) }
        return SupportDetails.text(error: error, appVersion: Brand.version,
                                   macOSVersion: ProcessInfo.processInfo.operatingSystemVersionString,
                                   deviceOSVersion: deviceOS, log: log, redact: redact)
    }
}
