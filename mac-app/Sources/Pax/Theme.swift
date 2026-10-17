// SPDX-License-Identifier: GPL-3.0-only
//
// Pax Peace brand v2 (paxpeace.com, v0.8.16): "Less scrolling. More living."
// Calm and airy: a soft sky wash behind white rounded cards, navy pill buttons, dusk-blue
// accents. Logo: lowercase "pax" in Fraunces Soft with an italic "peace" tucked beside the
// lower p (the stacked lockup). Colours: Mist #F7F9FB, Navy #1E2A38, Dusk blue #6E8BA8,
// Haze #C9D4DF, White #FFFFFF, Slate #3B4654. Decentralised, open source, free for everyone.
import SwiftUI
import AppKit
import CoreText
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
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.8.19"
    }
}

extension Color {
    /// Hex initialiser, e.g. Color(hex: 0x6E8BA8).
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

/// v0.8.16: the brand fonts bundled in Pax.app/Contents/Resources/Fonts (build-dmg.sh;
/// SIL Open Font License, see OFL.txt there). Static instances, renamed as the OFL asks:
/// Fraunces Soft (opsz 72, wght 420, SOFT 100) for headings, Inter for body and UI, and
/// Playfair Display Italic (as "Pax Accent") for the odd accent word. Without them
/// (e.g. `swift run`), headings use New York and body text SF Pro.
enum BrandFonts {
    static let heading = "PaxFrauncesSoft-Regular"
    static let accentItalic = "PaxAccent-Italic"
    static let bodyRegular = "PaxInter-Regular"
    static let bodyMedium = "PaxInter-Medium"
    static let bodySemibold = "PaxInter-SemiBold"

    /// Registers every bundled .ttf for this process, once.
    static let registered: Bool = {
        guard let dir = Bundle.main.resourceURL?.appendingPathComponent("Fonts", isDirectory: true),
              let urls = try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
        else { return false }
        var any = false
        for url in urls where url.pathExtension.lowercased() == "ttf" {
            if CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil) { any = true }
        }
        return any
    }()

    private static func available(_ name: String) -> Bool {
        _ = registered
        return NSFont(name: name, size: 12) != nil
    }

    static let hasHeading = available(heading)
    static let hasAccent = available(accentItalic)
    static let hasBody = available(bodyRegular) && available(bodyMedium) && available(bodySemibold)
}

/// v0.8.16: the logo images bundled in Pax.app/Contents/Resources/branding (build-dmg.sh).
enum BrandImages {
    private static func load(_ name: String) -> NSImage? {
        guard let url = Bundle.main.url(forResource: name, withExtension: "png", subdirectory: "branding") else {
            return nil
        }
        return NSImage(contentsOf: url)
    }

    /// "pax" with "peace" tucked beside the lower p: navy on light, white on dark.
    static let stackedNavy = load("pax-peace-stacked-navy")
    static let stackedWhite = load("pax-peace-stacked-white")
}

enum Theme {
    // Brand palette v2 (v0.8.16)
    static let mistHex: UInt32 = 0xF7F9FB      // background
    static let navyHex: UInt32 = 0x1E2A38      // primary text, primary buttons
    static let duskHex: UInt32 = 0x6E8BA8      // accents, selection, status dots, links, eyebrows
    static let hazeHex: UInt32 = 0xC9D4DF      // borders, dividers, subtle fills
    static let whiteHex: UInt32 = 0xFFFFFF     // cards
    static let slateHex: UInt32 = 0x3B4654     // body and secondary text
    // The sky wash behind the window: dusk-blue tint at the top, Mist, a faint peach below.
    static let skyTopHex: UInt32 = 0xDCE5EE
    static let skyBottomHex: UInt32 = 0xF6EDE6
    /// Errors only: a muted red, used sparingly.
    static let warningHex: UInt32 = 0xA5564F
    // Night tones (dark appearance)
    static let nightHex: UInt32 = 0x121A24
    static let nightCardHex: UInt32 = 0x1B2532
    static let nightBorderHex: UInt32 = 0x2E3B4B
    static let nightMutedHex: UInt32 = 0xA9B6C4
    static let duskNightHex: UInt32 = 0x9DB4CB

    // Semantic colours (light / dark)
    /// Window background: Mist, deep navy at night (the sky wash sits on top, see SkyBackground).
    static let background = Color.adaptive(light: mistHex, dark: nightHex)
    /// White cards on the wash.
    static let card = Color.adaptive(light: whiteHex, dark: nightCardHex)
    /// A quiet fill (kept for older call sites).
    static let section = Color.adaptive(light: 0xEEF2F6, dark: nightCardHex)
    static let primaryText = Color.adaptive(light: navyHex, dark: mistHex)
    static let mutedText = Color.adaptive(light: slateHex, dark: nightMutedHex)
    static let border = Color.adaptive(light: hazeHex, dark: nightBorderHex)
    /// Subtle Haze fill (selected rows, numbered circles).
    static let secondary = Color.adaptive(light: 0xE7EDF3, dark: nightBorderHex)
    /// Sidebar: translucent Mist over the wash.
    static let sidebar = Color.adaptive(light: mistHex, dark: nightHex).opacity(0.55)
    /// Primary buttons: navy pill with white text (Mist pill with navy text at night).
    static let buttonFill = Color.adaptive(light: navyHex, dark: mistHex)
    static let buttonText = Color.adaptive(light: whiteHex, dark: navyHex)
    /// Dusk blue: selection, progress, status dots, links, eyebrow labels.
    static let accent = Color.adaptive(light: duskHex, dark: duskNightHex)
    /// Muted red for errors and things that need fixing. Nothing else.
    static let warning = Color.adaptive(light: warningHex, dark: 0xD9958E)
    /// Soft card shadow.
    static let shadow = Color(hex: navyHex, opacity: 0.07)

    static let cornerRadius: CGFloat = 18
    static let smallRadius: CGFloat = 12
    static let spacing: CGFloat = 20

    // Typography: Fraunces Soft headings, Inter body (bundled), with system fallbacks.
    static func heading(_ size: CGFloat = 30) -> Font {
        if BrandFonts.hasHeading { return .custom(BrandFonts.heading, size: size) }
        return .system(size: size, weight: .regular, design: .serif)
    }

    static func body(_ size: CGFloat = 14, weight: Font.Weight = .regular) -> Font {
        guard BrandFonts.hasBody else { return .system(size: size, weight: weight) }
        let name: String
        if weight == .semibold || weight == .bold || weight == .heavy || weight == .black {
            name = BrandFonts.bodySemibold
        } else if weight == .medium {
            name = BrandFonts.bodyMedium
        } else {
            name = BrandFonts.bodyRegular
        }
        return .custom(name, size: size)
    }

    /// Playfair Display Italic for an accent word (welcome screen only).
    static func accentItalic(_ size: CGFloat = 30) -> Font {
        if BrandFonts.hasAccent { return .custom(BrandFonts.accentItalic, size: size) }
        return .system(size: size, weight: .regular, design: .serif).italic()
    }
}

/// v0.8.16: the subtle sky wash behind the main window: a dusk-blue tint at the top,
/// Mist through the middle and a faint peach at the bottom. Very low contrast.
struct SkyBackground: View {
    @Environment(\.colorScheme) private var scheme

    private var stops: [Gradient.Stop] {
        if scheme == .dark {
            return [Gradient.Stop(color: Color(hex: 0x1A2533), location: 0),
                    Gradient.Stop(color: Color(hex: Theme.nightHex), location: 0.55),
                    Gradient.Stop(color: Color(hex: 0x1C1B22), location: 1)]
        }
        return [Gradient.Stop(color: Color(hex: Theme.skyTopHex), location: 0),
                Gradient.Stop(color: Color(hex: Theme.mistHex), location: 0.45),
                Gradient.Stop(color: Color(hex: Theme.mistHex), location: 0.7),
                Gradient.Stop(color: Color(hex: Theme.skyBottomHex), location: 1)]
    }

    var body: some View {
        LinearGradient(stops: stops, startPoint: .top, endPoint: .bottom)
            .ignoresSafeArea()
    }
}

// MARK: - Logo

/// The stacked lockup: "pax" with an italic "peace" tucked beside the lower p. Uses the
/// bundled logo image; draws it from the brand fonts when the image isn't there.
struct PaxWordmark: View {
    /// Roughly the size of "pax" in points (the lockup is about 1.6 times as tall).
    var size: CGFloat = 30
    var showPeace = true
    @Environment(\.colorScheme) private var scheme

    private var logo: NSImage? { scheme == .dark ? BrandImages.stackedWhite : BrandImages.stackedNavy }

    var body: some View {
        Group {
            if showPeace, let img = logo {
                Image(nsImage: img)
                    .resizable()
                    .interpolation(.high)
                    .aspectRatio(contentMode: .fit)
                    .frame(height: size * 1.6)
            } else {
                drawn
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Pax Peace")
    }

    private var drawn: some View {
        VStack(alignment: .leading, spacing: -size * 0.3) {
            Text("pax")
                .font(Theme.heading(size))
                .foregroundStyle(Theme.primaryText)
            if showPeace {
                Text("peace")
                    .font(Theme.accentItalic(size * 0.45))
                    .foregroundStyle(Theme.accent)
                    .padding(.leading, size * 0.75)
            }
        }
    }
}

/// The header every screen shares: wordmark on the left, optional trailing items.
struct ScreenHeader<Trailing: View>: View {
    var onLogoTap: (() -> Void)?
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .center) {
            Button { onLogoTap?() } label: { PaxWordmark(size: 27) }
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

/// Primary: a navy pill with white text. (`accent` is kept for older call sites; since
/// brand v2 every primary button is the same navy pill.)
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
            .foregroundStyle(Theme.buttonText)
            .background(
                Capsule().fill(Theme.buttonFill)
                    .shadow(color: Theme.shadow, radius: 6, x: 0, y: 2)
            )
            .opacity(isEnabled ? (configuration.isPressed ? 0.85 : 1) : 0.4)
            .contentShape(Capsule())
    }
}

/// Secondary: a white pill with a Haze border.
struct SecondaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(Theme.body(14, weight: .medium))
            .padding(.horizontal, 18)
            .padding(.vertical, 9)
            .foregroundStyle(Theme.primaryText)
            .background(Capsule().fill(Theme.card))
            .overlay(Capsule().stroke(Theme.border, lineWidth: 1))
            .opacity(isEnabled ? (configuration.isPressed ? 0.7 : 1) : 0.45)
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
            .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card)
                .shadow(color: Theme.shadow, radius: 14, x: 0, y: 4))
            .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius).stroke(Theme.border.opacity(0.6), lineWidth: 1))
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
            .background(RoundedRectangle(cornerRadius: Theme.cornerRadius).fill(Theme.card)
                .shadow(color: Theme.shadow, radius: 14, x: 0, y: 4))
            .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius)
                .stroke(selected ? Theme.accent : Theme.border.opacity(0.6), lineWidth: selected ? 2 : 1))
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
                Image(systemName: "exclamationmark.circle").foregroundStyle(Theme.warning)
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
        .background(RoundedRectangle(cornerRadius: Theme.smallRadius).fill(Theme.warning.opacity(0.06)))
        .overlay(RoundedRectangle(cornerRadius: Theme.smallRadius).stroke(Theme.warning.opacity(0.25)))
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

/// v0.8.16: "Pax turns off in 2 days 14 h · Cancel", one calm line.
struct TurnOffCountdownRow: View {
    let seconds: Int
    /// Nil when the request can't be cancelled from here.
    let cancel: (() -> Void)?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(TurnOffWait.turnsOffIn(seconds: seconds))
                .font(Theme.heading(24).monospacedDigit())
                .foregroundStyle(Theme.primaryText)
                .fixedSize(horizontal: false, vertical: true)
            if let cancel {
                Text("·").font(Theme.body(15)).foregroundStyle(Theme.mutedText)
                Button("Cancel", action: cancel)
                    .buttonStyle(.link)
                    .font(Theme.body(15, weight: .medium))
                    .foregroundStyle(Theme.accent)
                    .accessibilityLabel("Cancel turning Pax off")
            }
        }
    }
}
