// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// v0.8.33 (Ruben, 28 Oct 2026): installing and updating apps without hunting for
// Settings › Updates. Three small doors, all into the same pax-guard checks:
//   1. an update an app already downloaded (Sparkle, Squirrel) shows as a Home card
//      and one notification per app and version;
//   2. "Open With › Pax" on a .dmg or .app (Pax is only an Alternate handler, never the default);
//   3. dropping one on Pax's Dock icon or window.
// Each ends on the same one-button confirmation, then installs.start. Nothing here decides
// what may be installed: pax-guard reads, copies and checks everything itself.

/// What the confirmation sheet is about to hand pax-guard.
public struct AppInstallRequest: Equatable, Sendable, Identifiable {
    public let path: String
    public let name: String
    /// Only for the title and button ("Update" vs "Install"); pax-guard decides for itself.
    public let isUpdate: Bool
    /// From a downloaded update: pax-guard refuses it unless it updates an app already installed.
    public let updateOnly: Bool

    public init(path: String, name: String, isUpdate: Bool, updateOnly: Bool = false) {
        self.path = path
        self.name = name
        self.isUpdate = isUpdate
        self.updateOnly = updateOnly
    }

    public var id: String { path }
    public var title: String { "\(isUpdate ? "Update" : "Install") \(name)?" }
    public var button: String { isUpdate ? "Update" : "Install" }
}

/// Downloaded updates → Home cards and notifications, without repeats.
public enum AppUpdatePrompts {
    /// Rescan this often while Pax is open (the scan is a bounded walk of ~/Library/Caches).
    public static let scanInterval: TimeInterval = 30 * 60
    /// Launch, Home appearing, waking: never more often than this.
    public static let minimumGap: TimeInterval = 60
    /// How many app+version pairs are remembered as already notified.
    public static let rememberLimit = 200
    /// At most this many cards on Home.
    public static let maxCards = 3
    /// UserDefaults key for the remembered pairs.
    public static let rememberedKey = "pax.installs.notified"
    /// Notification userInfo key: the update's path, matched against the current scan on click.
    public static let pathKey = "pax.install.path"
    public static let categoryID = "pax.app-update"

    public static let cardButton = "Update"

    public static func key(_ u: GuardClient.DownloadedUpdate) -> String {
        "\(u.bundle_id.lowercased())|\(u.version)"
    }

    public static func cardTitle(_ u: GuardClient.DownloadedUpdate) -> String {
        "App update ready: \(u.name) \(u.version)"
    }

    public static func notificationBody(_ u: GuardClient.DownloadedUpdate) -> String {
        "\(u.name) has an update ready. Pax can install it for you."
    }

    public static func request(for u: GuardClient.DownloadedUpdate) -> AppInstallRequest {
        AppInstallRequest(path: u.path, name: u.name, isUpdate: true, updateOnly: true)
    }

    public struct Outcome: Equatable {
        /// What Home shows now (one per app, at most `maxCards`).
        public let cards: [GuardClient.DownloadedUpdate]
        /// Newly seen app+version pairs: one notification each, ever.
        public let notify: [GuardClient.DownloadedUpdate]
        /// The remembered pairs to save (oldest dropped past `rememberLimit`).
        public let remembered: [String]
    }

    public static func process(_ found: [GuardClient.DownloadedUpdate], remembered: [String]) -> Outcome {
        var seenApps = Set<String>()
        var unique: [GuardClient.DownloadedUpdate] = []
        for u in found where !u.path.isEmpty && !u.name.isEmpty {
            let app = u.bundle_id.lowercased()
            if seenApps.insert(app).inserted { unique.append(u) }
        }
        var known = Set(remembered)
        var kept = remembered
        var notify: [GuardClient.DownloadedUpdate] = []
        for u in unique where !known.contains(key(u)) {
            notify.append(u)
            known.insert(key(u))
            kept.append(key(u))
        }
        if kept.count > rememberLimit { kept = Array(kept.suffix(rememberLimit)) }
        return Outcome(cards: Array(unique.prefix(maxCards)), notify: notify, remembered: kept)
    }

    public enum ScanReason: Sendable { case launch, appear, periodic }

    public static func shouldScan(last: Date?, now: Date, reason: ScanReason) -> Bool {
        guard let last else { return true }
        let gap = now.timeIntervalSince(last)
        if gap < 0 { return true }                          // clock moved back
        switch reason {
        case .launch, .appear: return gap >= minimumGap
        case .periodic: return gap >= scanInterval - 5
        }
    }

    /// A notification click: only an update still in the latest scan opens the sheet
    /// (a stale or unknown path just opens Home).
    public static func requestForClick(path: String?, current: [GuardClient.DownloadedUpdate]) -> AppInstallRequest? {
        guard let path, let u = current.first(where: { $0.path == path }) else { return nil }
        return request(for: u)
    }
}

/// Files handed to Pax by Open With, the Dock icon or a drop on the window.
public enum AppOpenRouting {
    public enum Route: Equatable {
        /// The one-button confirmation sheet.
        case confirm(AppInstallRequest)
        /// This Mac isn't protected (no pax-guard): show the file in Finder instead.
        case reveal(URL)
        case ignore
    }

    /// Words in a disk image's name that aren't the app's name ("Writer-3.2-universal.dmg").
    static let noiseWords: Set<String> = ["mac", "macos", "osx", "universal", "arm64", "aarch64", "x64", "x86",
                                          "x86_64", "intel", "apple", "silicon", "darwin", "installer", "setup",
                                          "install", "latest", "release", "stable", "dmg"]

    /// The first file Pax can take; anything else is ignored (only one install at a time).
    public static func route(_ urls: [URL], protected: Bool,
                             isInstalled: (String) -> Bool = { _ in false }) -> Route {
        guard let url = urls.first(where: AppInstallRules.isInstallable) else { return .ignore }
        guard protected else { return .reveal(url) }
        let name = displayName(url)
        return .confirm(AppInstallRequest(path: url.path, name: name, isUpdate: isInstalled(name)))
    }

    /// "Writer.app" → Writer; "Writer-3.2.1-universal.dmg" → Writer; "Big App 2 v4.dmg" → Big App 2.
    public static func displayName(_ url: URL) -> String {
        let base = url.deletingPathExtension().lastPathComponent
        if url.pathExtension.lowercased() == "app" { return base }
        var words: [String] = []
        for raw in base.split(whereSeparator: { $0 == " " || $0 == "-" || $0 == "_" }) {
            let w = String(raw)
            let lower = w.lowercased()
            let looksLikeVersion = lower.first.map { $0.isNumber } == true && lower.contains(".")
                || (lower.hasPrefix("v") && lower.dropFirst().first.map { $0.isNumber } == true)
            if looksLikeVersion || noiseWords.contains(lower) { break }
            words.append(w)
        }
        let name = words.joined(separator: " ")
        return name.isEmpty ? base : name
    }
}
