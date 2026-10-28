// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// v0.8.34 (Ruben, 28 Oct 2026): on a protected Mac the everyday account is Standard, so dragging an
// app from a disk image to Applications (or a third-party updater) makes macOS ask for an
// administrator's name and password. People don't know Pax can install it for them. Two quiet
// pointers, both ending on the same sheet and the same pax-guard checks (nothing here installs
// or loosens anything):
//   1. a disk image with an app on it is mounted → Pax comes forward with "Install <App>?"
//      (or "Update <App>?"), once per disk, app and version;
//   2. macOS's own authorisation dialog appears → a small Pax panel beside it:
//      "Installing or updating an app?" / "Pax can do it for you." [Open Pax] [Not now].
//      Pax never reads or touches that dialog: it only sees that a SecurityAgent window is on
//      screen (owner and bounds from the window list, which need no Screen Recording permission).
// The rules live here (tested in V0834Tests); the AppKit side is Pax/InstallHelpersModel.swift.

/// A rectangle in the window server's coordinates (origin at the top-left of the main display,
/// y grows downwards), so the rules don't depend on CoreGraphics.
public struct HelperRect: Equatable, Sendable {
    public var x: Double, y: Double, width: Double, height: Double
    public init(x: Double, y: Double, width: Double, height: Double) {
        self.x = x; self.y = y; self.width = width; self.height = height
    }
    public var maxX: Double { x + width }
    public var maxY: Double { y + height }
    public var midX: Double { x + width / 2 }
}

/// "1.10.2" vs "1.9": numbers compared one by one; anything unreadable is "not newer".
public enum HelperVersion {
    static func parts(_ v: String) -> [Int]? {
        let trimmed = v.trimmingCharacters(in: .whitespaces)
        guard let first = trimmed.first, first.isNumber else { return nil }
        var out: [Int] = []
        var cur = ""
        for ch in trimmed {
            if ch.isNumber { cur.append(ch) } else {
                if !cur.isEmpty { out.append(Int(cur) ?? 0); cur = "" }
                if out.count >= 6 { break }
            }
        }
        if !cur.isEmpty && out.count < 6 { out.append(Int(cur) ?? 0) }
        return out.isEmpty ? nil : out
    }

    /// True only when both parse and `new` is higher.
    public static func isNewer(_ new: String, than old: String) -> Bool {
        guard let a = parts(new), let b = parts(old) else { return false }
        for i in 0..<max(a.count, b.count) {
            let x = i < a.count ? a[i] : 0, y = i < b.count ? b[i] : 0
            if x != y { return x > y }
        }
        return false
    }
}

// MARK: 1. a disk image with an app on it

public enum MountedAppPrompts {
    /// A top-level app on the mounted disk.
    public struct AppOnDisk: Equatable, Sendable {
        public let path: String          // "/Volumes/Writer/Writer.app"
        public let name: String          // display name
        public let bundleID: String
        public let version: String
        public init(path: String, name: String, bundleID: String, version: String) {
            self.path = path; self.name = name; self.bundleID = bundleID; self.version = version
        }
        public var folder: String { (path as NSString).lastPathComponent }
    }

    public struct Volume: Equatable, Sendable {
        public let mountPoint: String
        /// The .dmg behind it (from `hdiutil info`); nil when it isn't a disk image.
        public let imagePath: String?
        /// Volume UUID when macOS gives one, else mount point + image: the "same disk" key.
        public let identity: String
        public let isLocal: Bool
        public let hasTimeMachineMarkers: Bool
        public let apps: [AppOnDisk]
        public init(mountPoint: String, imagePath: String?, identity: String, isLocal: Bool,
                    hasTimeMachineMarkers: Bool, apps: [AppOnDisk]) {
            self.mountPoint = mountPoint; self.imagePath = imagePath; self.identity = identity
            self.isLocal = isLocal; self.hasTimeMachineMarkers = hasTimeMachineMarkers; self.apps = apps
        }
        public var name: String { (mountPoint as NSString).lastPathComponent }
    }

    public enum Decision: Equatable {
        case prompt(AppInstallRequest, key: String)
        case skip(String)
    }

    /// UserDefaults key: disk+app+version already offered (so a relaunch with the disk still
    /// mounted doesn't ask again).
    public static let rememberedKey = "pax.installs.mounted"
    public static let rememberLimit = 200
    /// At most this many apps are read from one disk.
    public static let maxApps = 20
    static let paxPrefixes = ["org.paxpeace.", "org.paxmobile."]
    static let timeMachineMarkers = ["Backups.backupdb", ".com.apple.timemachine.supported",
                                     ".com.apple.TimeMachine.SnapshotHistory.plist"]

    public static func key(_ v: Volume, _ app: AppOnDisk) -> String {
        "\(v.identity)|\(app.bundleID.lowercased())|\(app.version)"
    }

    /// Names on a disk's top level that mark it as a Time Machine disk.
    public static func isTimeMachine(topLevel names: [String]) -> Bool {
        names.contains { n in timeMachineMarkers.contains(n) || n.hasSuffix(".backupbundle")
            || n.hasSuffix(".sparsebundle") || n.hasSuffix(".previous") || n.hasSuffix(".inprogress") }
    }

    /// Whether to bring Pax forward for this disk, and with what.
    /// `installedVersion(bundleID)` is the version of that app in /Applications, or nil.
    public static func decide(_ v: Volume, protected: Bool, isAdmin: Bool, home: String,
                              installedVersion: (String) -> String?, remembered: Set<String>) -> Decision {
        guard protected else { return .skip("this Mac isn't protected") }
        guard !isAdmin else { return .skip("an administrator can install it themselves") }
        let rest = v.mountPoint.hasPrefix("/Volumes/") ? String(v.mountPoint.dropFirst("/Volumes/".count)) : ""
        guard !rest.isEmpty, !rest.contains("/"), !rest.hasPrefix(".") else { return .skip("not a mounted disk") }
        guard v.isLocal else { return .skip("a network disk") }
        guard !v.hasTimeMachineMarkers else { return .skip("a Time Machine disk") }
        guard let image = v.imagePath, image.lowercased().hasSuffix(".dmg") else {
            return .skip("not a disk image")
        }
        if v.apps.contains(where: { a in
            let b = a.bundleID.lowercased()
            return paxPrefixes.contains { b.hasPrefix($0) } || a.folder.lowercased() == "pax.app"
        }) { return .skip("Pax's own disk image") }
        var offers: [(AppOnDisk, Bool)] = []          // (app, is an update)
        for a in v.apps.prefix(maxApps) {
            let b = a.bundleID.lowercased()
            guard !b.isEmpty, !b.hasPrefix("com.apple.") else { continue }
            if let have = installedVersion(a.bundleID) {
                guard HelperVersion.isNewer(a.version, than: have) else { continue }   // nothing to do
                offers.append((a, true))
            } else {
                offers.append((a, false))
            }
        }
        guard !offers.isEmpty else { return .skip("nothing new to install") }
        if offers.count == 1 {
            let (a, isUpdate) = offers[0]
            let k = key(v, a)
            guard !remembered.contains(k) else { return .skip("already offered") }
            return .prompt(AppInstallRequest(path: a.path, name: a.name, isUpdate: isUpdate), key: k)
        }
        // Several apps: hand pax-guard the image itself (it asks which one), when it's somewhere
        // pax-guard accepts; otherwise offer the first.
        let k = "\(v.identity)|" + offers.map { key(v, $0.0) }.sorted().joined(separator: ",")
        guard !remembered.contains(k) else { return .skip("already offered") }
        if image.hasPrefix(home + "/") || image.hasPrefix("/Volumes/") {
            return .prompt(AppInstallRequest(path: image, name: v.name, isUpdate: false), key: k)
        }
        let (a, isUpdate) = offers[0]
        return .prompt(AppInstallRequest(path: a.path, name: a.name, isUpdate: isUpdate), key: k)
    }

    /// The remembered keys to save after offering `key` (oldest dropped past the limit).
    public static func remember(_ key: String, in list: [String]) -> [String] {
        var out = list.filter { $0 != key } + [key]
        if out.count > rememberLimit { out = Array(out.suffix(rememberLimit)) }
        return out
    }

    /// `hdiutil info -plist` → mount point → disk image path.
    public static func imagesByMountPoint(_ data: Data) -> [String: String] {
        guard let root = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
                as? [String: Any],
              let images = root["images"] as? [[String: Any]] else { return [:] }
        var out: [String: String] = [:]
        for img in images {
            guard let path = img["image-path"] as? String,
                  let ents = img["system-entities"] as? [[String: Any]] else { continue }
            for e in ents {
                if let mp = e["mount-point"] as? String, !mp.isEmpty { out[mp] = path }
            }
        }
        return out
    }
}

// MARK: 2. the panel beside macOS's administrator dialog

public enum AdminPromptHelper {
    public static let title = "Installing or updating an app?"
    public static let body = "Pax can do it for you."
    public static let openButton = "Open Pax"
    public static let notNowButton = "Not now"

    /// At most one panel this often.
    public static let rateLimit: TimeInterval = 120
    /// How often the window list is looked at (owner names and bounds only).
    public static let pollInterval: TimeInterval = 1.5
    /// Gap between the dialog and the panel.
    public static let gap: Double = 16

    /// The process that draws macOS's authorisation dialogs ("Finder wants to copy …").
    public static let agentOwnerNames: Set<String> = ["SecurityAgent"]
    public static let agentBundleIDs: Set<String> = ["com.apple.securityagent"]
    public static let agentExecutableSuffix = "/SecurityAgent.bundle/Contents/MacOS/SecurityAgent"

    /// One on-screen window as the window list gives it without Screen Recording permission:
    /// owner, owner pid, bounds, layer, alpha. Never its title or contents.
    public struct WindowInfo: Equatable, Sendable {
        public let number: Int
        public let ownerName: String?
        public let ownerBundleID: String?
        public let ownerPath: String?
        public let bounds: HelperRect
        public let alpha: Double
        public init(number: Int, ownerName: String?, ownerBundleID: String?, ownerPath: String?,
                    bounds: HelperRect, alpha: Double) {
            self.number = number; self.ownerName = ownerName; self.ownerBundleID = ownerBundleID
            self.ownerPath = ownerPath; self.bounds = bounds; self.alpha = alpha
        }
    }

    public static func isAgent(ownerName: String?, bundleID: String?, path: String?) -> Bool {
        if let n = ownerName, agentOwnerNames.contains(n) { return true }
        if let b = bundleID?.lowercased(), agentBundleIDs.contains(b) { return true }
        if let p = path, p.hasSuffix(agentExecutableSuffix) { return true }
        return false
    }

    /// A visible dialog-sized SecurityAgent window.
    public static func authDialog(in windows: [WindowInfo]) -> WindowInfo? {
        windows.first { w in
            isAgent(ownerName: w.ownerName, bundleID: w.ownerBundleID, path: w.ownerPath)
                && w.alpha > 0.05 && w.bounds.width >= 200 && w.bounds.height >= 100
        }
    }

    /// The app the person was using just before the dialog: Finder (dragging to Applications)
    /// or a third-party app (its updater). Apple's other apps (System Settings, Installer,
    /// Safari, Keychain Access...) ask for an administrator for other reasons; so does Pax itself.
    public static func isInstallContext(_ bundleID: String?) -> Bool {
        guard let b = bundleID?.lowercased(), !b.isEmpty else { return false }
        if b == "com.apple.finder" { return true }
        if b.hasPrefix("com.apple.") { return false }
        if b.hasPrefix("org.paxpeace.") || b.hasPrefix("org.paxmobile.") { return false }
        return true
    }

    public static func shouldShow(dialog: WindowInfo, now: Date, lastShown: Date?, shownWindows: Set<Int>,
                                  protected: Bool, isAdmin: Bool, previousApp: String?) -> Bool {
        guard protected, !isAdmin else { return false }
        guard !shownWindows.contains(dialog.number) else { return false }
        if let last = lastShown {
            let gap = now.timeIntervalSince(last)
            if gap >= 0 && gap < rateLimit { return false }
        }
        return isInstallContext(previousApp)
    }

    /// Top-left of the panel (window-server coordinates): to the right of the dialog, else to
    /// its left, else below it; always on `screen`.
    public static func panelOrigin(dialog: HelperRect, screen: HelperRect, panelWidth: Double,
                                   panelHeight: Double) -> (x: Double, y: Double) {
        func clampY(_ y: Double) -> Double { min(max(y, screen.y), screen.maxY - panelHeight) }
        let right = dialog.maxX + gap
        if right + panelWidth <= screen.maxX { return (right, clampY(dialog.y)) }
        let left = dialog.x - gap - panelWidth
        if left >= screen.x { return (left, clampY(dialog.y)) }
        let x = min(max(dialog.midX - panelWidth / 2, screen.x), screen.maxX - panelWidth)
        let below = dialog.maxY + gap
        if below + panelHeight <= screen.maxY { return (x, below) }
        return (x, clampY(dialog.y - gap - panelHeight))
    }

    /// Where "Open Pax" goes: the sheet already waiting, else the disk image just offered, else
    /// an update already downloaded, else Settings › Updates › Install or update an app.
    public enum OpenTarget: Equatable {
        case sheet(AppInstallRequest)
        case installer
    }

    public static func openTarget(pending: AppInstallRequest?, mounted: AppInstallRequest?,
                                  cards: [GuardClient.DownloadedUpdate]) -> OpenTarget {
        if let p = pending { return .sheet(p) }
        if let m = mounted { return .sheet(m) }
        if let c = cards.first { return .sheet(AppUpdatePrompts.request(for: c)) }
        return .installer
    }
}
