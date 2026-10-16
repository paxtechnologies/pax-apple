// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.7: the user's own blocked apps.
///
/// iPhone/iPad: picked at set-up from the phone's installed apps (the bundled
/// helper's `apps` command) or typed as a bundle ID, and written into the locked
/// profile's blockedAppBundleIDs; they can't change until the phone is set up again.
/// Mac: a Blocked apps list kept and enforced by pax-guard (GuardClient `apps.*`).
///
/// Never blocked (project decision): Pax itself, Apple's own apps, password
/// managers. Same rules as profile/app_blocks.py and guard/guard_config.py.
public enum AppBlockRules {
    public static let maxCustomIPhoneApps = 200
    public static let maxMacApps = 200
    static let neverBlockPrefixes = ["com.apple.", "org.paxmobile.", "org.paxpeace."]
    static let passwordManagerBundleIDs: Set<String> = [
        "com.1password.1password", "com.agilebits.onepassword7", "com.agilebits.onepassword-osx",
        "com.1password.safari",
        "com.8bit.bitwarden", "com.bitwarden.desktop",
        "com.lastpass.ilastpass", "com.lastpass.lastpass", "com.lastpass.lastpassforsafari",
        "com.dashlane.dashlanephonefinal",
        "me.proton.pass.ios", "me.proton.pass.catalyst", "me.proton.pass.electron",
        "com.keepassium.ios", "org.keepassxc.keepassxc",
        "com.markmcguill.strongbox", "com.markmcguill.strongbox.pro", "com.markmcguill.strongbox.mac",
        "in.sinew.walletx", "in.sinew.enpass-desktop",
        "com.callpod.keepermac.lite", "com.keepersecurity.safari.keeperfill",
        "com.nordpass.ios.app.password.manager", "com.nordpass.safari.app.password.manager",
    ]
    static let passwordManagerNames = ["1password", "bitwarden", "lastpass", "dashlane", "proton pass", "keepass",
                                       "strongbox", "enpass", "keeper password", "nordpass", "roboform"]

    /// Why an app may never be blocked, in plain words, or nil.
    public static func protectedReason(bundleID: String, name: String = "") -> String? {
        let bid = bundleID.trimmingCharacters(in: .whitespaces).lowercased()
        for prefix in neverBlockPrefixes where bid.hasPrefix(prefix) {
            return prefix.contains("pax") ? "Pax itself" : "one of Apple's own apps"
        }
        if passwordManagerBundleIDs.contains(bid) { return "a password manager" }
        let lname = name.lowercased()
        if passwordManagerNames.contains(where: { lname.contains($0) }) { return "a password manager" }
        return nil
    }

    /// A reverse-DNS bundle ID such as com.example.app.
    public static func isPlausibleBundleID(_ raw: String) -> Bool {
        let s = raw.trimmingCharacters(in: .whitespaces)
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2, s.count <= 255 else { return false }
        let ok = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        for (i, p) in parts.enumerated() {
            guard !p.isEmpty, p.unicodeScalars.allSatisfy({ ok.contains($0) && $0.isASCII }) else { return false }
            if i == 0, p.first == "-" || p.first == "_" { return false }
        }
        return true
    }

    /// Typed bundle ID -> accepted ID, or the reason it isn't.
    public static func checkTyped(_ raw: String) -> Result<String, AppBlockProblem> {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isPlausibleBundleID(s) else { return .failure(.notAnAppID) }
        if let why = protectedReason(bundleID: s) { return .failure(.neverBlocked(why)) }
        return .success(s)
    }

    /// How many of `chosen` count against the cap (apps Pax blocks anyway don't).
    public static func customCount(_ chosen: [String], paxBlocked: [String]) -> Int {
        let pax = Set(paxBlocked.map { $0.lowercased() })
        return Set(chosen.map { $0.lowercased() }).subtracting(pax).count
    }
}

public enum AppBlockProblem: Error, Equatable {
    case notAnAppID
    case neverBlocked(String)

    public var message: String {
        switch self {
        case .notAnAppID: return "That doesn't look like an app ID (for example com.example.app)."
        case .neverBlocked(let why): return "That can't be blocked: it's \(why)."
        }
    }
}

/// One app on the connected iPhone (helper `apps`).
public struct IPhoneApp: Equatable, Sendable, Identifiable {
    public var id: String { bundleID }
    public let bundleID: String
    public let name: String
    public let version: String
    /// Pax blocks it on every iPhone anyway (bypass apps, remote AI browsers).
    public let paxBlocks: Bool
    public let canBlock: Bool
    public let whyNot: String
    /// A PNG of its home-screen icon, when the helper could fetch it.
    public let iconPath: String?

    public init(bundleID: String, name: String, version: String = "", paxBlocks: Bool = false,
                canBlock: Bool = true, whyNot: String = "", iconPath: String? = nil) {
        self.bundleID = bundleID
        self.name = name
        self.version = version
        self.paxBlocks = paxBlocks
        self.canBlock = canBlock
        self.whyNot = whyNot
        self.iconPath = iconPath
    }
}

public struct IPhoneAppList: Equatable, Sendable {
    public let apps: [IPhoneApp]
    public let paxBlocked: [String]
    public let maxCustom: Int

    public init(json: [String: Any]) {
        let rows = json["apps"] as? [[String: Any]] ?? []
        apps = rows.compactMap { r in
            guard let bid = r["bundle_id"] as? String, !bid.isEmpty else { return nil }
            return IPhoneApp(bundleID: bid, name: r["name"] as? String ?? bid, version: r["version"] as? String ?? "",
                             paxBlocks: r["pax_blocks"] as? Bool ?? false, canBlock: r["can_block"] as? Bool ?? true,
                             whyNot: r["why_not"] as? String ?? "", iconPath: r["icon"] as? String)
        }
        paxBlocked = json["pax_blocked"] as? [String] ?? []
        maxCustom = json["max_custom"] as? Int ?? AppBlockRules.maxCustomIPhoneApps
    }

    /// Case-insensitive search on name or bundle ID.
    public func filtered(_ query: String) -> [IPhoneApp] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return apps }
        return apps.filter { $0.name.lowercased().contains(q) || $0.bundleID.lowercased().contains(q) }
    }
}

extension KeepDataSupervisor {
    /// v0.8.7: the iPhone's own apps for the set-up picker (the phone must trust this Mac).
    public func installedApps(udid: String, iconsDirectory: URL? = nil) async throws -> IPhoneAppList {
        var extra: [String] = []
        if let iconsDirectory { extra += ["--icons-dir", iconsDirectory.path] }
        return IPhoneAppList(json: try await helper.call("apps", udid: udid, extra: extra))
    }
}

/// An app in /Applications for the Mac's Blocked apps picker.
public struct InstalledMacApp: Equatable, Sendable, Identifiable {
    public var id: String { path }
    public let path: String
    public let name: String
    public let bundleID: String
    /// nil when it may be blocked; else why not (pax-guard checks again, as root).
    public let whyNot: String?

    public init(path: String, name: String, bundleID: String, whyNot: String? = nil) {
        self.path = path
        self.name = name
        self.bundleID = bundleID
        self.whyNot = whyNot
    }
}

public enum MacAppScanner {
    /// Top-level .app bundles in `directories` (default /Applications and ~/Applications),
    /// sorted by name. Reads only Info.plist; pax-guard reads the signature itself.
    public static func installedApps(directories: [URL]? = nil,
                                     fileManager: FileManager = .default) -> [InstalledMacApp] {
        let dirs = directories ?? [URL(fileURLWithPath: "/Applications"),
                                   fileManager.homeDirectoryForCurrentUser.appendingPathComponent("Applications")]
        var out: [InstalledMacApp] = []
        var seen = Set<String>()
        for dir in dirs {
            guard let names = try? fileManager.contentsOfDirectory(atPath: dir.path) else { continue }
            for n in names where n.lowercased().hasSuffix(".app") {
                let url = dir.appendingPathComponent(n)
                guard let app = read(url), !seen.contains(app.path) else { continue }
                seen.insert(app.path)
                out.append(app)
            }
        }
        return out.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    static func read(_ url: URL) -> InstalledMacApp? {
        let plistURL = url.appendingPathComponent("Contents/Info.plist")
        guard let data = try? Data(contentsOf: plistURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let bid = plist["CFBundleIdentifier"] as? String, !bid.isEmpty else { return nil }
        let folder = url.deletingPathExtension().lastPathComponent
        let name = (plist["CFBundleDisplayName"] as? String) ?? (plist["CFBundleName"] as? String) ?? folder
        return InstalledMacApp(path: url.path, name: name, bundleID: bid,
                               whyNot: AppBlockRules.protectedReason(bundleID: bid, name: name))
    }
}
