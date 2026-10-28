// SPDX-License-Identifier: GPL-3.0-only
import Foundation

// v0.8.33: Pax-approved installs and updates. On a protected Mac the everyday account
// is Standard, so macOS asks for an administrator to install or update an app in
// Applications. pax-guard (root) does it instead for apps it can check (guard/app_installs.py,
// docs/APP_INSTALLS.md). The app only passes a path; pax-guard reads, copies and checks
// everything itself, so nothing here can loosen Pax.

extension GuardClient {
    /// One install or update. `state` is working, installed, updated, refused or failed.
    public struct InstallJob: Decodable, Sendable, Equatable {
        public let id: Int
        public let state: String
        public let step: String?
        public let kind: String?
        public let source: String?
        public let name: String?
        public let version: String?
        public let code: String?
        public let error: String?
        public let options: [String]?
        public let category: String?
        public let dest: String?

        public var isWorking: Bool { state == "working" }
        public var succeeded: Bool { state == "installed" || state == "updated" }
    }

    /// An update an app's own updater already downloaded (Sparkle, Squirrel), newer than
    /// the copy in Applications. Installing it goes through every check.
    public struct DownloadedUpdate: Decodable, Sendable, Equatable, Identifiable {
        public let path: String
        public let name: String
        public let bundle_id: String
        public let version: String
        public let installed_version: String
        public var id: String { path }
    }

    public struct SystemUpdate: Decodable, Sendable, Equatable, Identifiable {
        public let label: String
        public let title: String
        public let version: String?
        public let restart: Bool?
        public let recommended: Bool?
        public let size: String?
        public var id: String { label }
    }

    /// Apple's software updates as pax-guard last saw them (`softwareupdate --list`).
    public struct SystemUpdates: Decodable, Sendable, Equatable {
        public let state: String               // idle, checking, installing, failed
        public let updates: [SystemUpdate]?
        public let checked_at: Int?
        public let code: String?
        public let error: String?
        public let restart_needed: Bool?
        public let installing: String?

        public var isBusy: Bool { state == "checking" || state == "installing" }
    }

    /// pax-guard copies the file into a root-only folder, checks the copy and installs it.
    /// Returns at once with the job working; poll `installStatus()`.
    public func startInstall(path: String, choice: String? = nil, updateOnly: Bool = false) async throws -> InstallJob {
        var req: [String: Any] = ["cmd": "installs.start", "path": path]
        if let choice { req["choice"] = choice }
        if updateOnly { req["update_only"] = true }
        return try decode(InstallJob.self, try await call(req), key: "job")
    }

    public func installStatus() async throws -> InstallJob? {
        let obj = try await call(["cmd": "installs.status"])
        guard obj["job"] is [String: Any] else { return nil }
        return try decode(InstallJob.self, obj, key: "job")
    }

    public func downloadedUpdates() async throws -> [DownloadedUpdate] {
        try decode([DownloadedUpdate].self, try await call(["cmd": "installs.updates"]), key: "updates")
    }

    public func systemUpdates() async throws -> SystemUpdates {
        try decode(SystemUpdates.self, try await call(["cmd": "system_updates.status"]), key: "system_updates")
    }

    public func checkSystemUpdates() async throws -> SystemUpdates {
        try decode(SystemUpdates.self, try await call(["cmd": "system_updates.check"]), key: "system_updates")
    }

    /// Never restarts the Mac: the user restarts when they're ready.
    public func installSystemUpdate(label: String) async throws -> SystemUpdates {
        try decode(SystemUpdates.self, try await call(["cmd": "system_updates.install", "label": label]),
                   key: "system_updates")
    }
}

/// What Pax can be handed to install (the guard checks again; this only keeps the
/// drop target and the file picker honest).
public enum AppInstallRules {
    public static let extensions = ["app", "dmg", "pkg"]

    public static func isInstallable(_ url: URL) -> Bool {
        url.isFileURL && extensions.contains(url.pathExtension.lowercased())
    }
}

/// v0.8.33 copy for Settings › Updates › Install or update an app. Calm and plain.
public enum AppInstallText {
    public static let rowTitle = "Install or update an app"
    public static let rowLine = "Pax checks the app and installs it for you. No administrator needed."
    public static let open = "Open…"
    public static let sheetTitle = "Install or update an app"
    public static let dropHint = "Drop an app or a disk image (.dmg) here"
    public static let choose = "Choose…"
    public static let close = "Done"
    public static let rules = [
        "Updates to apps you already have install straight away when they're from the same developer.",
        "New apps need to be signed by their developer and checked by Apple.",
        "Remote desktop, VPN, proxy and similar apps aren't installed here. They can get round Pax, "
            + "so they wait like turning Pax off.",
        "Installer packages (.pkg) wait too, except Apple's own.",
    ]
    public static let chooseOne = "Which one would you like to install?"

    public static let downloadedTitle = "Updates ready to install"
    public static let downloadedLine = "Downloaded by the apps themselves. Pax checks each one first."
    public static let installButton = "Install"

    public static let systemTitle = "Apple software updates"
    public static let systemLine = "Safari, security and macOS updates from Apple. Pax never restarts your Mac for you."
    public static let systemCheck = "Check for updates"
    public static let systemChecking = "Checking with Apple…"
    public static let systemInstalling = "Installing…"
    public static let systemNone = "Your Mac is up to date."
    public static let systemRestart = "Restart your Mac when you're ready to finish installing."

    /// The line shown while pax-guard works.
    public static func step(_ step: String?) -> String {
        switch step {
        case "opening": return "Opening the disk image…"
        case "checking": return "Checking the app…"
        case "installing": return "Installing…"
        default: return "Copying…"
        }
    }

    /// The one line after a job finishes successfully.
    public static func done(_ job: GuardClient.InstallJob) -> String {
        let name = (job.name?.isEmpty == false ? job.name : job.source) ?? "The app"
        let version = (job.version?.isEmpty == false) ? " \(job.version!)" : ""
        if job.state == "updated" { return "\(name) is updated to\(version.isEmpty ? " the new version" : version)." }
        return "\(name)\(version) is installed in Applications."
    }

    /// A refusal or failure: the catalog's calm sentence (with the kind of app for a
    /// blocked one) and what to do. The code goes with it, as on every error card.
    public static func problem(_ job: GuardClient.InstallJob) -> (message: String, action: String, code: String) {
        let code = job.code ?? "PAX-MAC-028"
        let info = PaxErrorCatalog.info(code)
        if code == "PAX-MAC-021", let category = job.category, !category.isEmpty {
            return ("Pax doesn't install \(category).", info.action, code)
        }
        return (info.message, info.action, code)
    }

    /// "Restart needed" (with a size when Apple gave one).
    public static func systemRow(_ u: GuardClient.SystemUpdate) -> String {
        var parts: [String] = []
        if let v = u.version, !v.isEmpty, !u.title.contains(v) { parts.append(v) }
        if u.restart == true { parts.append("restart needed") }
        return parts.joined(separator: " · ")
    }
}
