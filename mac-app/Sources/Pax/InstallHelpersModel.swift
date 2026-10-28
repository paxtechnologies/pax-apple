// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI
import AppKit
import CoreGraphics
import Darwin
import PaxCore

// v0.8.34 (Ruben, 28 Oct 2026): point the Standard user at Pax when macOS would ask for an
// administrator to install or update an app. Rules: PaxCore/InstallHelpers.swift (V0834Tests).
//   1. A disk image with an app on it is mounted → Pax comes forward with the same
//      "Install <App>?" / "Update <App>?" sheet, once per disk, app and version.
//   2. macOS's authorisation dialog (a SecurityAgent window) appears just after Finder or a
//      third-party app was in front → a small floating Pax panel beside it, at most every two
//      minutes. Pax only reads the window list's owner, pid and bounds (no Screen Recording
//      permission needed; titles and contents aren't available to it and aren't asked for),
//      and never clicks, types into, moves or reads the dialog.
// Both only on a Mac Pax protects, for a Standard account. Every install still goes through
// installs.start and pax-guard's checks.

@MainActor
final class InstallHelpersModel {
    static let shared = InstallHelpersModel()

    private var isProtected: () -> Bool = { false }
    private var showSettings: () -> Void = {}
    private var attached = false
    private let isAdmin = InstallHelpersModel.currentUserIsAdmin()
    private let defaults = UserDefaults.standard

    // 1. disk images
    private var offeredThisSession = Set<String>()
    /// The latest disk-image offer still mounted ("Open Pax" goes there).
    private(set) var mountedRequest: AppInstallRequest?
    private var mountedRequestMount: String?

    // 2. the panel
    private var poll: Timer?
    private var lastShown: Date?
    private var shownWindows = Set<Int>()
    private var previousApp: String?
    private var panel: NSPanel?
    private var panelDialog: Int?
    private var pidInfo: [pid_t: (bundle: String?, path: String?)] = [:]

    private var observers: [NSObjectProtocol] = []

    // v0.8.35: why pax-guard started Pax (nil: opened normally), and when.
    private let launchReason = InstallCheckLaunch.reason(ProcessInfo.processInfo.arguments)
    private let launchedAt = Date()

    func attach(isProtected: @escaping () -> Bool, showSettings: @escaping () -> Void) {
        guard !attached else { return }
        attached = true
        self.isProtected = isProtected
        self.showSettings = showSettings
        let center = NSWorkspace.shared.notificationCenter
        observers.append(center.addObserver(forName: NSWorkspace.didMountNotification, object: nil,
                                            queue: .main) { note in
            let url = note.userInfo?[NSWorkspace.volumeURLUserInfoKey] as? URL
            Task { @MainActor in if let url { InstallHelpersModel.shared.volumeMounted(url) } }
        })
        observers.append(center.addObserver(forName: NSWorkspace.didUnmountNotification, object: nil,
                                            queue: .main) { note in
            let url = note.userInfo?[NSWorkspace.volumeURLUserInfoKey] as? URL
            Task { @MainActor in InstallHelpersModel.shared.volumeUnmounted(url) }
        })
        observers.append(center.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil,
                                            queue: .main) { note in
            let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
            let bundle = app?.bundleIdentifier
            Task { @MainActor in InstallHelpersModel.shared.appActivated(bundle) }
        })
        appActivated(NSWorkspace.shared.frontmostApplication?.bundleIdentifier)
        // Disks already mounted when Pax opens.
        let keys: [URLResourceKey] = [.volumeIsLocalKey, .volumeUUIDStringKey]
        for url in FileManager.default.mountedVolumeURLs(includingResourceValuesForKeys: keys,
                                                         options: [.skipHiddenVolumes]) ?? [] {
            volumeMounted(url)
        }
        poll = Timer.scheduledTimer(withTimeInterval: AdminPromptHelper.pollInterval, repeats: true) { _ in
            Task { @MainActor in InstallHelpersModel.shared.lookForDialog() }
        }
    }

    // MARK: 1. a disk image with an app on it

    private func volumeMounted(_ url: URL) {
        guard isProtected(), !isAdmin else { return }
        let home = NSHomeDirectory()
        Task.detached(priority: .utility) {
            guard let volume = InstallHelpersModel.readVolume(url) else { return }
            let installed = InstallHelpersModel.installedVersions(for: volume.apps.map(\.bundleID))
            await MainActor.run {
                InstallHelpersModel.shared.offer(volume, home: home, installed: installed)
            }
        }
    }

    private func offer(_ volume: MountedAppPrompts.Volume, home: String, installed: [String: String]) {
        let saved = defaults.stringArray(forKey: MountedAppPrompts.rememberedKey) ?? []
        let remembered = offeredThisSession.union(saved)
        let decision = MountedAppPrompts.decide(volume, protected: isProtected(), isAdmin: isAdmin, home: home,
                                                installedVersion: { installed[$0.lowercased()] },
                                                remembered: remembered)
        guard case .prompt(let request, let key) = decision else { return }
        // Offered once: dismissing it doesn't bring it back for this disk, app and version.
        offeredThisSession.insert(key)
        defaults.set(MountedAppPrompts.remember(key, in: saved), forKey: MountedAppPrompts.rememberedKey)
        mountedRequest = request
        mountedRequestMount = volume.mountPoint
        AppUpdatesModel.shared.present(request)
    }

    /// A job from the sheet finished: that disk image has been dealt with.
    func jobFinished(path: String?) {
        if let path, path == mountedRequest?.path {
            mountedRequest = nil
            mountedRequestMount = nil
        }
    }

    private func volumeUnmounted(_ url: URL?) {
        guard let mount = mountedRequestMount else { return }
        if url == nil || url!.standardizedFileURL.path == mount {
            mountedRequest = nil
            mountedRequestMount = nil
        }
    }

    /// Off the main thread: what's on the disk, and the image behind it.
    nonisolated static func readVolume(_ url: URL) -> MountedAppPrompts.Volume? {
        let mount = url.standardizedFileURL.path
        guard mount.hasPrefix("/Volumes/") else { return nil }
        let values = try? url.resourceValues(forKeys: [.volumeIsLocalKey, .volumeUUIDStringKey])
        let image = hdiutilImages()[mount]
        let fm = FileManager.default
        let names = (try? fm.contentsOfDirectory(atPath: mount)) ?? []
        var apps: [MountedAppPrompts.AppOnDisk] = []
        for n in names.sorted() where n.lowercased().hasSuffix(".app") && !n.hasPrefix(".") {
            let path = (mount as NSString).appendingPathComponent(n)
            guard let attrs = try? fm.attributesOfItem(atPath: path),
                  attrs[.type] as? FileAttributeType == .typeDirectory else { continue }   // no links
            let plist = NSDictionary(contentsOfFile: path + "/Contents/Info.plist") as? [String: Any] ?? [:]
            let bid = plist["CFBundleIdentifier"] as? String ?? ""
            let name = (plist["CFBundleDisplayName"] as? String) ?? (plist["CFBundleName"] as? String)
                ?? String(n.dropLast(4))
            apps.append(.init(path: path, name: name, bundleID: bid,
                              version: plist["CFBundleShortVersionString"] as? String ?? ""))
            if apps.count >= MountedAppPrompts.maxApps { break }
        }
        let identity = values?.volumeUUIDString ?? "\(mount)|\(image ?? "")"
        return .init(mountPoint: mount, imagePath: image, identity: identity,
                     isLocal: values?.volumeIsLocal ?? false,
                     hasTimeMachineMarkers: MountedAppPrompts.isTimeMachine(topLevel: names), apps: apps)
    }

    /// `hdiutil info -plist`: which mounted disks are disk images (no administrator needed).
    nonisolated static func hdiutilImages() -> [String: String] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        p.arguments = ["info", "-plist"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return [:] }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return MountedAppPrompts.imagesByMountPoint(data)
    }

    /// bundle ID (lower-cased) → version of that app directly in /Applications.
    nonisolated static func installedVersions(for bundleIDs: [String]) -> [String: String] {
        var out: [String: String] = [:]
        for bid in bundleIDs where !bid.isEmpty {
            for url in NSWorkspace.shared.urlsForApplications(withBundleIdentifier: bid)
            where url.deletingLastPathComponent().path == "/Applications" {
                let plist = NSDictionary(contentsOfFile: url.path + "/Contents/Info.plist") as? [String: Any]
                out[bid.lowercased()] = plist?["CFBundleShortVersionString"] as? String ?? ""
            }
        }
        return out
    }

    // MARK: 2. the panel beside macOS's administrator dialog

    private func appActivated(_ bundle: String?) {
        guard let b = bundle?.lowercased(), !b.isEmpty else { return }
        // The dialog itself and Pax don't count as "what the person was doing".
        if AdminPromptHelper.agentBundleIDs.contains(b) || b == Bundle.main.bundleIdentifier?.lowercased() {
            return
        }
        previousApp = bundle
    }

    private func lookForDialog() {
        guard isProtected(), !isAdmin else { closePanel(); return }
        let windows = currentWindows()
        let dialog = AdminPromptHelper.authDialog(in: windows)
        if let shown = panelDialog, dialog?.number != shown {
            closePanel()                               // the dialog went away
        }
        guard let dialog, panel == nil else { return }
        let now = Date()
        guard AdminPromptHelper.shouldShow(dialog: dialog, now: now, lastShown: lastShown,
                                           shownWindows: shownWindows, protected: true, isAdmin: isAdmin,
                                           previousApp: previousApp,
                                           assumeInstallWhenUnknown: InstallCheckLaunch.assumeInstallContext(
                                               reason: launchReason, launchedAt: launchedAt, now: now))
        else { return }
        lastShown = now
        shownWindows.insert(dialog.number)
        if shownWindows.count > 50 { shownWindows = [dialog.number] }
        showPanel(beside: dialog)
    }

    /// On-screen windows: number, owner name, owner pid, bounds and alpha only. Owner names may be
    /// missing without Screen Recording (macOS 26), so the pid's bundle ID / executable path are
    /// looked up for unnamed windows.
    private func currentWindows() -> [AdminPromptHelper.WindowInfo] {
        guard let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements],
                                                    kCGNullWindowID) as? [[String: Any]] else { return [] }
        var out: [AdminPromptHelper.WindowInfo] = []
        var seenPids = Set<pid_t>()
        for w in list {
            guard let number = w[kCGWindowNumber as String] as? Int,
                  let pidNum = w[kCGWindowOwnerPID as String] as? Int,
                  let b = w[kCGWindowBounds as String] as? [String: Any] else { continue }
            let pid = pid_t(pidNum)
            let owner = w[kCGWindowOwnerName as String] as? String
            var bundle: String?
            var path: String?
            if owner == nil || owner == "SecurityAgent" {
                if pidInfo[pid] == nil { pidInfo[pid] = Self.describe(pid) }
                seenPids.insert(pid)
                bundle = pidInfo[pid]?.bundle
                path = pidInfo[pid]?.path
            }
            func num(_ k: String) -> Double { (b[k] as? NSNumber)?.doubleValue ?? 0 }
            let alpha = (w[kCGWindowAlpha as String] as? NSNumber)?.doubleValue ?? 1
            out.append(.init(number: number, ownerName: owner, ownerBundleID: bundle, ownerPath: path,
                             bounds: HelperRect(x: num("X"), y: num("Y"), width: num("Width"), height: num("Height")),
                             alpha: alpha))
        }
        if pidInfo.count > 200 { pidInfo = pidInfo.filter { seenPids.contains($0.key) } }
        return out
    }

    private static func describe(_ pid: pid_t) -> (bundle: String?, path: String?) {
        let app = NSRunningApplication(processIdentifier: pid)
        var buf = [CChar](repeating: 0, count: 4096)
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        let path = n > 0 ? String(cString: buf) : app?.executableURL?.path
        return (app?.bundleIdentifier, path)
    }

    private func showPanel(beside dialog: AdminPromptHelper.WindowInfo) {
        let size = NSSize(width: 300, height: 128)
        guard let primary = NSScreen.screens.first else { return }
        let primaryHeight = primary.frame.height
        // Window-server rect (top-left origin) → the screen it's on, in the same coordinates.
        let d = dialog.bounds
        let centre = NSPoint(x: d.midX, y: primaryHeight - (d.y + d.height / 2))
        let screen = NSScreen.screens.first { $0.frame.contains(centre) } ?? primary
        let vf = screen.visibleFrame
        let screenRect = HelperRect(x: vf.minX, y: primaryHeight - vf.maxY, width: vf.width, height: vf.height)
        let o = AdminPromptHelper.panelOrigin(dialog: d, screen: screenRect, panelWidth: size.width,
                                              panelHeight: size.height)
        let frame = NSRect(x: o.x, y: primaryHeight - o.y - size.height, width: size.width, height: size.height)

        let p = HelperPanel(contentRect: frame, styleMask: [.borderless, .nonactivatingPanel],
                            backing: .buffered, defer: false)
        p.isFloatingPanel = true
        p.level = .modalPanel
        p.hidesOnDeactivate = false
        p.isOpaque = false
        p.backgroundColor = .clear
        p.hasShadow = true
        p.isMovableByWindowBackground = true
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]
        p.contentView = NSHostingView(rootView: AdminHelperPanelView(
            open: { InstallHelpersModel.shared.openPax() },
            notNow: { InstallHelpersModel.shared.closePanel() }))
        if NSApp.isHidden {
            // Started hidden at login: show only the panel, not Pax's window.
            PaxActivation.orderOutMainWindows()
            NSApp.unhideWithoutActivation()
        }
        p.orderFrontRegardless()                       // never takes focus from the dialog
        panel = p
        panelDialog = dialog.number
    }

    func closePanel() {
        panel?.orderOut(nil)
        panel = nil
        panelDialog = nil
    }

    /// "Open Pax": the sheet already waiting, the disk image just offered, a downloaded update,
    /// or Settings › Updates › Install or update an app.
    func openPax() {
        closePanel()
        let updates = AppUpdatesModel.shared
        switch AdminPromptHelper.openTarget(pending: updates.pending, mounted: mountedRequest, cards: updates.cards) {
        case .sheet(let r):
            updates.present(r)
        case .installer:
            showSettings()
            updates.openInstaller()
        }
    }

    // MARK: Standard or administrator

    /// Member of the admin group (gid 80)? If macOS won't say, treated as an administrator:
    /// the helpers then stay quiet (they only ever point at Pax; nothing is loosened either way).
    nonisolated static func currentUserIsAdmin() -> Bool {
        guard let pw = getpwuid(getuid()), let name = pw.pointee.pw_name else { return true }
        var count: Int32 = 64
        var groups = [Int32](repeating: 0, count: Int(count))
        let base = Int32(bitPattern: pw.pointee.pw_gid)
        if getgrouplist(name, base, &groups, &count) == -1 {
            groups = [Int32](repeating: 0, count: Int(count) + 64)
            count = Int32(groups.count)
            if getgrouplist(name, base, &groups, &count) == -1 { return true }
        }
        return groups.prefix(Int(count)).contains(80)
    }
}

/// A borderless panel that can take a click without making Pax the active app.
final class HelperPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

/// "Installing or updating an app?" / "Pax can do it for you." [Not now] [Open Pax]
struct AdminHelperPanelView: View {
    let open: () -> Void
    let notNow: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(AdminPromptHelper.title).font(Theme.body(14, weight: .medium)).foregroundStyle(Theme.primaryText)
            Text(AdminPromptHelper.body).font(Theme.body(13)).foregroundStyle(Theme.mutedText)
            HStack {
                Spacer()
                Button(AdminPromptHelper.notNowButton, action: notNow).buttonStyle(SecondaryButtonStyle())
                Button(AdminPromptHelper.openButton, action: open).buttonStyle(PrimaryButtonStyle(accent: true))
            }
        }
        .padding(16)
        .frame(width: 300, height: 128)
        .background(RoundedRectangle(cornerRadius: Theme.smallRadius).fill(Theme.card))
        .overlay(RoundedRectangle(cornerRadius: Theme.smallRadius).stroke(Theme.border))
    }
}
