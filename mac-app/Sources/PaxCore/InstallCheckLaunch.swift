// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.35 (Ruben, 28 Oct 2026): Pax opens itself when the Standard user starts installing or updating
/// an app, even when Pax isn't running. On a Mac Pax protects, pax-guard starts Pax with
/// `--pax-install-check` when:
///   • a disk is mounted and a mounted volume has an app at its top level (a root-owned StartOnMount
///     LaunchAgent, /Library/LaunchAgents/org.paxpeace.pax-installs.plist; no reason argument);
///   • macOS's administrator dialog appears (`--pax-install-reason=auth`);
///   • an app's own updater runs or has downloaded an update (`--pax-install-reason=update`).
/// Pax then starts with no window and no Dock icon, and only comes forward when there is something to
/// offer: the "Install <App>?" sheet for a disk image, the floating "Pax can do it for you" panel beside
/// the dialog, or the "App update ready" card and notification. Nothing here installs anything:
/// every install still goes through pax-guard's checks.
public enum InstallCheckLaunch {
    public static let argument = "--pax-install-check"
    public static let reasonPrefix = "--pax-install-reason="
    public static let agentLabel = "org.paxpeace.pax-installs"
    public static let agentPath = "/Library/LaunchAgents/org.paxpeace.pax-installs.plist"
    /// How long after an `auth` launch an administrator dialog counts as an install even when the app
    /// that was in front isn't known (Pax wasn't running to see it).
    public static let authContextWindow: TimeInterval = 60

    public enum Reason: String, Equatable, Sendable {
        case mount, auth, update
    }

    /// Started by pax-guard or its mount agent (the flag after the executable).
    public static func isInstallCheck(_ arguments: [String]) -> Bool {
        arguments.dropFirst().contains(argument)
    }

    /// Why: `auth` / `update` from pax-guard, `mount` from the agent (no reason) or anything unknown.
    public static func reason(_ arguments: [String]) -> Reason? {
        guard isInstallCheck(arguments) else { return nil }
        for a in arguments.dropFirst() where a.hasPrefix(reasonPrefix) {
            return Reason(rawValue: String(a.dropFirst(reasonPrefix.count))) ?? .mount
        }
        return .mount
    }

    /// Start without showing a window: a login launch (v0.8.34) or an install check, unless the launch
    /// also asked Pax to open a file.
    public static func startHidden(arguments: [String], openedFiles: Bool) -> Bool {
        (LoginLaunch.isLoginLaunch(arguments) || isInstallCheck(arguments)) && !openedFiles
    }

    /// No Dock icon until Pax has something to show (install checks only; a login launch keeps its
    /// 0.8.34 behaviour).
    public static func startAsAccessory(arguments: [String], openedFiles: Bool) -> Bool {
        isInstallCheck(arguments) && !openedFiles
    }

    /// The admin-dialog panel may treat an unknown front app as an install: Pax was started because of
    /// that very dialog, within the last minute.
    public static func assumeInstallContext(reason: Reason?, launchedAt: Date, now: Date) -> Bool {
        guard reason == .auth else { return false }
        let gap = now.timeIntervalSince(launchedAt)
        return gap >= 0 && gap < authContextWindow
    }
}
