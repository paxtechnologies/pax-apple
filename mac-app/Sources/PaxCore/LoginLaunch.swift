// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.34 (Ruben, 28 Oct 2026): Pax opens at login on a Mac it protects. pax-guard keeps a
/// root-owned LaunchAgent (/Library/LaunchAgents/org.paxpeace.pax-login.plist) that runs
/// `open -g -j -F -a /Applications/Pax.app --args --pax-login` in every login session. Pax starts
/// hidden in the background, so its window doesn't pop open at each login; it only comes forward
/// when something needs it (an install prompt, a notification, the Dock icon). Unprotected Macs
/// have no pax-guard, so no agent and no login launch.
public enum LoginLaunch {
    public static let argument = "--pax-login"
    public static let agentLabel = "org.paxpeace.pax-login"
    public static let agentPath = "/Library/LaunchAgents/org.paxpeace.pax-login.plist"

    /// True when this process was started by the login agent (the flag after the executable).
    public static func isLoginLaunch(_ arguments: [String]) -> Bool {
        arguments.dropFirst().contains(argument)
    }

    /// Stay hidden at launch: a login launch, unless the launch also asked Pax to open something
    /// (a file opened with Pax) — then Pax comes forward for it as usual.
    public static func startHidden(arguments: [String], openedFiles: Bool) -> Bool {
        isLoginLaunch(arguments) && !openedFiles
    }
}
