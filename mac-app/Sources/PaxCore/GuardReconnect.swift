// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.34 (Ruben, 28 Oct 2026): Pax.app was deleted (e.g. by a cleaner app) together with its
/// preferences, but pax-guard (root, /Library/PaxGuard) is still protecting the Mac. The reinstalled
/// app has no saved device, so it used to offer set-up and fail with PAX-MAC-002 on the Standard
/// account. Instead it asks pax-guard first and reconnects to the protection that is already there.
/// This gives nothing away: it only brings back Home and the turn-off wait.
public enum GuardReconnect {
    public enum Decision: Equatable, Sendable {
        /// Nothing to do: the app knows its device, or pax-guard isn't protecting this Mac.
        case none
        /// pax-guard holds this Mac's key itself: restore deviceID "local" and open on Home.
        case reconnectLocal
        /// pax-guard protects this Mac with the key on the Pax server: don't guess an ID,
        /// show `serverMessage` instead of set-up.
        case protectedByServer
    }

    /// The device ID the app keeps for a Mac whose key pax-guard holds.
    public static let localDeviceID = "local"

    public static let serverMessage = "Pax is still protecting this Mac. Open the Pax account you set it up with, or contact hello@paxpeace.com."

    /// - Parameters:
    ///   - savedDeviceID: the app's saved pax.mac.deviceID (nil after the preferences were wiped).
    ///   - guardEscrowMode: pax-guard's `status` escrow_mode, or nil when pax-guard didn't answer.
    ///   - localEscrowHeld: pax-guard answered `escrow.status` with a device (no error).
    public static func decide(savedDeviceID: String?, guardEscrowMode: String?,
                              localEscrowHeld: Bool) -> Decision {
        if let id = savedDeviceID, !id.isEmpty { return .none }
        switch guardEscrowMode {
        case "local": return localEscrowHeld ? .reconnectLocal : .none
        case "server": return .protectedByServer
        default: return .none
        }
    }

    /// Set-up (and its PAX-MAC-002 administrator check) is only offered when this is `.none`.
    public static func offersSetUp(_ d: Decision) -> Bool { d == .none }
}
