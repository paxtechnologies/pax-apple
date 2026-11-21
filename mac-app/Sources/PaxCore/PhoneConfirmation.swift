// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.8.38 (Ruben, 21 Nov 2026, Pax 0.8.37): after a reinstall Home listed three iPhones all
/// called "RDN", each saying "Protected". Only one was a real phone; the other two were set-ups
/// from 0.8.36 that stored a password and then failed to install, so nothing of theirs was ever
/// on a phone. The server can't tell them apart (they are ordinary unreleased devices, and
/// "checking in" is one DNS address shared by all of an account's iPhones and iPads), so
/// "Protected" was a claim this Mac couldn't back up.
///
/// Now a phone brought back from the account (PhoneReconnect.phonesToRestore) says
/// "Not confirmed" instead of "Protected" until it is confirmed:
///   * a plugged-in phone was matched to it by the protection profile's identifier
///     (`org.paxpeace.pax.ios.<uuid>`, unique per set-up), or
///   * it is unambiguous: the only unreleased USB-set-up iPhone or iPad on the whole account,
///     and the server says the account's phones are checking in. Checking in is shared by
///     every phone on the account, so it only speaks for one phone when there is only one.
///     A unique name alone isn't enough: a set-up that never finished can have a unique name.
/// Phones set up from this copy of the app were confirmed at set-up.
///
/// Only the all-is-well headlines (Protected, trial day) give way. A turn-off wait, Turned off
/// and Not checking in are facts the server holds about that set-up and always show as they
/// are. Nothing here hides, disables or changes any protection, turn-off wait, emergency or
/// support action; the turn-off card stays exactly as before, and no new removal is offered.
public enum PhoneConfirmation {
    /// - Parameters:
    ///   - restored: brought back from the account, not set up from this copy of the app.
    ///   - matchedOnPhone: a plugged-in phone carried this set-up's profile identifier.
    ///   - notOnPhone: a phone with this name was plugged in and this set-up's profile wasn't on it.
    ///   - unambiguous: see `isUnambiguous`.
    public static func isConfirmed(restored: Bool, matchedOnPhone: Bool, notOnPhone: Bool,
                                   unambiguous: Bool) -> Bool {
        if notOnPhone { return false }
        return !restored || matchedOnPhone || unambiguous
    }

    /// The only unreleased USB-set-up iPhone or iPad on the account (hidden ones count: they are
    /// still on the account and share its DNS address), it is this one, and it is checking in.
    public static func isUnambiguous(deviceID: String, account: [PhoneReconnect.ServerPhone],
                                     checkingIn: Bool?) -> Bool {
        guard checkingIn == true else { return false }
        let phones = account.filter { !$0.isMac && !$0.released && PhoneReconnect.isPhoneProfile($0.profileIdentifier) }
        return phones.count == 1 && phones[0].deviceID == deviceID
    }

    /// Whether Home says "Not confirmed" in place of the server's state. nil (no answer from
    /// the server yet) counts as all-is-well, which Home used to show as "Protected".
    public static func showsNotConfirmed(_ state: PhoneStatus.State?, confirmed: Bool) -> Bool {
        guard !confirmed else { return false }
        switch state {
        case nil, .protected?, .trial?: return true
        case .turningOff?, .turnedOff?, .notCheckingIn?: return false
        }
    }

    /// Records saved by 0.8.37 that were already matched: 0.8.37 marked every other set-up with
    /// the same name as "not on this phone" when one was recognised, and nothing else sets that
    /// mark. So a restored record whose same-named siblings all carry it was the match.
    public static func wasMatchedBefore(notOnPhone: Bool, sameNameSiblingsNotOnPhone: [Bool]) -> Bool {
        !notOnPhone && !sameNameSiblingsNotOnPhone.isEmpty && sameNameSiblingsNotOnPhone.allSatisfy { $0 }
    }

    // MARK: Words (calm, plain)

    public static let headline = "Not confirmed"
    public static let sidebarLabel = "Not confirmed"

    /// Under the headline, for one unconfirmed phone (no other with its name).
    public static func line(name: String, isIPad: Bool) -> String {
        let kind = isIPad ? "iPad" : "iPhone"
        return "Pax hasn't matched \(name) to an \(kind) yet. Plug it in and choose Add iPhone or iPad to check. "
            + "Nothing will be installed again."
    }

    /// Device details row.
    public static let detailsValue = "Not confirmed"
}
