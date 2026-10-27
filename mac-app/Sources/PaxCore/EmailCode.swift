// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - v0.8.32 verified email for every new account

/// Every new Pax account proves its email with a 6-digit code before it exists
/// (POST /v1/accounts/email/start, then /verify; docs/ONETAP_ACCOUNTS.md). The same
/// two calls sign in to an account the address already has. This is the state of
/// that one step: where the code went, what was typed, when "Resend code" is allowed.
/// Pure value type so it can be tested without a server.
public struct EmailCodeState: Equatable, Sendable {
    public static let length = 6
    /// Server rules (server/pax_server/sync.py): 15 minutes, newest code only, 5 tries,
    /// 5 codes an hour for an address.
    public static let lifetime: TimeInterval = 15 * 60
    public static let codesPerHour = 5
    /// The app waits this long between sends, so a double click never sends two.
    public static let resendCooldown: TimeInterval = 30

    /// The address (normalised) the newest code went to; nil before the first send.
    public private(set) var sentTo: String?
    /// When codes were sent in the last hour (for the hourly limit).
    public private(set) var sends: [Date] = []
    /// What the user typed or pasted into the code field.
    public var code: String = ""
    /// One plain sentence shown under the field (wrong code, too many codes…).
    public var problem: String?

    public init() {}

    public static func normalized(_ email: String) -> String {
        email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// A light check before anything is sent (the server checks properly).
    public static func looksLikeEmail(_ email: String) -> Bool {
        let e = normalized(email)
        let parts = e.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !e.contains(" ") else { return false }
        let domain = parts[1]
        return domain.contains(".") && !domain.hasPrefix(".") && !domain.hasSuffix(".")
    }

    /// Paste-friendly: "123456", "123 456", "123-456" or the whole email text
    /// ("Your Pax code is 123456. It works for 15 minutes.") all give "123456".
    /// Anything shorter keeps just its digits, so typing works as usual.
    public static func digits(from text: String) -> String {
        let chars = Array(text)
        var i = 0
        while i < chars.count {
            if chars[i].isASCII && chars[i].isNumber {
                var j = i
                while j < chars.count && chars[j].isASCII && chars[j].isNumber { j += 1 }
                if j - i == length { return String(chars[i..<j]) }
                i = j
            } else {
                i += 1
            }
        }
        return String(text.filter { $0.isASCII && $0.isNumber }.prefix(length))
    }

    public var digits: String { Self.digits(from: code) }
    public var codeComplete: Bool { digits.count == Self.length }

    /// True when a code has gone to this address and the code field should show.
    /// Changing the email hides it again (the next Continue sends a new code).
    public func awaitingCode(for email: String) -> Bool {
        guard let sentTo else { return false }
        return sentTo == Self.normalized(email)
    }

    public mutating func didSend(to email: String, at now: Date) {
        sentTo = Self.normalized(email)
        sends = sends.filter { now.timeIntervalSince($0) < 3600 } + [now]
        code = ""
        problem = nil
    }

    /// After the account exists (or to start again). The hourly count is kept.
    public mutating func finish() {
        sentTo = nil
        code = ""
        problem = nil
    }

    /// Seconds until "Resend code" may send again: the short cooldown, or the hourly
    /// limit once 5 codes went out in the last hour. 0 = now.
    public func secondsUntilResend(now: Date) -> Int {
        let recent = sends.filter { now.timeIntervalSince($0) < 3600 }
        if recent.count >= Self.codesPerHour, let first = recent.min() {
            return max(0, Int((3600 - now.timeIntervalSince(first)).rounded(.up)))
        }
        guard let last = recent.max() else { return 0 }
        return max(0, Int((Self.resendCooldown - now.timeIntervalSince(last)).rounded(.up)))
    }
}

/// The words for the email step (calm, plain; shared by set-up and Settings).
public enum EmailCodeCopy {
    public static let why = "Pax emails you a 6-digit code to check it's yours. After that, it writes only "
        + "when someone asks to change or turn off Pax."
    public static func sent(to email: String) -> String {
        "We emailed a 6-digit code to \(email). Enter it here. It works for 15 minutes."
    }
    public static let sendButton = "Send code"
    public static let enterCode = "Enter the 6-digit code from the email."
    public static let enterEmail = "Enter your email address."
    public static let wrongCode = "That code isn't right or has expired. Check the newest email from Pax, "
        + "or send a new code."
    public static let tooMany = "Pax has sent too many codes for now. Wait a while, then send a new one."
    public static let badEmail = "Pax couldn't use that email address. Check it and try again."
    public static let oldServer = "This Pax server can't check email addresses yet. It needs Pax server "
        + "0.8.31 or later."

    public static func resendTitle(seconds: Int) -> String {
        if seconds <= 0 { return "Resend code" }
        if seconds >= 120 { return "Resend code in \((seconds + 59) / 60) min" }
        return "Resend code in \(seconds) s"
    }

    /// The sentence for a failed send (`checking` false) or code check (`checking` true).
    /// nil: not one of these, so the usual error card shows it with its support code.
    public static func message(for error: Error, checking: Bool) -> String? {
        guard let e = error as? EscrowClient.APIError else { return nil }
        switch e.status {
        case 401 where checking: return wrongCode
        case 429: return tooMany
        case 422: return checking ? enterCode : badEmail
        case 404, 405: return oldServer
        default: return nil
        }
    }
}

extension EscrowClient {
    /// POST /v1/accounts/email/verify: 201 a new account (created true), 200 a sign-in
    /// to the account the address already has (created false).
    public struct VerifiedAccount: Decodable, Sendable {
        public let account_id: String
        public let token: String
        public let created: Bool?
    }

    /// POST /v1/accounts/email/start: always 202 {"sent": true}, new address or not.
    public func startEmailCode(email: String) async throws {
        let _: [String: AnyDecodable] = try await send(
            "POST", "v1/accounts/email/start", body: ["email": EmailCodeState.normalized(email)])
    }

    public func verifyEmailCode(email: String, code: String, label: String) async throws -> VerifiedAccount {
        try await send("POST", "v1/accounts/email/verify", body: [
            "email": EmailCodeState.normalized(email),
            "code": EmailCodeState.digits(from: code),
            "label": String(label.prefix(100)),
        ])
    }
}

/// Thrown when a step needs the account but the email hasn't been confirmed yet
/// (defensive: the set-up screens confirm it first).
public struct EmailNotConfirmed: Error, LocalizedError, Equatable {
    public init() {}
    public var errorDescription: String? { "Confirm your email with the 6-digit code first." }
}
