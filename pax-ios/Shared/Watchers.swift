// SPDX-License-Identifier: GPL-3.0-only
// What Pax notices on launch and tells the trusted person about. iPhone lets anyone
// switch the encrypted DNS off in Settings, and lets someone with the Screen Time
// passcode (or Face ID, without one) switch Pax's Screen Time access off. Pax can't stop
// either; it says so plainly and sends one email per event.
import Foundation

enum DNSAlert: Equatable {
    case none
    /// The DNS was on and is now off. `key` marks this off-period so it's sent once.
    case switchedOff(key: String)
    /// A day after set-up the DNS has never been switched on.
    case neverOn
}

enum DNSWatch {
    /// How long after set-up a DNS that was never switched on is worth an email.
    static let neverOnAfter: TimeInterval = 86_400

    /// Updates the policy's DNS fields from what iPhone reports and says which email (if
    /// any) is due. The caller records `dnsAlertSent` only after the email went out, so a
    /// failed email is tried again next time.
    static func update(_ p: inout PaxPolicy, isEnabled: Bool, now: Date) -> DNSAlert {
        guard p.isActive, p.dnsInstalled else { return .none }
        if isEnabled {
            p.dnsSeenOn = true
            p.dnsOffSince = nil
            if p.dnsAlertSent != "never" { p.dnsAlertSent = nil }
            return .none
        }
        if !p.dnsSeenOn {
            guard let setUp = p.setUpAt, now.timeIntervalSince(setUp) >= neverOnAfter,
                  p.dnsAlertSent != "never" else { return .none }
            return .neverOn
        }
        if p.dnsOffSince == nil { p.dnsOffSince = now }
        let key = "off:\(Int(p.dnsOffSince!.timeIntervalSince1970))"
        return p.dnsAlertSent == key ? .none : .switchedOff(key: key)
    }

    static func sentKey(for alert: DNSAlert) -> String? {
        switch alert {
        case .none: return nil
        case .switchedOff(let key): return key
        case .neverOn: return "never"
        }
    }
}

enum AccessWatch {
    /// Screen Time access is reported lost only when Pax is on and two checks a few seconds
    /// apart both say it isn't approved (the status can read "not determined" for a moment
    /// at launch).
    static func isLost(isActive: Bool, checks: [Bool]) -> Bool {
        isActive && checks.count >= 2 && checks.allSatisfy { !$0 }
    }
}

/// The emails Pax sends through the server's notify relay (POST /v1/notify). The server
/// sends the trusted person's copy first.
struct PaxAlertEmail: Equatable {
    let kind: String
    let subject: String
    let body: String
    let trustedBody: String

    static func dnsOff(device: String, email: String) -> PaxAlertEmail {
        PaxAlertEmail(kind: "ios_dns_off",
                      subject: "Encrypted DNS is off on \(device)",
                      body: "Pax noticed that its encrypted DNS was switched off in Settings on \(device). "
                          + "The adult-site filter and the delete block are still on. To switch the DNS back on: "
                          + "Settings › General › VPN & Device Management › DNS › Pax.",
                      trustedBody: "Pax noticed that its encrypted DNS was switched off on \(device) (\(email)). "
                          + "The adult-site filter and the delete block are still on. You might want to check in.")
    }

    static func dnsNeverOn(device: String, email: String) -> PaxAlertEmail {
        PaxAlertEmail(kind: "ios_dns_never_on",
                      subject: "Encrypted DNS isn't on yet on \(device)",
                      body: "Pax's encrypted DNS hasn't been switched on on \(device) since set-up. "
                          + "To switch it on: Settings › General › VPN & Device Management › DNS › Pax.",
                      trustedBody: "Pax's encrypted DNS hasn't been switched on on \(device) (\(email)) since set-up. "
                          + "The adult-site filter and the delete block are on.")
    }

    static func accessOff(device: String, email: String) -> PaxAlertEmail {
        PaxAlertEmail(kind: "ios_screen_time_off",
                      subject: "Pax's Screen Time access is off on \(device)",
                      body: "Pax's Screen Time access was switched off on \(device), so its protection there has stopped.",
                      trustedBody: "Pax's Screen Time access was switched off on \(device) (\(email)), so Pax's "
                          + "protection on that device has stopped. You might want to check in.")
    }
}
