// SPDX-License-Identifier: GPL-3.0-only
// What the server's answer to DELETE /v1/accounts/me means (Pax server 0.8.30 contract).
//   204           deleted: every token of the account is dead; the app signs out locally.
//   404 / 405     the route isn't on this server yet (0.8.29 answers 405 because GET exists
//                 on the same path): the app offers an emailed request instead.
//   401           PAX-ESCROW-001, signed out or the token is no longer valid: email instead.
//   409           "devices_still_protected": Pax is still on one or more devices. Nothing is
//                 deleted; the person turns Pax off first. Deleting never skips the wait.
//   429           rate_limited: too many refused tries in the last hour.
// Pure Foundation so it can be unit tested without the app.
import Foundation

enum AccountDeletion {
    /// A device the server says is still protected.
    struct StillOn: Equatable {
        let deviceID: String
        let name: String
        let platform: String
        /// pax_on | turn_off_wait | emergency_release | pending_request (or something newer).
        let reason: String
        let removalRequest: String?
        let checkingIn: Bool?

        /// "iPhone", "iPad", "Mac" or a plain fallback, for the line under the name.
        var kind: String {
            let p = platform.lowercased()
            if p.contains("ipad") { return "iPad" }
            if p.contains("iphone") || p == "ios" { return "iPhone" }
            if p.contains("mac") { return "Mac" }
            return "Device"
        }
    }

    enum Outcome: Equatable {
        case deleted
        case notAvailable
        case signedOut
        case stillProtected(message: String, count: Int, devices: [StillOn])
        case rateLimited
        case failed(String)
    }

    static func outcome(status: Int, body: Data) -> Outcome {
        let obj = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
        switch status {
        case 200..<300:
            return .deleted
        case 404, 405:
            return .notAvailable
        case 401:
            return .signedOut
        case 409 where (obj?["error"] as? String) == "devices_still_protected":
            let list = (obj?["devices"] as? [[String: Any]]) ?? []
            let devices: [StillOn] = list.map { d in
                StillOn(deviceID: d["device_id"] as? String ?? "",
                        name: (d["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "A device",
                        platform: d["platform"] as? String ?? "",
                        reason: d["reason"] as? String ?? "pax_on",
                        removalRequest: d["removal_request"] as? String,
                        checkingIn: d["checking_in"] as? Bool)
            }
            let count = (obj?["count"] as? Int) ?? devices.count
            // Fail closed: a 409 with an unreadable list is still a refusal.
            return .stillProtected(message: obj?["message"] as? String ?? "", count: max(count, devices.count, 1),
                                   devices: devices)
        case 429:
            return .rateLimited
        default:
            let m = (obj?["message"] as? String) ?? (obj?["detail"] as? String)
            return .failed(m.map(tidy) ?? "Pax's server couldn't delete your account (\(status)). Nothing has changed.")
        }
    }

    private static func tidy(_ m: String) -> String {
        guard let first = m.first else { return m }
        var s = first.uppercased() + m.dropFirst()
        if !s.hasSuffix(".") { s += "." }
        return s
    }
}
