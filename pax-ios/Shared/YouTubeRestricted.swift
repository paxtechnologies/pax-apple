// SPDX-License-Identifier: GPL-3.0-only
// YouTube Restricted Mode on iPhone and iPad (1.2, Ruben 24 Oct 2026). It lives on the Pax server,
// in the account's DNS filter (dns.paxpeace.com), not on the device, so the app never changes it
// on its own. On by default.
//
//   * Turning it ON is instant.
//   * Turning it OFF takes the account's full turn-off wait, like removing a blocked site: the
//     person you trust is emailed first (if that email can't be sent, nothing starts), then it
//     stays on until the server's own clock is past the wait. It can be cancelled at any time.
//   * A child's device: always on, no switch.
//   * A device set up from a Mac: shown, read only (its locked profile is fixed), no switch.
//   * The switch is shown only when the server says it can do the wait (GET /v1/categories lists
//     "youtube_restricted" with can_turn_off true; /workspace/YOUTUBE_RESTRICTED_SERVER.md). Servers
//     0.8.31 / 0.8.32 don't, so there it stays on and no switch is shown. Fail closed: anything
//     the app can't read counts as on, with no switch.
import Foundation

/// GET /v1/categories (server v0.5+): one built-in category or setting.
struct CategoryInfo: Decodable, Equatable {
    let id: String
    let enabled: Bool
    var can_turn_off: Bool? = nil
    var pending: BlocklistRequestInfo? = nil
}

struct CategoriesView: Decodable, Equatable {
    /// The server's clock (Unix seconds).
    let now: Int
    let categories: [CategoryInfo]
    var delay_seconds: Int? = nil
}

/// PUT /v1/categories/youtube_restricted: {"enabled": false} → 202 {"request": …, "categories": …};
/// {"enabled": true} → 200 {"categories": …}.
struct CategoryChange: Decodable, Equatable {
    var now: Int? = nil
    var request: BlocklistRequestInfo? = nil
    var categories: [CategoryInfo]? = nil
}

/// GET /v1/dns/settings (server 0.8.8+): the account's filter settings.
struct DNSSettingsView: Decodable, Equatable {
    struct Values: Decodable, Equatable { let youtube_restricted: Bool? }
    let settings: Values
}

/// A turn-off of YouTube Restricted Mode waiting on the server.
struct YouTubeTurnOff: Equatable {
    var requestID: String
    /// Server time (Unix seconds) the wait ends.
    var effectiveAt: Int
}

/// What Settings shows for YouTube Restricted Mode.
struct YouTubeRow: Equatable {
    enum Value: Equatable {
        case on
        case off
        /// A child's device: always on, no switch.
        case alwaysOn
    }
    var value: Value
    /// A switch is shown (only when the server can do the wait, never for a child or a Mac set-up).
    var canSwitch: Bool
    /// Turning off: still ON until the server's wait ends.
    var turningOff: YouTubeTurnOff?

    /// What the switch shows: a turn-off that's waiting is still on.
    var isOn: Bool { value != .off }

    static let fallback = YouTubeRow(value: .on, canSwitch: false, turningOff: nil)
}

enum YouTubeRestricted {
    static let categoryID = "youtube_restricted"
    static let offAction = "youtube_restricted_off"

    /// Does this server do the wait for turning it off? (The capability check: the category is
    /// listed and can be turned off.) Older servers: no, so no switch.
    static func serverHasWait(_ view: CategoriesView?) -> Bool {
        category(view)?.can_turn_off == true
    }

    static func category(_ view: CategoriesView?) -> CategoryInfo? {
        view?.categories.first { $0.id == categoryID }
    }

    /// The row, from what the server said. `dnsSetting`: GET /v1/dns/settings' value (nil if
    /// unread). Fail closed: unknown is on.
    static func row(categories: CategoriesView?, dnsSetting: Bool?, child: Bool, macSetUp: Bool) -> YouTubeRow {
        if child { return YouTubeRow(value: .alwaysOn, canSwitch: false, turningOff: nil) }
        let cat = category(categories)
        let enabled = cat?.enabled ?? dnsSetting ?? true
        if macSetUp {
            return YouTubeRow(value: enabled ? .on : .off, canSwitch: false, turningOff: nil)
        }
        guard serverHasWait(categories), let listed = cat else {
            // No wait on this server: no switch. It shows what the server has (on unless the
            // account was set that way from a Mac before).
            return YouTubeRow(value: enabled ? .on : .off, canSwitch: false, turningOff: nil)
        }
        var off: YouTubeTurnOff?
        if listed.enabled, let r = listed.pending, r.status == "pending", r.action == offAction {
            off = YouTubeTurnOff(requestID: r.request_id, effectiveAt: r.effective_at)
        }
        return YouTubeRow(value: listed.enabled ? .on : .off, canSwitch: true, turningOff: off)
    }

    /// What the switch does when flipped. Off never happens here: it only ever starts the wait.
    enum Flip: Equatable {
        case nothing
        /// Ask first, then start the wait on the server.
        case confirmTurnOff
        /// Instant, on the server.
        case turnOnNow
    }

    static func flip(_ row: YouTubeRow, to on: Bool) -> Flip {
        guard row.canSwitch else { return .nothing }
        if on { return row.value == .off ? .turnOnNow : .nothing }
        if row.value == .off || row.turningOff != nil { return .nothing }
        return .confirmTurnOff
    }

    /// What's left of the wait, by the server's clock (`serverOffset` = server now − device now
    /// at the last read). For the "Turning off, available in …" line only; never decides anything.
    static func remaining(_ t: YouTubeTurnOff, serverOffset: TimeInterval, now: Date) -> TimeInterval {
        Double(t.effectiveAt) - (now.timeIntervalSince1970 + serverOffset)
    }
}
