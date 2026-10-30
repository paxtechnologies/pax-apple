// SPDX-License-Identifier: GPL-3.0-only
// Removing one of your own blocked sites (1.2). The rule is the same as turning Pax off, and
// it's the Pax server's rule (server/pax_server/blocklist.py, the same one Pax for Mac uses):
//
//   * Only sites the person added can be removed. Pax's own lists and the adult-content filter
//     are never on this list, so they can never be removed or excepted here.
//   * Adding a site is instant.
//   * Removing one is a request (POST /v1/blocklist/remove): the person they trust is emailed
//     first (if that email can't be sent, nothing starts: 503), then the site stays blocked for
//     the turn-off wait, and the request can be cancelled at any time before it ends.
//   * This device takes the site off only when the server's list no longer has it AND the
//     server's own clock (not this phone's) is past the wait. Anything else keeps it blocked.
import Foundation

/// The parts of the server's blocklist view the app reads (GET /v1/blocklist).
struct BlocklistRequestInfo: Codable, Equatable {
    let request_id: String
    let action: String
    let domain: String?
    let status: String
    let effective_at: Int
    let seconds_remaining: Int?
}

struct BlockedSiteInfo: Decodable, Equatable {
    let domain: String
    let pending_removal: BlocklistRequestInfo?
}

struct BlocklistViewInfo: Decodable, Equatable {
    /// The server's clock (Unix seconds).
    let now: Int
    let blocked: [BlockedSiteInfo]
}

/// POST /v1/blocklist/remove: 202 {"request": …, "list": …}.
struct BlocklistRequestResult: Decodable, Equatable {
    let request: BlocklistRequestInfo
    let list: BlocklistViewInfo
}

enum SiteRemoval {
    /// A site can be asked to come off only if the person added it on this device and no
    /// removal is already waiting for it.
    static func canRemove(_ domain: String, policy: PaxPolicy) -> Bool {
        policy.blockedDomains.contains(domain) && pending(domain, in: policy) == nil
    }

    static func pending(_ domain: String, in policy: PaxPolicy) -> PendingSiteRemoval? {
        policy.pendingSiteRemovals.first { $0.domain == domain }
    }

    /// The record kept after the server accepted a removal request.
    static func record(from r: BlocklistRequestResult, domain: String) -> PendingSiteRemoval? {
        guard r.request.action == "unblock", r.request.status == "pending" else { return nil }
        return PendingSiteRemoval(domain: r.request.domain ?? domain, requestID: r.request.request_id,
                                  effectiveAt: r.request.effective_at)
    }

    struct Reconciled: Equatable {
        /// Sites whose wait has ended on the server: take them off this device now.
        var removeNow: [String]
        /// Removals still waiting (the server's request id and end time).
        var pending: [PendingSiteRemoval]
    }

    /// Compares this device's waiting removals with the server's list. Fail closed: a site comes
    /// off only when the server no longer lists it and the server's clock is past its wait.
    static func reconcile(local: [PendingSiteRemoval], blockedDomains: [String],
                          server: BlocklistViewInfo) -> Reconciled {
        var onServer: [String: BlockedSiteInfo] = [:]
        for b in server.blocked { onServer[b.domain] = b }
        var removeNow: [String] = []
        var pending: [PendingSiteRemoval] = []
        for p in local where blockedDomains.contains(p.domain) {
            if let b = onServer[p.domain] {
                if let r = b.pending_removal, r.status == "pending", r.action == "unblock" {
                    pending.append(PendingSiteRemoval(domain: p.domain, requestID: r.request_id,
                                                      effectiveAt: r.effective_at))
                }
                // Still listed with nothing waiting: cancelled (here, on another device, or by
                // adding it again). It stays blocked and the record goes.
            } else if server.now >= p.effectiveAt {
                removeNow.append(p.domain)
            } else {
                pending.append(p)       // gone from the server before its wait ended: keep it blocked
            }
        }
        // A removal started on another device (Pax for Mac) for a site on this device's list.
        for b in server.blocked {
            guard let r = b.pending_removal, r.status == "pending", r.action == "unblock",
                  blockedDomains.contains(b.domain),
                  !pending.contains(where: { $0.domain == b.domain }) else { continue }
            pending.append(PendingSiteRemoval(domain: b.domain, requestID: r.request_id, effectiveAt: r.effective_at))
        }
        return Reconciled(removeNow: removeNow, pending: pending)
    }

    /// What's left of the wait, by the server's clock (`serverOffset` = server now − device now
    /// at the last read). For the "Removing, available in …" line only; never decides anything.
    static func remaining(_ p: PendingSiteRemoval, serverOffset: TimeInterval, now: Date) -> TimeInterval {
        Double(p.effectiveAt) - (now.timeIntervalSince1970 + serverOffset)
    }

    /// Takes the sites whose wait ended off the policy and stores what's still waiting.
    static func apply(_ r: Reconciled, to policy: inout PaxPolicy) -> Bool {
        let before = policy
        policy.blockedDomains.removeAll { r.removeNow.contains($0) }
        policy.pendingSiteRemovals = r.pending
        return policy != before
    }
}
