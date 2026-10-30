// SPDX-License-Identifier: GPL-3.0-only
// Blocked apps, including apps that aren't installed yet (1.2, Ruben 24 Oct 2026), e.g. Baidu: if
// it's installed later from the App Store it won't open.
//
// How (Apple's public Screen Time API, .individual):
//   * ManagedSettings `application.blockedApplications` with `Application(bundleIdentifier:)`:
//     Apple: "The system hides blocked applications and prevents the user from launching them",
//     up to 50 apps for a store (Pax's own untrusted browsers share it). A bundle ID needs no token,
//     so it can name an app that isn't installed. Whether iOS applies it under .individual and to
//     an app installed AFTER the setting is hardware test T6 / T6b (work/PLAN.md §3.2); only a real
//     iPhone can confirm it.
//   * The app's own websites can be added to your blocked sites too (Pax's DNS filter and Apple's
//     web filter), so even where the block above doesn't hold, it can't load its content.
//   * Categories chosen in "Apps to keep closed" are shielded by category, which covers apps of
//     that category installed later.
//
// Rules (the same as blocked sites): adding is instant. Removing one takes the full turn-off wait
// on the Pax server: the person you trust (or parent) is emailed first, fail closed, "Removing,
// available in X" + Cancel, and the app comes off this device only when the server no longer
// lists it AND the server's own clock is past the wait. The server needs a blocked-apps list for
// that (/workspace/BLOCKED_APPS_SERVER.md); until it has one (GET /v1/apps answers 404), blocked
// apps simply stay blocked: there is no removal on the device alone.
//
// 1.3: the account's one list for Mac and iPhone, labels and the background refresh are in
// AppsSync.swift.
//
// Never blocked, whatever is typed: Pax itself, Apple's own apps (some keep the phone working) and
// password managers (the same lists as Pax for Mac, profile/app_blocks.py).
import Foundation

/// One app the person blocked by its bundle ID.
struct BlockedApp: Codable, Equatable, Hashable {
    var bundleID: String
    var name: String
}

/// A blocked app the person asked to remove; the Pax server holds the request (see above).
struct PendingAppRemoval: Codable, Equatable {
    var bundleID: String
    var requestID: String
    /// Server time (Unix seconds) the wait ends.
    var effectiveAt: Int
}

/// A curated app: its name, bundle ID (checked with Apple's iTunes Lookup API on 24 Oct 2026) and
/// the websites it loads its content from.
struct CatalogApp: Equatable, Identifiable {
    let name: String
    let bundleID: String
    let domains: [String]
    var id: String { bundleID }
}

enum AppCatalog {
    static let apps: [CatalogApp] = [
        CatalogApp(name: "Baidu", bundleID: "com.baidu.BaiduMobile", domains: ["baidu.com", "bdstatic.com"]),
        CatalogApp(name: "Bluesky", bundleID: "xyz.blueskyweb.app", domains: ["bsky.app", "bsky.social"]),
        CatalogApp(name: "Discord", bundleID: "com.hammerandchisel.discord", domains: ["discord.com", "discord.gg", "discordapp.com"]),
        CatalogApp(name: "Facebook", bundleID: "com.facebook.Facebook", domains: ["facebook.com"]),
        CatalogApp(name: "Grindr", bundleID: "com.grindrguy.grindrx", domains: ["grindr.com"]),
        CatalogApp(name: "Instagram", bundleID: "com.burbn.instagram", domains: ["instagram.com", "cdninstagram.com"]),
        CatalogApp(name: "Kik", bundleID: "com.kik.chat", domains: ["kik.com"]),
        CatalogApp(name: "Reddit", bundleID: "com.reddit.Reddit", domains: ["reddit.com", "redd.it", "redditmedia.com"]),
        CatalogApp(name: "Rednote (Xiaohongshu)", bundleID: "com.xingin.discover", domains: ["xiaohongshu.com", "xhscdn.com"]),
        CatalogApp(name: "Snapchat", bundleID: "com.toyopagroup.picaboo", domains: ["snapchat.com", "sc-cdn.net"]),
        CatalogApp(name: "Telegram", bundleID: "ph.telegra.Telegraph", domains: ["telegram.org", "t.me"]),
        CatalogApp(name: "TikTok", bundleID: "com.zhiliaoapp.musically", domains: ["tiktok.com", "tiktokv.com", "tiktokcdn.com"]),
        CatalogApp(name: "Tinder", bundleID: "com.cardify.tinder", domains: ["tinder.com", "gotinder.com"]),
        CatalogApp(name: "Tumblr", bundleID: "com.tumblr.tumblr", domains: ["tumblr.com"]),
        CatalogApp(name: "Twitch", bundleID: "tv.twitch", domains: ["twitch.tv", "ttvnw.net"]),
        CatalogApp(name: "WeChat", bundleID: "com.tencent.xin", domains: ["wechat.com", "weixin.qq.com"]),
        CatalogApp(name: "Weibo", bundleID: "com.sina.weibo", domains: ["weibo.com", "weibo.cn"]),
        CatalogApp(name: "X", bundleID: "com.atebits.Tweetie2", domains: ["x.com", "twitter.com", "twimg.com"]),
        CatalogApp(name: "YouTube", bundleID: "com.google.ios.youtube", domains: ["youtube.com", "youtu.be"]),
    ]

    /// Matches the start of any word of the name, or the bundle ID, ignoring case.
    static func search(_ raw: String) -> [CatalogApp] {
        let q = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !q.isEmpty else { return apps }
        return apps.filter { a in
            let words = a.name.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber })
            return words.contains { $0.hasPrefix(q) } || a.name.lowercased().hasPrefix(q)
                || a.bundleID.lowercased() == q
        }
    }

    static func entry(bundleID: String) -> CatalogApp? {
        apps.first { $0.bundleID.lowercased() == bundleID.lowercased() }
    }
}

enum AppBlockRules {
    /// blockedApplications holds up to 50 apps per store; Pax's untrusted browsers use some, and
    /// a few are kept spare.
    static var maxCustomApps: Int { max(0, 50 - Pax.bypassAppBundleIDs.count - 5) }

    static let neverBlockPrefixes = ["com.apple.", "org.paxpeace.", "org.paxmobile."]
    /// Same set as profile/app_blocks.py PASSWORD_MANAGER_BUNDLE_IDS (Pax for Mac).
    static let passwordManagers: Set<String> = [
        "com.1password.1password", "com.agilebits.onepassword7", "com.1password.safari",
        "com.8bit.bitwarden", "com.lastpass.ilastpass", "com.lastpass.lastpass",
        "com.dashlane.dashlanephonefinal", "me.proton.pass.ios", "com.keepassium.ios",
        "com.markmcguill.strongbox", "com.markmcguill.strongbox.pro", "in.sinew.walletx",
        "com.callpod.keepermac.lite", "com.nordpass.ios.app.password.manager",
    ]

    enum Problem: Equatable {
        case notAnApp           // not a bundle ID or App Store link
        case pax                // Pax itself
        case apple              // one of Apple's own apps
        case passwordManager
        case alreadyBlocked
        case full
    }

    /// Reverse-DNS: letters, digits, hyphens; at least two parts.
    static func isBundleID(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 2, s.count <= 155 else { return false }
        return parts.allSatisfy { p in
            guard let f = p.first, f.isLetter || f.isNumber else { return false }
            return p.allSatisfy { ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" || $0 == "_" }
        }
    }

    /// Never blocked, whatever is saved: Pax, Apple's own apps, password managers.
    static func isProtected(_ bundleID: String) -> Bool {
        let l = bundleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return neverBlockPrefixes.contains(where: { l.hasPrefix($0) }) || passwordManagers.contains(l)
    }

    /// `listed`: apps already on the account's one list (1.3), e.g. ones added on the Mac.
    static func problem(_ bundleID: String, policy: PaxPolicy, listed: [String] = []) -> Problem? {
        let b = bundleID.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isBundleID(b) else { return .notAnApp }
        let l = b.lowercased()
        if l.hasPrefix("org.paxpeace.") || l.hasPrefix("org.paxmobile.") { return .pax }
        if l.hasPrefix("com.apple.") { return .apple }
        if passwordManagers.contains(l) { return .passwordManager }
        if Pax.bypassAppBundleIDs.contains(where: { $0.lowercased() == l })
            || policy.blockedApps.contains(where: { $0.bundleID.lowercased() == l })
            || listed.contains(where: { $0.lowercased() == l }) { return .alreadyBlocked }
        if policy.blockedApps.count >= maxCustomApps { return .full }
        return nil
    }

    /// Every bundle ID for blockedApplications: Pax's own, then the person's, within the limit.
    /// Anything protected is left out even if it somehow got saved.
    static func bundleIDs(_ policy: PaxPolicy) -> [String] {
        var out = Pax.bypassAppBundleIDs
        for a in policy.blockedApps where !out.contains(a.bundleID) {
            let l = a.bundleID.lowercased()
            if neverBlockPrefixes.contains(where: { l.hasPrefix($0) }) || passwordManagers.contains(l) { continue }
            out.append(a.bundleID)
        }
        return Array(out.prefix(50))
    }

    /// 1.3, a device set up from a Mac: only the apps added on the phone, for the phone's own layer
    /// (PhoneAppLayer). The Mac's profile already closes Pax's untrusted browsers and its own apps.
    static func phoneLayerBundleIDs(_ policy: PaxPolicy) -> [String] {
        var out: [String] = []
        for a in policy.blockedApps where !isProtected(a.bundleID) && !out.contains(a.bundleID) {
            out.append(a.bundleID)
        }
        return Array(out.prefix(maxCustomApps))
    }
}

/// What the person typed in "Add by App Store link or bundle ID".
enum AppEntry: Equatable {
    /// An App Store link: its numeric id, looked up with Apple's iTunes Lookup API.
    case appStoreID(Int)
    case bundleID(String)

    static func parse(_ raw: String) -> AppEntry? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        if s.lowercased().contains("apps.apple.com") || s.lowercased().contains("itunes.apple.com") {
            guard let r = s.range(of: #"id(\d{5,12})"#, options: .regularExpression) else { return nil }
            return Int(s[r].dropFirst(2)).map { .appStoreID($0) }
        }
        if s.hasPrefix("id"), let n = Int(s.dropFirst(2)), n > 9_999 { return .appStoreID(n) }
        return AppBlockRules.isBundleID(s) ? .bundleID(s) : nil
    }
}

/// GET /v1/apps on a server with a blocked-apps list. Codable so the last answer can be kept as
/// a cache (AppsSync.swift). 1.3: each app says where it was added (`source` "mac" | "iphone",
/// optional `device_id`), and the list carries `apps_version` (also sent as its ETag).
struct BlockedAppInfo: Codable, Equatable {
    let bundle_id: String
    var name: String? = nil
    var pending_removal: BlocklistRequestInfo? = nil
    var source: String? = nil
    var device_id: String? = nil
}

struct AppsViewInfo: Codable, Equatable {
    let now: Int
    let apps: [BlockedAppInfo]
    var apps_version: Int? = nil
}

/// POST /v1/apps/remove: 202 {"request": …, "list": …}.
struct AppRequestResult: Decodable, Equatable {
    let request: BlocklistRequestInfo
    let list: AppsViewInfo
}

enum AppRemoval {
    static let action = "unblock_app"

    /// Only an app the person blocked, with no removal already waiting, and only on a server that
    /// keeps the list (no removal on the device alone).
    static func canRemove(_ bundleID: String, policy: PaxPolicy, serverHasList: Bool) -> Bool {
        serverHasList && policy.blockedApps.contains { $0.bundleID == bundleID } && pending(bundleID, in: policy) == nil
    }

    static func pending(_ bundleID: String, in policy: PaxPolicy) -> PendingAppRemoval? {
        policy.pendingAppRemovals.first { $0.bundleID == bundleID }
    }

    static func record(from r: AppRequestResult, bundleID: String) -> PendingAppRemoval? {
        guard r.request.action == action, r.request.status == "pending" else { return nil }
        return PendingAppRemoval(bundleID: bundleID, requestID: r.request.request_id, effectiveAt: r.request.effective_at)
    }

    struct Reconciled: Equatable {
        var removeNow: [String]
        var pending: [PendingAppRemoval]
    }

    /// Same rule as SiteRemoval.reconcile: an app comes off only when the server no longer lists it
    /// and the server's clock is past its wait. Anything else keeps it blocked.
    static func reconcile(local: [PendingAppRemoval], blocked: [BlockedApp], server: AppsViewInfo) -> Reconciled {
        let ids = Set(blocked.map { $0.bundleID })
        var onServer: [String: BlockedAppInfo] = [:]
        for a in server.apps { onServer[a.bundle_id] = a }
        var removeNow: [String] = []
        var pending: [PendingAppRemoval] = []
        for p in local where ids.contains(p.bundleID) {
            if let a = onServer[p.bundleID] {
                if let r = a.pending_removal, r.status == "pending", r.action == action {
                    pending.append(PendingAppRemoval(bundleID: p.bundleID, requestID: r.request_id, effectiveAt: r.effective_at))
                }
            } else if server.now >= p.effectiveAt {
                removeNow.append(p.bundleID)
            } else {
                pending.append(p)
            }
        }
        for a in server.apps {
            guard let r = a.pending_removal, r.status == "pending", r.action == action, ids.contains(a.bundle_id),
                  !pending.contains(where: { $0.bundleID == a.bundle_id }) else { continue }
            pending.append(PendingAppRemoval(bundleID: a.bundle_id, requestID: r.request_id, effectiveAt: r.effective_at))
        }
        return Reconciled(removeNow: removeNow, pending: pending)
    }

    static func apply(_ r: Reconciled, to policy: inout PaxPolicy) -> Bool {
        let before = policy
        policy.blockedApps.removeAll { r.removeNow.contains($0.bundleID) }
        policy.pendingAppRemovals = r.pending
        return policy != before
    }

    static func remaining(_ p: PendingAppRemoval, serverOffset: TimeInterval, now: Date) -> TimeInterval {
        Double(p.effectiveAt) - (now.timeIntervalSince1970 + serverOffset)
    }
}

/// "Apps to keep closed" (the picker) only ever adds: un-choosing in the picker can't remove
/// anything, because the picker opens empty and its choices are merged in.
enum SelectionRules {
    static func merged<T: Hashable>(_ current: Set<T>, adding more: Set<T>) -> Set<T> { current.union(more) }
}
