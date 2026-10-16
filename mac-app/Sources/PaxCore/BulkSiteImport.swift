// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// v0.7.0 "Import list": turns a pasted list or a .txt/.csv file into sites to block.
/// Accepts plain domains, URLs (just the host is kept), hosts-file lines
/// ("0.0.0.0 example.com", "127.0.0.1 a.com b.com") and adblock-style "||example.com^".
/// Skips blank lines and comments (# or !), lowercases, de-duplicates, drops what
/// isn't a website, and stops at a cap. Pure and unit-tested.
public enum BulkSiteImport {
    /// Most sites one import adds. The server's list holds 2,000 by default
    /// (PAX_BLOCKLIST_MAX_ENTRIES); `parse` is also told how much room is left.
    public static let maxPerImport = 2000
    /// Most custom sites Pax puts in an iPhone's own web filter (WebContentFilter
    /// DenyListURLs). Apple documents no hard limit, but very long lists slow Safari
    /// and profile installs, so Pax keeps the profile to this many and relies on the
    /// synced list for the rest.
    public static let profileLimit = 500
    /// v0.8.0: the iPhone/iPad profile always carries 4 Reddit/Imgur media hosts
    /// (make_profile.py IOS_BUILTIN_DENY_HOSTS). v0.8.1: plus 60 media converters
    /// (profile/media_converters.py), 8 remote AI browsers (ChatGPT, Manus;
    /// profile/remote_ai_browsers.py) and room for the 60-URL fallback list, so
    /// custom blocks get the other 368 (make_profile.py MAX_CUSTOM_DENYLIST_URLS).
    /// v0.8.13: plus the 7 X/Bluesky media hosts (AlwaysBlockedMedia.hosts), always,
    /// so custom blocks get 361. Before, the app sent those 7 as custom blocks, so
    /// the room left for the user's own sites is the same.
    public static let iosBuiltInHosts = ["redd.it", "redditmedia.com", "redditstatic.com", "imgur.io"]
        + AlwaysBlockedMedia.hosts
    public static let iosConverterURLCount = 60
    public static let iosRemoteAIURLCount = 8
    public static let iosFallbackURLCount = 60
    public static let iosCustomLimit = profileLimit - iosBuiltInHosts.count - iosConverterURLCount
        - iosRemoteAIURLCount - iosFallbackURLCount

    /// Hosts-file names that aren't sites.
    static let ignoredNames: Set<String> = ["localhost", "localhost.localdomain", "local", "broadcasthost",
                                           "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
                                           "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0"]
    /// First column of a hosts file.
    static let sinkAddresses: Set<String> = ["0.0.0.0", "127.0.0.1", "::", "::1", "0", "255.255.255.255",
                                            "fe80::1%lo0", "ff00::0", "ff02::1", "ff02::2", "ff02::3"]

    public struct Result: Equatable, Sendable {
        /// New sites, in file order, lowercased, de-duplicated, at most `cap`.
        public var sites: [String]
        /// Entries that weren't a website (and weren't comments or blank).
        public var skipped: Int
        /// Repeats inside the list, plus sites already on the user's list.
        public var duplicates: Int
        /// Good sites left out because the cap was reached.
        public var overCap: Int
        public var capReached: Bool { overCap > 0 }
    }

    public static func parse(_ text: String, alreadyBlocked: Set<String> = [],
                             cap: Int = maxPerImport) -> Result {
        var out: [String] = []
        var seen = Set<String>()
        var skipped = 0, duplicates = 0, overCap = 0
        let limit = max(0, min(cap, maxPerImport))

        for rawLine in text.components(separatedBy: .newlines) {
            var line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("\u{FEFF}") { line.removeFirst() }
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") || line.hasPrefix("[") { continue }
            // Trailing comment: "0.0.0.0 example.com # ads"
            if let hash = line.range(of: " #") { line = String(line[..<hash.lowerBound]) }
            if let bang = line.range(of: " !") { line = String(line[..<bang.lowerBound]) }

            var tokens = line.split(whereSeparator: { ",;\t ".contains($0) })
                .map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\"'")) }
                .filter { !$0.isEmpty }
            // Hosts file: drop the address column.
            if let first = tokens.first, sinkAddresses.contains(first) || isIPAddress(first) {
                tokens.removeFirst()
            }
            for token in tokens {
                var t = token
                // Adblock style ||example.com^ (options after $ ignored).
                if t.hasPrefix("||") { t.removeFirst(2) }
                if let dollar = t.firstIndex(of: "$") { t = String(t[..<dollar]) }
                while t.hasSuffix("^") || t.hasSuffix("|") { t.removeLast() }
                if ignoredNames.contains(t.lowercased()) { continue }
                guard let site = DomainInput.normalise(t), isPlausibleHost(site) else {
                    skipped += 1
                    continue
                }
                if seen.contains(site) || alreadyBlocked.contains(site) {
                    duplicates += 1
                    continue
                }
                seen.insert(site)
                if out.count >= limit {
                    overCap += 1
                } else {
                    out.append(site)
                }
            }
        }
        return Result(sites: out, skipped: skipped, duplicates: duplicates, overCap: overCap)
    }

    static func isIPAddress(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        if parts.count == 4, parts.allSatisfy({ !$0.isEmpty && $0.count <= 3 && $0.allSatisfy(\.isNumber) }) {
            return true
        }
        return s.contains(":") && s.allSatisfy { $0.isHexDigit || $0 == ":" || $0 == "%" || $0.isLetter }
    }

    /// Letters, digits, hyphens and dots; labels 1-63 characters, not starting or
    /// ending with a hyphen; a top-level part of at least two letters (or xn--).
    static func isPlausibleHost(_ s: String) -> Bool {
        guard s.count <= 253 else { return false }
        let labels = s.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        for l in labels {
            guard (1...63).contains(l.count), !l.hasPrefix("-"), !l.hasSuffix("-"),
                  l.allSatisfy({ ($0.isASCII && ($0.isLetter || $0.isNumber)) || $0 == "-" || $0 == "_" })
            else { return false }
        }
        let tld = labels.last!
        return tld.hasPrefix("xn--") || (tld.count >= 2 && tld.allSatisfy(\.isLetter))
    }
}
