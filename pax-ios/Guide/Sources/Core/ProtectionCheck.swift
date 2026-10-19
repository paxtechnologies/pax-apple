// SPDX-License-Identifier: GPL-3.0-only
// "Is this phone protected?": an on-device check that this iPhone or iPad looks up
// names through Pax's own DNS filter.
//
// What it relies on (no server change needed): Pax's filter always answers the media
// servers of X and Bluesky with the blocked address, 0.0.0.0 for A and :: for AAAA, for
// every account and even for an unknown token (guard_config.ALWAYS_BLOCKED_MEDIA_NAMES,
// server/pax_server/doh.py Policies._base; v0.8.13 "always blocked, no switch anywhere").
// Public DNS answers the same names with real addresses. So:
//   * every probe name answers only blocked addresses  -> Protected by Pax
//   * every probe name answers real addresses          -> Not protected
//   * the control name (and the probes) don't resolve  -> Couldn't check (offline)
//   * anything else (mixed, errors, empty)             -> Couldn't check
// It never says "protected" unless all four names come back blocked.
//
// Privacy: four lookups through the phone's own resolver. Nothing is stored or sent
// anywhere by the app; no account, no analytics.
import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum ProtectionCheck {
    /// X and Bluesky media servers (mac-app AlwaysBlockedMedia.hosts, a subset).
    public static let probeNames = ["pbs.twimg.com", "video.twimg.com", "cdn.bsky.app", "video.bsky.app"]
    /// An everyday name Pax's filter always lets through; tells "offline" from the rest.
    public static let controlName = "www.apple.com"
    /// Seconds before a single lookup counts as failed.
    public static let lookupTimeout: Double = 6

    /// The answer for one name.
    public enum Lookup: Equatable, Sendable {
        case addresses([String])   // what the resolver returned (may be empty)
        case failed                // no answer: error, NXDOMAIN, SERVFAIL or timeout
    }

    public enum Outcome: Equatable, Sendable {
        case protected
        case notProtected
        case couldNotCheck(Reason)

        public enum Reason: Equatable, Sendable {
            case offline     // even the everyday name didn't resolve
            case unclear     // a mix of answers this check can't vouch for
        }
    }

    /// The address Pax's filter gives a blocked name. NAT64 networks may synthesise
    /// 0.0.0.0 into the well-known prefix (64:ff9b::0.0.0.0), so that counts too.
    public static func isBlockedAddress(_ raw: String) -> Bool {
        var s = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if let pct = s.firstIndex(of: "%") { s = String(s[..<pct]) }       // zone id
        if s == "0.0.0.0" { return true }
        guard s.contains(":"), let bytes = ipv6Bytes(s) else { return false }
        if bytes.allSatisfy({ $0 == 0 }) { return true }                   // ::
        let nat64: [UInt8] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
        if Array(bytes[0..<12]) == nat64 && bytes[12...].allSatisfy({ $0 == 0 }) { return true }
        // IPv4-mapped ::ffff:0.0.0.0
        if bytes[0..<10].allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff
            && bytes[12...].allSatisfy({ $0 == 0 }) { return true }
        return false
    }

    /// A probe answered only with blocked addresses.
    static func isBlocked(_ l: Lookup) -> Bool {
        if case .addresses(let a) = l, !a.isEmpty { return a.allSatisfy(isBlockedAddress) }
        return false
    }

    /// A probe answered with at least one real (routable-looking) address and no blocked one.
    static func isOpen(_ l: Lookup) -> Bool {
        if case .addresses(let a) = l, !a.isEmpty { return !a.contains(where: isBlockedAddress) }
        return false
    }

    /// Pure classification, unit-tested.
    public static func classify(control: Lookup, probes: [Lookup]) -> Outcome {
        guard !probes.isEmpty else { return .couldNotCheck(.unclear) }
        if probes.allSatisfy(isBlocked) {
            // Pax's filter answered. It also answers the control unless something is very
            // wrong; either way every probe proved the filter is in the path.
            return .protected
        }
        let controlOK: Bool = { if case .addresses(let a) = control { return !a.isEmpty }; return false }()
        if !controlOK {
            return .couldNotCheck(.offline)
        }
        if probes.allSatisfy(isOpen) && isOpen(control) {
            return .notProtected
        }
        return .couldNotCheck(.unclear)
    }

    /// Runs the lookups through the system resolver (the one every app and Safari use,
    /// so a DNS profile on the device applies) and classifies them.
    public static func run(resolve: @escaping @Sendable (String) async -> Lookup = { await resolveWithTimeout($0) }) async -> Outcome {
        async let control = resolve(controlName)
        let probes = await withTaskGroup(of: (Int, Lookup).self) { group -> [Lookup] in
            for (i, name) in probeNames.enumerated() {
                group.addTask { (i, await resolve(name)) }
            }
            var out = [Lookup](repeating: .failed, count: probeNames.count)
            for await (i, l) in group { out[i] = l }
            return out
        }
        return classify(control: await control, probes: probes)
    }

    /// getaddrinfo on a background thread, given up after `lookupTimeout` seconds.
    public static func resolveWithTimeout(_ name: String) async -> Lookup {
        await withCheckedContinuation { (cont: CheckedContinuation<Lookup, Never>) in
            let once = Once(cont)
            DispatchQueue.global(qos: .userInitiated).async { once.resume(resolveBlocking(name)) }
            DispatchQueue.global().asyncAfter(deadline: .now() + lookupTimeout) { once.resume(.failed) }
        }
    }

    static func resolveBlocking(_ name: String) -> Lookup {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, "443", &hints, &res) == 0, let first = res else { return .failed }
        defer { freeaddrinfo(first) }
        var out: [String] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if let sa = ai.pointee.ai_addr,
               getnameinfo(sa, ai.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                let s = String(cString: host)
                if !out.contains(s) { out.append(s) }
            }
            p = ai.pointee.ai_next
        }
        return .addresses(out)
    }

    static func ipv6Bytes(_ s: String) -> [UInt8]? {
        var addr = in6_addr()
        guard inet_pton(AF_INET6, s, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Array($0) }
    }
}

/// Resumes a continuation exactly once (lookup vs. timeout).
private final class Once: @unchecked Sendable {
    private var cont: CheckedContinuation<ProtectionCheck.Lookup, Never>?
    private let lock = NSLock()
    init(_ c: CheckedContinuation<ProtectionCheck.Lookup, Never>) { cont = c }
    func resume(_ v: ProtectionCheck.Lookup) {
        lock.lock(); let c = cont; cont = nil; lock.unlock()
        c?.resume(returning: v)
    }
}
