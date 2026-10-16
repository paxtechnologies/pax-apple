// SPDX-License-Identifier: GPL-3.0-only
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// v0.5 built-in categories (server/pax_server/blocklist.py). "bypass" (cloud
// PCs, remote browsers, web proxies) is always on. "remote_desktop" is on by
// default; turning it off is a request that waits like a removal (default
// 72 h), can be cancelled with cancelBlocklistRequest, and tells the partner.

public struct PaxCategory: Decodable, Sendable, Equatable, Identifiable {
    public let id: String
    public let title: String
    public let can_turn_off: Bool
    public let enabled: Bool
    public let pending: BlocklistRequest?
}

public struct CategoriesView: Decodable, Sendable, Equatable {
    public let now: Int
    public let categories: [PaxCategory]
    public let delay_seconds: Int
    /// Present when turning a category off started a wait.
    public let request: BlocklistRequest?

    public var remoteDesktop: PaxCategory? { categories.first { $0.id == "remote_desktop" } }
}

extension EscrowClient {
    public func categories() async throws -> CategoriesView {
        try await send("GET", "v1/categories")
    }

    /// On: immediate. Off: starts the wait (the server answers 202 with `request`).
    public func setCategory(_ id: String, enabled: Bool) async throws -> CategoriesView {
        try await send("PUT", "v1/categories/\(id)", body: ["enabled": enabled])
    }
}
