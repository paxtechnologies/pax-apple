// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// Plays pax-guard's socket (guard/guard_ipc.py) from canned answers.
final class FakeGuardTransport: GuardTransport, @unchecked Sendable {
    let lock = NSLock()
    var sent: [[String: Any]] = []
    var answers: [String: String]

    init(_ answers: [String: String]) { self.answers = answers }

    func exchange(_ request: Data) async throws -> Data {
        let obj = (try JSONSerialization.jsonObject(with: request)) as? [String: Any] ?? [:]
        lock.lock(); defer { lock.unlock() }
        sent.append(obj)
        let cmd = obj["cmd"] as? String ?? ""
        return Data((answers[cmd] ?? #"{"ok": false, "code": "PAX-GUARD-012", "error": "unknown"}"#).utf8)
    }
}

final class GuardClientTests: XCTestCase {
    let device = #"{"device_id":"local","name":"This Mac","platform":"mac","installed_at":1,"grace_until":2,"in_grace_period":false,"released_at":null,"wait_seconds":86400,"removal_request":{"request_id":"r1","kind":"standard","status":"pending","unlock_at":90000,"seconds_remaining":86400,"can_reveal":false}}"#

    func testLocalEscrowRoundTrip() async throws {
        let t = FakeGuardTransport([
            "escrow.request": #"{"ok": true, "device": \#(device)}"#,
            "escrow.reveal": #"{"ok": true, "released": {"device_id":"local","reason":"remove","removal_password":"pw","recovery_key":"AAAA-BBBB"}}"#,
        ])
        let g = GuardClient(transport: t)
        let st = try await g.requestRemoval(reason: "locked_out")
        XCTAssertEqual(st.removal_request?.seconds_remaining, 86400)
        XCTAssertEqual(t.sent[0]["reason"] as? String, "locked_out")
        let r = try await g.reveal()
        XCTAssertEqual(r.removal_password, "pw")
        XCTAssertEqual(r.recovery_key, "AAAA-BBBB")
        XCTAssertNil(r.firmware_password)
    }

    func testCodedErrorsCarryTheirCode() async {
        let t = FakeGuardTransport(["escrow.request": #"{"ok": false, "code": "PAX-ESCROW-010", "error": "partner not told"}"#])
        do {
            _ = try await GuardClient(transport: t).requestRemoval()
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-ESCROW-010")
        }
    }

    func testStatusAndFilterLine() async throws {
        let t = FakeGuardTransport(["status": #"{"ok": true, "version": "0.8.0", "escrow_mode": "local", "released": false, "dns": {"active": "AdGuard Family", "ready": true, "all_down": false, "upstreams": []}, "update": {"installed": "0.8.0", "last_checked": 1800000000, "latest": "0.8.0", "state": "up_to_date", "notice": null, "last_error": null}, "tamper": {"intact": true, "count": 1, "recent": [{"ts": 1, "kind": "changed:admins", "detail": {}}]}}"#])
        let s = try await GuardClient(transport: t).status()
        XCTAssertEqual(s.version, "0.8.0")
        XCTAssertEqual(s.update?.state, "up_to_date")
        XCTAssertEqual(s.tamper?.recent.first?.kind, "changed:admins")
        XCTAssertEqual(FilterStatusText.line(s.dns), "Filtering through AdGuard Family (backup).")
        XCTAssertEqual(FilterStatusText.line(.init(active: "CleanBrowsing Family", ready: true, all_down: false)),
                       "Filtering through CleanBrowsing.")
        XCTAssertTrue(FilterStatusText.line(.init(active: nil, ready: true, all_down: true)).contains("won't open"))
    }

    func testBlocklistBackendShapes() async throws {
        let list = #"{"now":1,"blocked":[{"domain":"example.com","display_domain":"example.com","added_at":1}],"allowed":[],"pending":[],"limits":{"max_blocked":2000,"max_allowed":200,"delay_seconds":86400}}"#
        let t = FakeGuardTransport([
            "blocklist.get": #"{"ok": true, "list": \#(list)}"#,
            "blocklist.add": #"{"ok": true, "domain": "example.com", "created": true, "list": \#(list)}"#,
            "blocklist.unblock": #"{"ok": true, "request": {"request_id":"q","action":"unblock","domain":"example.com","status":"pending","created_at":1,"effective_at":86401,"seconds_remaining":86400}, "list": \#(list)}"#,
        ])
        let backend: BlocklistBackend = GuardClient(transport: t)
        let v = try await backend.blocklist()
        XCTAssertEqual(v.blocked.map(\.domain), ["example.com"])
        let added = try await backend.blockSite("example.com")
        XCTAssertTrue(added.created)
        let asked = try await backend.requestUnblock("example.com")
        XCTAssertEqual(asked.request.seconds_remaining, 86400)
    }

    func testEscrowModeDefaultsToLocal() {
        let d = UserDefaults(suiteName: "pax-test-\(UUID().uuidString)")!
        XCTAssertEqual(MacEscrowMode.current(d), .local)
        d.set("server", forKey: MacEscrowMode.defaultsKey)
        XCTAssertEqual(MacEscrowMode.current(d), .server)
    }

    func testIPhoneCustomLimitLeavesRoomForBuiltIns() {
        // v0.8.13: 361 custom + 11 media hosts (v0.8.1: 368 + 4) + 60 media converters
        // + 8 remote AI browsers + 60 fallback = Apple's 500.
        XCTAssertEqual(BulkSiteImport.iosCustomLimit, 361)
        XCTAssertEqual(BulkSiteImport.iosCustomLimit + BulkSiteImport.iosBuiltInHosts.count
                       + BulkSiteImport.iosConverterURLCount + BulkSiteImport.iosRemoteAIURLCount
                       + BulkSiteImport.iosFallbackURLCount, 500)
        XCTAssertEqual(BulkSiteImport.iosBuiltInHosts, ["redd.it", "redditmedia.com", "redditstatic.com", "imgur.io",
                                                        "pbs.twimg.com", "video.twimg.com", "ton.twimg.com",
                                                        "cdn.bsky.app", "video.bsky.app", "video.cdn.bsky.app",
                                                        "gifs.bsky.app"])
    }
}

final class UpdatesTests: XCTestCase {
    func testVersionCompare() {
        XCTAssertLessThan(AppVersion("0.7.9")!, AppVersion("0.8.0")!)
        XCTAssertLessThan(AppVersion("0.8.0")!, AppVersion("0.10.0")!)
        XCTAssertNil(AppVersion("0.8"))
        XCTAssertNil(AppVersion("v0.8.0"))
    }

    func manifest(_ v: String, min: String, url: String = "https://x/y.zip") -> UpdateManifest {
        UpdateManifest(schema: "pax.update.v1", version: v, minimum_version: min, url: url,
                       sha256: String(repeating: "a", count: 64), size: 10)
    }

    func testDecisions() {
        XCTAssertEqual(manifest("0.8.1", min: "0.8.0").decision(installed: "0.8.0"), .install)
        XCTAssertEqual(manifest("0.8.1", min: "0.8.1").decision(installed: "0.8.0"), .installNow)
        XCTAssertEqual(manifest("0.8.0", min: "0.7.0").decision(installed: "0.8.1"), .upToDate)   // no downgrade
        XCTAssertEqual(manifest("0.8.1", min: "0.9.0").decision(installed: "0.8.0"), .refuse("minimum above version"))
        XCTAssertEqual(manifest("0.8.1", min: "0.8.0", url: "http://x").decision(installed: "0.8.0"), .refuse("malformed"))
    }

    func testCanonicalJSONMatchesGuard() {
        // pax_signing.canonical({"b": [1, true, null], "a": "é/\"x\""}) in Python:
        let value: [String: Any] = ["b": [1, true, NSNull()] as [Any], "a": "é/\"x\""]
        XCTAssertEqual(SignedDocument.canonical(value), #"{"a":"é/\"x\"","b":[1,true,null]}"#)
    }

    func testUnsignedIsRejected() {
        let doc = Data(#"{"payload": {"version": "9.9.9"}}"#.utf8)
        guard case .failure(let p) = SignedDocument.verify(doc) else { return XCTFail("accepted unsigned") }
        XCTAssertEqual(p, .notSigned)
    }

    #if canImport(CryptoKit)
    func testSignatureFromGuardVerifies() {
        // Made by guard/pax_signing.sign_document with the RFC 8032 test-1 key
        // (public d75a98…511a): payload {"schema":"t","version":"1.0.0"}.
        let doc = Data(#"{"payload":{"schema":"t","version":"1.0.0"},"signature":"2wZk9tMSnCfuDuXjcBul45Jog9hgMZAyALWXH/c1pafqxYXzH/S3ZtRgM+M5t91nybo3UjkhxVp3AW3sAOO3Bw==","key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","alg":"ed25519"}"#.utf8)
        let keys = ["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"]
        guard case .success(let payload) = SignedDocument.verify(doc, keysHex: keys) else { return XCTFail("rejected") }
        XCTAssertEqual(payload["version"] as? String, "1.0.0")
        let tampered = Data(String(decoding: doc, as: UTF8.self).replacingOccurrences(of: "1.0.0", with: "9.0.0").utf8)
        guard case .failure(.badSignature) = SignedDocument.verify(tampered, keysHex: keys) else { return XCTFail("tamper") }
        guard case .failure(.badSignature) = SignedDocument.verify(doc) else { return XCTFail("wrong key accepted") }
    }
    #endif

    func testSHA256Vectors() {
        XCTAssertEqual(SHA256Hex.hash(Data()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        XCTAssertEqual(SHA256Hex.hash(Data("abc".utf8)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        XCTAssertEqual(SHA256Hex.hash(Data(String(repeating: "a", count: 1000).utf8)),
                       "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3")
    }

    func testLocalEscrowReceipt() {
        let pw = "S3cret"
        let line = #"{"stored": "paxadmin", "sha256": "\#(SHA256Hex.hash(Data(pw.utf8)))"}"#
        XCTAssertTrue(LocalEscrowReceipt.matches("noise\n" + line + "\n", password: pw))
        XCTAssertFalse(LocalEscrowReceipt.matches(line, password: "other"))
        XCTAssertFalse(LocalEscrowReceipt.matches("", password: pw))
    }

    func testPinnedKeyMatchesGuard() throws {
        let here = URL(fileURLWithPath: #filePath)
        let guardFile = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("guard/pax_signing.py")
        guard let text = try? String(contentsOf: guardFile, encoding: .utf8) else { throw XCTSkip("guard not found") }
        for k in UpdatePolicy.publicKeysHex { XCTAssertTrue(text.contains(k), "guard doesn't pin \(k)") }
    }
}
