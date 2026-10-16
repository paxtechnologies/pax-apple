// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.5: configurable escrow server URL and the categories API models.
final class V05Tests: XCTestCase {
    private func ok(_ raw: String) -> String? {
        if case .success(let url) = ServerURLSetting.validate(raw) { return url.absoluteString }
        return nil
    }

    private func problem(_ raw: String) -> ServerURLSetting.Problem? {
        if case .failure(let p) = ServerURLSetting.validate(raw) { return p }
        return nil
    }

    func testDefaultIsProductionServer() {   // v0.8.5 (was http://127.0.0.1:8080/)
        XCTAssertEqual(ServerURLSetting.defaultURL.absoluteString, "https://api.paxpeace.com/")
        XCTAssertEqual(ServerURLSetting.resolve(environment: [:], stored: nil).absoluteString,
                       "https://api.paxpeace.com/")
    }

    func testValidateAddsSchemeAndSlash() {
        XCTAssertEqual(ok("pax.example.org"), "https://pax.example.org/")
        XCTAssertEqual(ok("  https://Pax.Example.org  "), "https://pax.example.org/")
        XCTAssertEqual(ok("127.0.0.1:8080"), "http://127.0.0.1:8080/")
        XCTAssertEqual(ok("localhost:8080"), "http://localhost:8080/")
        XCTAssertEqual(ok("http://192.168.1.20:8080"), "http://192.168.1.20:8080/")
        XCTAssertEqual(ok("https://example.org/pax"), "https://example.org/pax/")
    }

    func testValidateRejectsUnsafeOrOdd() {
        XCTAssertEqual(problem(""), .empty)
        XCTAssertEqual(problem("http://pax.example.org"), .insecureRemote)
        XCTAssertEqual(problem("http://8.8.8.8:8080"), .insecureRemote)
        XCTAssertEqual(problem("ftp://pax.example.org"), .unsupportedScheme)
        XCTAssertEqual(problem("https://user:pw@pax.example.org"), .extraParts)
        XCTAssertEqual(problem("https://pax.example.org/?x=1"), .extraParts)
    }

    func testPrivateHosts() {
        for h in ["localhost", "127.0.0.1", "10.0.0.5", "172.16.0.1", "172.31.255.1", "192.168.0.10",
                  "169.254.1.1", "mac-mini.local", "::1", "fd12:3456::1"] {
            XCTAssertTrue(ServerURLSetting.isLocalOrPrivate(host: h), h)
        }
        for h in ["172.32.0.1", "8.8.8.8", "pax.example.org", "192.169.0.1", "fd.example.com"] {
            XCTAssertFalse(ServerURLSetting.isLocalOrPrivate(host: h), h)
        }
    }

    func testResolveOrder() {
        let stored = "https://pax.example.org/"
        XCTAssertEqual(ServerURLSetting.resolve(environment: [:], stored: stored).absoluteString, stored)
        XCTAssertEqual(ServerURLSetting.resolve(environment: ["PAX_SERVER_URL": "https://dev.example/"],
                                                stored: stored).absoluteString, "https://dev.example/")
        XCTAssertEqual(ServerURLSetting.resolve(environment: [:], stored: "http://evil.example").absoluteString,
                       "https://api.paxpeace.com/")   // an invalid saved value falls back to the default
    }

    func testCategoriesDecode() throws {
        let json = """
        {"now": 100, "delay_seconds": 259200,
         "categories": [
           {"id": "bypass", "title": "Cloud PCs", "can_turn_off": false, "enabled": true, "pending": null},
           {"id": "remote_desktop", "title": "Remote desktop", "can_turn_off": true, "enabled": true,
            "pending": {"request_id": "r1", "action": "remote_desktop_off", "domain": null,
                        "display_domain": null, "status": "pending", "created_at": 100,
                        "effective_at": 259300, "seconds_remaining": 259200}}],
         "request": {"request_id": "r1", "action": "remote_desktop_off", "domain": null,
                     "display_domain": null, "status": "pending", "created_at": 100,
                     "effective_at": 259300, "seconds_remaining": 259200}}
        """
        let v = try JSONDecoder().decode(CategoriesView.self, from: Data(json.utf8))
        XCTAssertEqual(v.remoteDesktop?.enabled, true)
        XCTAssertEqual(v.remoteDesktop?.pending?.action, "remote_desktop_off")
        XCTAssertEqual(v.request?.seconds_remaining, 259200)
        XCTAssertEqual(v.categories.first?.can_turn_off, false)
        let noRequest = try JSONDecoder().decode(CategoriesView.self, from: Data("""
        {"now": 1, "delay_seconds": 1, "categories": []}
        """.utf8))
        XCTAssertNil(noRequest.request)
        XCTAssertNil(noRequest.remoteDesktop)
    }
}
