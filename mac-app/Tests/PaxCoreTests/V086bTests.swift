// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.6 (second part): pax-guard's own runtime, the update parts, and the YouTube
/// Restricted Mode switch.
final class V086bTests: XCTestCase {

    // MARK: YouTube Restricted Mode (pax-guard switch, immediate both ways)

    func testYouTubeSwitchGoesStraightToPaxGuard() async throws {
        let t = FakeGuardTransport([
            "settings.get": #"{"ok": true, "settings": {"youtube_restricted": true, "youtube_available": true, "changed_at": null}}"#,
            "settings.set": #"{"ok": true, "settings": {"youtube_restricted": false, "youtube_available": true, "changed_at": 1800000000}}"#,
        ])
        let g = GuardClient(transport: t)
        let first = try await g.settings()
        XCTAssertEqual(first, GuardClient.Settings(youtube_restricted: true))
        let s = try await g.setYouTubeRestricted(false)
        XCTAssertFalse(s.youtube_restricted)
        XCTAssertEqual(t.sent.last?["cmd"] as? String, "settings.set")
        XCTAssertEqual(t.sent.last?["youtube_restricted"] as? Bool, false)
    }

    func testYouTubeSwitchUnavailableKeepsItsCode() async {
        let t = FakeGuardTransport(["settings.set": #"{"ok": false, "code": "PAX-DNS-011", "error": "no"}"#])
        do {
            _ = try await GuardClient(transport: t).setYouTubeRestricted(false)
            XCTFail("should throw")
        } catch {
            XCTAssertEqual(PaxErrorClassifier.classify(error).code, "PAX-DNS-011")
        }
    }

    func testStatusCarriesSettings() async throws {
        let t = FakeGuardTransport(["status": #"{"ok": true, "version": "0.8.6", "escrow_mode": "local", "settings": {"youtube_restricted": false, "youtube_available": true}}"#])
        let s = try await GuardClient(transport: t).status()
        XCTAssertEqual(s.settings?.youtube_restricted, false)
        let old = FakeGuardTransport(["status": #"{"ok": true, "version": "0.8.5", "escrow_mode": "local"}"#])
        let older = try await GuardClient(transport: old).status()
        XCTAssertNil(older.settings)      // older pax-guard
    }

    func testGuardConfigCarriesTheSetUpChoice() throws {
        let on = GuardConfigFile(server_url: "s", guard_token: "", profile_identifier: "p", user: "u", resolver_host: "r")
        XCTAssertTrue(String(decoding: try on.json(), as: UTF8.self).contains(#""youtube_restricted_default":true"#))
        let off = GuardConfigFile(server_url: "s", guard_token: "", profile_identifier: "p", user: "u",
                                  resolver_host: "r", youtube_restricted_default: false)
        XCTAssertTrue(String(decoding: try off.json(), as: UTF8.self).contains(#""youtube_restricted_default":false"#))
    }

    func testIPhoneProfileArgumentsCarryTheSwitch() {
        let script = URL(fileURLWithPath: "/R/profile/make_profile.py")
        let out = URL(fileURLWithPath: "/tmp/p.mobileconfig"), esc = URL(fileURLWithPath: "/tmp/e.json")
        let on = ProfileGenerator.arguments(script: script, platform: "ios", out: out, escrow: esc, filter: .family,
                                            resolverURL: nil, blockApps: [], blockURLs: [])
        XCTAssertFalse(on.contains("--no-youtube-restricted"))
        let off = ProfileGenerator.arguments(script: script, platform: "ios", out: out, escrow: esc, filter: .family,
                                             resolverURL: nil, blockApps: [], blockURLs: [], youtubeRestricted: false)
        XCTAssertEqual(off.last, "--no-youtube-restricted")
        XCTAssertTrue(off.contains("--filter") && off.contains("family"))     // the filter itself is unchanged
        XCTAssertTrue(SetupConfiguration().youtubeRestricted)                  // on by default
    }

    // MARK: pax-guard's own runtime: no Command Line Tools on the Mac path

    func testLocalEscrowDepositUsesTheBundledPython() {
        let bundled = "/Applications/Pax.app/Contents/Resources/device/python/bin/python3.12"
        let cmd = MacLockdownCommands.localEscrowDeposit(
            guardSource: "/Applications/Pax.app/Contents/Resources/guard", secretFile: "/tmp/s", waitSeconds: 60,
            isExecutable: { $0 == bundled })
        XCTAssertEqual(cmd.0, bundled)
        XCTAssertEqual(Array(cmd.1.prefix(3)), ["-I", "-B", "/Applications/Pax.app/Contents/Resources/guard/local_escrow.py"])
        let dev = MacLockdownCommands.localEscrowDeposit(guardSource: "/repo/guard", secretFile: "/tmp/s",
                                                         waitSeconds: 60, isExecutable: { _ in false })
        XCTAssertEqual(dev.0, "/usr/bin/python3")       // a build without the runtime (swift run)
    }

    func testRuntimeInstallFailureMapsToGuard002() {
        XCTAssertEqual(PaxErrorClassifier.guardCode("pax-guard-install: Pax's runtime didn't verify"), "PAX-GUARD-002")
        XCTAssertTrue(PaxErrorCatalog.contains("PAX-GUARD-013") && PaxErrorCatalog.contains("PAX-DNS-011"))
        XCTAssertFalse(PaxErrorCatalog.info("PAX-GUARD-002").action.contains("xcode-select"))
    }

    // MARK: Update manifest with mirror parts

    func testCanonicalJSONMatchesPythonForNestedParts() throws {
        let doc = #"{"schema":"pax.update.v1","version":"0.8.6","size":31457281,"mirrors":[],"parts":{"base_urls":["https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/parts/0.8.6/"],"files":[{"name":"Pax-0.8.6.zip.part-000","size":15728640,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"name":"Pax-0.8.6.zip.part-001","size":15728641,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}}"#
        let obj = try JSONSerialization.jsonObject(with: Data(doc.utf8))
        // pax_signing.canonical() of the same payload, byte for byte.
        XCTAssertEqual(SignedDocument.canonical(obj),
                       #"{"mirrors":[],"parts":{"base_urls":["https://cdn.jsdelivr.net/gh/paxtechnologies/pax-apple@releases/parts/0.8.6/"],"files":[{"name":"Pax-0.8.6.zip.part-000","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":15728640},{"name":"Pax-0.8.6.zip.part-001","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":15728641}]},"schema":"pax.update.v1","size":31457281,"version":"0.8.6"}"#)
    }

    func testManifestWithPartsStillDecodes() throws {
        let doc = #"{"schema":"pax.update.v1","version":"0.8.6","minimum_version":"0.8.0","url":"https://github.com/x/y.zip","sha256":"\#(String(repeating: "c", count: 64))","size":78000000,"mirrors":[],"parts":{"base_urls":["https://cdn.jsdelivr.net/gh/x/y@releases/parts/0.8.6/"],"files":[]}}"#
        let m = try JSONDecoder().decode(UpdateManifest.self, from: Data(doc.utf8))
        XCTAssertEqual(m.decision(installed: "0.8.5"), .install)
    }
}
