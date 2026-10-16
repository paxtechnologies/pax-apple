// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// The C `bind` (XCTestCase has a `bind` method of its own on macOS).
private func sysBind(_ fd: Int32, _ addr: UnsafePointer<sockaddr>, _ len: socklen_t) -> Int32 {
    #if canImport(Darwin)
    return Darwin.bind(fd, addr, len)
    #else
    return Glibc.bind(fd, addr, len)
    #endif
}

/// The real Unix-socket transport against a tiny one-shot server (pax-guard's
/// shape: one JSON line in, one JSON line out), plus canonical JSON of parsed
/// booleans, which JSONSerialization hands back differently on each platform.
final class GuardSocketTests: XCTestCase {
    /// Listens on `path`, reads one line, answers `reply` + "\n", closes.
    static func serveOnce(path: String, reply: String, got: @escaping @Sendable (String) -> Void) -> Int32 {
        unlink(path)
        #if canImport(Darwin)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, b) in bytes.enumerated() { raw[i] = b }
            raw[bytes.count] = 0
        }
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sysBind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        precondition(bound == 0 && listen(fd, 1) == 0)
        Thread.detachNewThread {
            let c = accept(fd, nil, nil)
            var line = [UInt8]()
            var b = [UInt8](repeating: 0, count: 4096)
            while true {
                let n = recv(c, &b, b.count, 0)
                if n <= 0 { break }
                line += b[0..<n]
                if line.last == 0x0A { break }
            }
            got(String(decoding: line, as: UTF8.self))
            let out = Array((reply + "\n").utf8)
            _ = out.withUnsafeBytes { send(c, $0.baseAddress, out.count, 0) }
            close(c)
        }
        return fd
    }

    func testUnixSocketRoundTrip() async throws {
        let path = "/tmp/pax-sock-\(UInt32.random(in: 0...UInt32.max)).sock"
        final class Box: @unchecked Sendable { var line = "" }
        let box = Box()
        let listener = Self.serveOnce(path: path, reply: #"{"ok": true, "version": "0.8.0", "escrow_mode": "local", "dns": {"active": "CleanBrowsing Family", "ready": true, "all_down": false}}"#) { box.line = $0 }
        defer { close(listener); unlink(path) }
        let client = GuardClient(transport: UnixSocketTransport(path: path, timeoutSeconds: 5))
        let status = try await client.status()
        XCTAssertEqual(status.version, "0.8.0")
        XCTAssertEqual(status.dns?.ready, true)
        XCTAssertEqual(box.line, "{\"cmd\":\"status\"}\n")
    }

    func testNoListenerIsGuard012() async {
        let client = GuardClient(transport: UnixSocketTransport(path: "/tmp/pax-nobody-\(UUID().uuidString.prefix(8)).sock",
                                                                timeoutSeconds: 1))
        do {
            _ = try await client.status()
            XCTFail("should throw")
        } catch let f as GuardClient.Failure {
            XCTAssertEqual(f.code, "PAX-GUARD-012")
        } catch {
            XCTFail("wrong error \(error)")
        }
    }

    func testCanonicalOfParsedJSONKeepsBooleansAndIntegers() throws {
        let text = #"{"z": true, "a": false, "n": 1, "o": 0, "big": 1234567890123, "s": "x", "l": [true, 0, null]}"#
        let obj = try JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any]
        // json.dumps(..., sort_keys=True, separators=(",", ":")) in Python:
        XCTAssertEqual(SignedDocument.canonical(obj),
                       #"{"a":false,"big":1234567890123,"l":[true,0,null],"n":1,"o":0,"s":"x","z":true}"#)
    }
}
