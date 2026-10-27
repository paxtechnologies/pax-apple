// SPDX-License-Identifier: GPL-3.0-only
import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import PaxCore

/// Fake Pax server for the email-code calls: records each request, answers from `reply`.
final class EmailCodeFakeServer: URLProtocol {
    nonisolated(unsafe) static var requests: [(path: String, body: [String: Any])] = []
    nonisolated(unsafe) static var reply: (Int, String) = (202, #"{"sent":true}"#)
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        var data = request.httpBody
        if data == nil, let stream = request.httpBodyStream {
            stream.open(); var buf = [UInt8](repeating: 0, count: 8192)
            let n = stream.read(&buf, maxLength: buf.count); stream.close()
            data = Data(buf.prefix(max(0, n)))
        }
        let body = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        Self.requests.append((request.url?.path ?? "", body))
        let (status, text) = Self.reply
        let resp = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(text.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

/// v0.8.32: every new Pax account (Mac too) proves its email with a 6-digit code
/// before it exists; POST /v1/accounts no longer makes accounts.
final class V0832Tests: XCTestCase {
    func client() -> EscrowClient {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [EmailCodeFakeServer.self]
        EmailCodeFakeServer.requests = []
        return EscrowClient(baseURL: URL(string: "http://pax.test/")!, session: URLSession(configuration: cfg))
    }

    // MARK: paste-friendly code field

    func testDigitsFromTypingAndPasting() {
        XCTAssertEqual(EmailCodeState.digits(from: "123456"), "123456")
        XCTAssertEqual(EmailCodeState.digits(from: " 123 456 "), "123456")
        XCTAssertEqual(EmailCodeState.digits(from: "123-456"), "123456")
        XCTAssertEqual(EmailCodeState.digits(from: "Your Pax code is 654321. It works for 15 minutes."), "654321")
        XCTAssertEqual(EmailCodeState.digits(from: "It works for 15 minutes. Your Pax code is 000123."), "000123")
        XCTAssertEqual(EmailCodeState.digits(from: "12"), "12")
        XCTAssertEqual(EmailCodeState.digits(from: "12a"), "12")
        XCTAssertEqual(EmailCodeState.digits(from: "1234567"), "123456")      // never more than 6
        XCTAssertEqual(EmailCodeState.digits(from: "١٢٣٤٥٦"), "")              // ASCII digits only
        XCTAssertEqual(EmailCodeState.digits(from: ""), "")
        var s = EmailCodeState()
        s.code = "code: 987 654"
        XCTAssertEqual(s.digits, "987654")
        XCTAssertTrue(s.codeComplete)
        s.code = "98765"
        XCTAssertFalse(s.codeComplete)
    }

    func testEmailCheckAndNormalising() {
        XCTAssertEqual(EmailCodeState.normalized("  Sam@Example.COM \n"), "sam@example.com")
        for good in ["sam@example.com", " Sam@Example.co.uk "] { XCTAssertTrue(EmailCodeState.looksLikeEmail(good), good) }
        for bad in ["", "sam", "sam@", "@example.com", "sam@example", "sam@.com", "sam@example.", "s am@example.com",
                    "a@b@example.com"] {
            XCTAssertFalse(EmailCodeState.looksLikeEmail(bad), bad)
        }
    }

    // MARK: one step: email, then the code field on the same step

    func testCodeFieldFollowsTheAddressItWentTo() {
        var s = EmailCodeState()
        XCTAssertFalse(s.awaitingCode(for: "sam@example.com"))
        let t0 = Date(timeIntervalSince1970: 1_000_000)
        s.problem = "old"
        s.code = "111"
        s.didSend(to: " Sam@Example.com", at: t0)
        XCTAssertEqual(s.sentTo, "sam@example.com")
        XCTAssertTrue(s.awaitingCode(for: "SAM@example.com "))
        XCTAssertEqual(s.code, "")
        XCTAssertNil(s.problem)
        // Changing the email hides the code field: the next Continue sends a new code.
        XCTAssertFalse(s.awaitingCode(for: "alex@example.com"))
        s.finish()
        XCTAssertFalse(s.awaitingCode(for: "sam@example.com"))
        XCTAssertEqual(s.sends.count, 1)                                    // the hourly count stays
    }

    func testResendWaitsAndRespectsFiveAnHour() {
        var s = EmailCodeState()
        let t0 = Date(timeIntervalSince1970: 2_000_000)
        XCTAssertEqual(s.secondsUntilResend(now: t0), 0)
        s.didSend(to: "sam@example.com", at: t0)
        XCTAssertEqual(s.secondsUntilResend(now: t0), 30)
        XCTAssertEqual(s.secondsUntilResend(now: t0.addingTimeInterval(10)), 20)
        XCTAssertEqual(s.secondsUntilResend(now: t0.addingTimeInterval(30)), 0)
        for i in 1..<5 { s.didSend(to: "sam@example.com", at: t0.addingTimeInterval(Double(i) * 60)) }
        // Five codes in the hour: wait until the first is an hour old (the server's rule).
        XCTAssertEqual(s.secondsUntilResend(now: t0.addingTimeInterval(300)), 3300)
        XCTAssertEqual(s.secondsUntilResend(now: t0.addingTimeInterval(3600)), 0)
        XCTAssertEqual(EmailCodeCopy.resendTitle(seconds: 0), "Resend code")
        XCTAssertEqual(EmailCodeCopy.resendTitle(seconds: 20), "Resend code in 20 s")
        XCTAssertEqual(EmailCodeCopy.resendTitle(seconds: 3300), "Resend code in 55 min")
    }

    // MARK: clear errors

    func testPlainMessagesForCodeProblems() {
        func api(_ status: Int, _ code: String = "x") -> EscrowClient.APIError {
            EscrowClient.APIError(status: status, code: code, message: "m")
        }
        XCTAssertEqual(EmailCodeCopy.message(for: api(401, "unauthorized"), checking: true), EmailCodeCopy.wrongCode)
        XCTAssertTrue(EmailCodeCopy.wrongCode.contains("isn't right or has expired"))
        XCTAssertEqual(EmailCodeCopy.message(for: api(429, "rate_limited"), checking: false), EmailCodeCopy.tooMany)
        XCTAssertEqual(EmailCodeCopy.message(for: api(429, "rate_limited"), checking: true), EmailCodeCopy.tooMany)
        XCTAssertEqual(EmailCodeCopy.message(for: api(422), checking: false), EmailCodeCopy.badEmail)
        XCTAssertEqual(EmailCodeCopy.message(for: api(422), checking: true), EmailCodeCopy.enterCode)
        XCTAssertEqual(EmailCodeCopy.message(for: api(404), checking: false), EmailCodeCopy.oldServer)
        // Anything else goes to the usual error card with its support code.
        XCTAssertNil(EmailCodeCopy.message(for: api(401), checking: false))
        XCTAssertNil(EmailCodeCopy.message(for: api(503), checking: true))
        XCTAssertNil(EmailCodeCopy.message(for: URLError(.notConnectedToInternet), checking: true))
        for text in [EmailCodeCopy.why, EmailCodeCopy.wrongCode, EmailCodeCopy.tooMany, EmailCodeCopy.badEmail,
                     EmailCodeCopy.oldServer, EmailCodeCopy.sent(to: "sam@example.com")] {
            XCTAssertFalse(text.contains("PAX-"), text)
            XCTAssertFalse(text.lowercased().contains("verify"), text)          // plain words
        }
    }

    func testRetiredRouteHasItsOwnSupportCode() {
        let e = PaxErrorClassifier.classify(EscrowClient.APIError(
            status: 410, code: "app_update_required", message: "This version of Pax can't make new accounts any more."))
        XCTAssertEqual(e.code, "PAX-ESCROW-020")
        XCTAssertTrue(e.info.action.contains("paxpeace.com"))
        // Child accounts (server 0.8.32): their own codes in the shared catalog.
        XCTAssertEqual(PaxErrorClassifier.classify(EscrowClient.APIError(
            status: 403, code: "child_wait_fixed", message: "")).code, "PAX-ESCROW-021")
        XCTAssertEqual(PaxErrorClassifier.classify(EscrowClient.APIError(
            status: 429, code: "child_limit", message: "")).code, "PAX-ESCROW-022")
        // An older app sees the same 410 as PAX-ESCROW-005 (status only).
        XCTAssertEqual(PaxErrorClassifier.escrowCode(status: 410), "PAX-ESCROW-005")
    }

    // MARK: the two calls

    func testStartAndVerifyCallTheEmailRoutes() async throws {
        let c = client()
        EmailCodeFakeServer.reply = (202, #"{"sent":true}"#)
        try await c.startEmailCode(email: "  Sam@Example.com ")
        EmailCodeFakeServer.reply = (201, #"{"account_id":"a1","token":"pax_t","created":true}"#)
        let made = try await c.verifyEmailCode(email: "Sam@Example.com", code: "Your Pax code is 123456.", label: "Mac")
        XCTAssertEqual(made.token, "pax_t")
        XCTAssertEqual(made.created, true)
        EmailCodeFakeServer.reply = (200, #"{"account_id":"a0","token":"pax_s","created":false}"#)
        let joined = try await c.verifyEmailCode(email: "sam@example.com", code: "123 456", label: "Mac")
        XCTAssertEqual(joined.created, false)                               // signs in to the existing account
        let reqs = EmailCodeFakeServer.requests
        XCTAssertEqual(reqs.map { $0.path }, ["/v1/accounts/email/start", "/v1/accounts/email/verify",
                                         "/v1/accounts/email/verify"])
        XCTAssertEqual(reqs[0].body["email"] as? String, "sam@example.com")
        XCTAssertEqual(reqs[1].body["code"] as? String, "123456")
        XCTAssertEqual(reqs[1].body["email"] as? String, "sam@example.com")
        XCTAssertEqual(reqs[1].body["label"] as? String, "Mac")
    }

    func testWrongCodeIsAPlainSentence() async {
        let c = client()
        EmailCodeFakeServer.reply = (401, #"{"error":"unauthorized","message":"that code isn't right or has expired"}"#)
        do {
            _ = try await c.verifyEmailCode(email: "sam@example.com", code: "000000", label: "Mac")
            XCTFail("expected 401")
        } catch {
            XCTAssertEqual(EmailCodeCopy.message(for: error, checking: true), EmailCodeCopy.wrongCode)
        }
    }

    /// No source file posts to the retired POST /v1/accounts any more.
    func testNothingCallsTheRetiredRoute() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources")
        guard let walker = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil) else {
            throw XCTSkip("sources not next to the tests")
        }
        var checked = 0
        for case let url as URL in walker where url.pathExtension == "swift" {
            let text = try String(contentsOf: url, encoding: .utf8)
            XCTAssertFalse(text.contains("\"v1/accounts\","), url.lastPathComponent)
            XCTAssertFalse(text.contains("registerAccount("), url.lastPathComponent)
            checked += 1
        }
        XCTAssertGreaterThan(checked, 10)
    }
}
