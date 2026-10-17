// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.21: Home › Turn off › "In an emergency" description (Mac).
final class V0821Tests: XCTestCase {
    let exact = "Emergency release is self-serve. You give a reason, your trusted person is emailed, and Pax turns off "
        + "after 24 hours instead of your full turn-off wait. You can use it once every 90 days."

    func testDefaultCooloffIsExact() {
        XCTAssertEqual(HomeLayout.emergencyDescription(cooloffSeconds: nil, trialActive: false), exact)
        XCTAssertEqual(HomeLayout.emergencyDescription(cooloffSeconds: 86_400, trialActive: false), exact)
    }

    func testConfiguredCooloffIsFormattedTheSameWay() {
        XCTAssertEqual(HomeLayout.emergencyDescription(cooloffSeconds: 12 * 3600, trialActive: false),
                       exact.replacingOccurrences(of: "after 24 hours", with: "after 12 hours"))
        XCTAssertTrue(HomeLayout.emergencyDescription(cooloffSeconds: 3600, trialActive: false)
            .contains("after 1 hour instead"))
        XCTAssertTrue(HomeLayout.emergencyDescription(cooloffSeconds: 3 * 86_400, trialActive: false)
            .contains("after 3 days instead"))
    }

    func testTrialDayHasNoCooloff() {
        let s = HomeLayout.emergencyDescription(cooloffSeconds: 86_400, trialActive: true)
        XCTAssertFalse(s.contains("24 hours"), s)
        XCTAssertTrue(s.contains("straight away"), s)
        XCTAssertTrue(s.hasSuffix("You can use it once every 90 days."), s)
    }

    func testStatusDecodesTheCooloff() throws {
        let base = #"{"device_id":"local","name":"This Mac","platform":"mac","installed_at":1,"grace_until":2,"#
            + #""in_grace_period":false,"released_at":null,"removal_request":null"#
        let a = try JSONDecoder().decode(EscrowClient.DeviceStatus.self,
                                         from: Data((base + #","emergency_cooloff_seconds":43200}"#).utf8))
        XCTAssertEqual(a.emergency_cooloff_seconds, 43_200)
        let b = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data((base + "}").utf8))
        XCTAssertNil(b.emergency_cooloff_seconds)
    }
}
