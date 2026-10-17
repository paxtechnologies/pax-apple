// SPDX-License-Identifier: GPL-3.0-only
import XCTest
@testable import PaxCore

/// v0.8.18: Home in three steps, the trial day, and the verified-support-release choice.
final class V0818Tests: XCTestCase {
    private let t0 = 1_800_000_000

    private func trial(active: Bool = true, until: Int? = nil, ended: Int? = nil) -> EscrowClient.DeviceStatus.TrialState {
        EscrowClient.DeviceStatus.TrialState(active: active, until: until ?? t0 + 86_400, ended_at: ended)
    }

    private func at(_ ts: Int) -> Date { Date(timeIntervalSince1970: TimeInterval(ts)) }

    func testHomeHasThreeSteps() {
        XCTAssertEqual(HomeLayout.steps, ["Status", "What's blocked", "Turn off"])
    }

    func testStatusPicksOneCalmState() {
        XCTAssertEqual(HomeLayout.status(removalStatus: nil, secondsLeft: 0, trial: nil, now: at(t0)), .protected)
        XCTAssertEqual(HomeLayout.status(removalStatus: nil, secondsLeft: 0, trial: trial(), now: at(t0)),
                       .trial(until: t0 + 86_400))
        // The trial is over by the clock even if the last read said active.
        XCTAssertEqual(HomeLayout.status(removalStatus: nil, secondsLeft: 0, trial: trial(), now: at(t0 + 86_401)),
                       .protected)
        XCTAssertEqual(HomeLayout.status(removalStatus: "pending", secondsLeft: 44_340, trial: trial(), now: at(t0)),
                       .turningOff(secondsLeft: 44_340, notifying: false))
        XCTAssertEqual(HomeLayout.status(removalStatus: "notifying", secondsLeft: 9, trial: nil, now: at(t0)),
                       .turningOff(secondsLeft: 9, notifying: true))
        XCTAssertEqual(HomeLayout.status(removalStatus: "cancelled", secondsLeft: 0, trial: nil, now: at(t0)), .protected)
        XCTAssertEqual(HomeLayout.headline(.protected), "Protected")
        XCTAssertEqual(HomeLayout.headline(.trial(until: 1)), "Protected")
        XCTAssertEqual(HomeLayout.headline(.turningOff(secondsLeft: 12 * 3600 + 19 * 60, notifying: false)),
                       "Pax turns off in 12 h 19 min")
    }

    func testOneThingToKnow() {
        XCTAssertNil(HomeLayout.noticesSummary(count: 0))
        XCTAssertEqual(HomeLayout.noticesSummary(count: 1), "1 thing to know")
        XCTAssertEqual(HomeLayout.noticesSummary(count: 3), "3 things to know")
    }

    func testCountsAndCaptions() {
        XCTAssertEqual(HomeLayout.sitesCount(0), "No sites yet")
        XCTAssertEqual(HomeLayout.sitesCount(1), "1 site")
        XCTAssertEqual(HomeLayout.sitesCount(12), "12 sites")
        XCTAssertEqual(HomeLayout.appsCount(2), "2 apps")
        XCTAssertEqual(HomeLayout.turnOffCaption(waitSeconds: 3 * 86_400, trialActive: false),
                       "Takes 3 days after you ask. You can cancel any time during the wait.")
        XCTAssertTrue(HomeLayout.turnOffCaption(waitSeconds: 3 * 86_400, trialActive: true).contains("No wait today"))
        XCTAssertEqual(HomeLayout.turnOffButton(trialActive: false), "Start the turn-off wait")
        XCTAssertEqual(HomeLayout.turnOffButton(trialActive: true), "Turn Pax off")
    }

    func testFilterLineOnlyWhenUnusual() throws {
        func dns(_ json: String) throws -> GuardClient.Status.DNS {
            try JSONDecoder().decode(GuardClient.Status.DNS.self, from: Data(json.utf8))
        }
        XCTAssertFalse(HomeLayout.filterNeedsNotice(nil))
        XCTAssertFalse(HomeLayout.filterNeedsNotice(try dns(#"{"active":"CleanBrowsing Family","ready":true}"#)))
        XCTAssertTrue(HomeLayout.filterNeedsNotice(try dns(#"{"active":"AdGuard Family","ready":true}"#)))
        XCTAssertTrue(HomeLayout.filterNeedsNotice(try dns(#"{"active":null,"all_down":true}"#)))
    }

    func testTrialDayWords() {
        XCTAssertTrue(TrialDay.setUpDefault)
        XCTAssertTrue(TrialDay.setUpLine.contains("24 hours"))
        XCTAssertTrue(TrialDay.setUpLine.contains("turn-off wait applies by itself"))
        XCTAssertEqual(TrialDay.startWaitButton, "Start my wait now")
        var cal = Calendar(identifier: .gregorian)
        cal.timeZone = TimeZone(identifier: "Europe/London")!
        let line = TrialDay.homeLine(until: t0, calendar: cal, locale: Locale(identifier: "en_GB"))
        XCTAssertTrue(line.hasPrefix("Trial day · turn off anytime until "), line)
        XCTAssertEqual(TrialDay.countdown(secondsLeft: 23 * 3600 + 10 * 60), "23 h 10 min left")
        XCTAssertTrue(TrialDay.countdown(secondsLeft: 0).contains("over"))
        for s in [TrialDay.setUpLine, TrialDay.confirmMessage, TrialDay.turnOffCaption, line] {
            XCTAssertFalse(s.contains("!"), s)
        }
    }

    func testTrialActivityFollowsTheClock() {
        XCTAssertTrue(TrialDay.isActive(trial(), now: at(t0)))
        XCTAssertFalse(TrialDay.isActive(trial(), now: at(t0 + 86_400)))
        XCTAssertFalse(TrialDay.isActive(trial(active: false, ended: t0 - 5), now: at(t0)))
        XCTAssertFalse(TrialDay.isActive(nil, now: at(t0)))
        XCTAssertEqual(TrialDay.secondsLeft(trial(), now: at(t0 + 3600)), 23 * 3600)
        XCTAssertEqual(TrialDay.secondsLeft(trial(active: false), now: at(t0)), 0)
        XCTAssertNotNil(TrialDay.settingsLine(trial(), now: at(t0)))
        XCTAssertTrue(TrialDay.settingsLine(trial(active: false, ended: t0), now: at(t0 + 10))!.contains("ended early"))
        XCTAssertNil(TrialDay.settingsLine(nil))
    }

    func testDeviceStatusDecodesTheTrial() throws {
        let base = #"{"device_id":"d","name":"n","platform":"ios","installed_at":1,"grace_until":2,"#
            + #""in_grace_period":true,"released_at":null,"removal_request":null"#
        let with = try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(
            (base + #","trial":{"active":true,"until":1800086400,"ended_at":null}}"#).utf8))
        XCTAssertEqual(with.trial, EscrowClient.DeviceStatus.TrialState(active: true, until: 1_800_086_400))
        // pax-guard also sends started_at; an older server or guard sends nothing.
        let guardJSON = base + #","trial":{"active":false,"until":5,"ended_at":3,"started_at":1}}"#
        XCTAssertEqual(try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(guardJSON.utf8)).trial?.ended_at, 3)
        XCTAssertNil(try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data((base + "}").utf8)).trial)
        let none = base + #","trial":null}"#
        XCTAssertNil(try JSONDecoder().decode(EscrowClient.DeviceStatus.self, from: Data(none.utf8)).trial)
    }

    func testDepositAsksForATrialDay() {
        let on = MacLockdownCommands.localEscrowDeposit(guardSource: "/R/guard", secretFile: "/tmp/s",
                                                        waitSeconds: 86_400, isExecutable: { _ in false })
        XCTAssertEqual(on.1[on.1.firstIndex(of: "--trial")! + 1], "on")
        XCTAssertTrue(on.1.joined(separator: " ").contains("--wait-seconds 86400 --reset"))
        let off = MacLockdownCommands.localEscrowDeposit(guardSource: "/R/guard", secretFile: "/tmp/s",
                                                         waitSeconds: 86_400, trial: false, isExecutable: { _ in false })
        XCTAssertEqual(off.1[off.1.firstIndex(of: "--trial")! + 1], "off")
    }

    func testHardwareIDIsHashedAndStable() {
        let a = TrialDay.hardwareID("0x1A2B3C")!
        XCTAssertEqual(a.count, 64)
        XCTAssertEqual(a, TrialDay.hardwareID(" 0x1a2b3c\n"))
        XCTAssertNotEqual(a, TrialDay.hardwareID("0x1A2B3D"))
        XCTAssertFalse(a.contains("1a2b3c"))
        XCTAssertNil(TrialDay.hardwareID("  "))
    }

    func testSupportReleaseSetUpChoice() {
        XCTAssertTrue(VerifiedSupportRelease.setUpDefault)          // on by default since 0.8.15
        XCTAssertTrue(SetupConfiguration().supportRelease)
        XCTAssertEqual(VerifiedSupportRelease.setUpCheckbox, "Allow verified support release (recommended)")
        XCTAssertTrue(VerifiedSupportRelease.detail(allowed: false, pendingOnAt: nil).contains("full wait"))
        XCTAssertTrue(VerifiedSupportRelease.detail(allowed: false, pendingOnAt: nil, trialActive: true)
            .contains("instant during your trial day"))
        XCTAssertTrue(AppSettingsLayout.Line.supportReleaseRule.contains("Turning it off is instant"))
    }
}
