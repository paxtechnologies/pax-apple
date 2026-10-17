// SPDX-License-Identifier: GPL-3.0-only
// Runs on a daily schedule and re-applies the person's own settings, so they stay in
// place after a restart or an update (self-heal). It never removes anything.
import DeviceActivity
import ManagedSettings
import FamilyControls

final class PaxMonitor: DeviceActivityMonitor {
    override func intervalDidStart(for activity: DeviceActivityName) {
        super.intervalDidStart(for: activity)
        PaxRestrictions.apply(PaxPolicy.load())
    }

    override func intervalDidEnd(for activity: DeviceActivityName) {
        super.intervalDidEnd(for: activity)
        PaxRestrictions.apply(PaxPolicy.load())
    }
}
