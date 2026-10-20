// SPDX-License-Identifier: GPL-3.0-only
// Woken by four Device Activity schedules a day (Pax.monitorWindows). Each time, it
// re-applies the person's own settings from the App Group, so they stay in place after a
// restart or an update (self-heal). It never removes anything, and if the saved policy
// can't be read it treats Pax as on (PaxPolicy.decode).
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
