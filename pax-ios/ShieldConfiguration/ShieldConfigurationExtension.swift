// SPDX-License-Identifier: GPL-3.0-only
// The calm screen shown over an app or site the person chose to keep closed.
import ManagedSettings
import ManagedSettingsUI
import UIKit

final class ShieldConfigurationExtension: ShieldConfigurationDataSource {
    override func configuration(shielding application: Application) -> ShieldConfiguration { paxShield() }
    override func configuration(shielding application: Application, in category: ActivityCategory) -> ShieldConfiguration { paxShield() }
    override func configuration(shielding webDomain: WebDomain) -> ShieldConfiguration { paxShield() }
    override func configuration(shielding webDomain: WebDomain, in category: ActivityCategory) -> ShieldConfiguration { paxShield() }

    private func paxShield() -> ShieldConfiguration {
        ShieldConfiguration(
            backgroundBlurStyle: .extraLight,
            backgroundColor: PaxColor.mist,
            icon: UIImage(named: "ShieldMark"),
            title: .init(text: "pax", color: PaxColor.navy),
            subtitle: .init(text: "You chose to keep this closed for now. Take a breath. It can wait.",
                            color: PaxColor.slate),
            primaryButtonLabel: .init(text: "Close", color: .white),
            primaryButtonBackgroundColor: PaxColor.navy,
            secondaryButtonLabel: nil)
    }
}
