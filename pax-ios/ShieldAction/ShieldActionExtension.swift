// SPDX-License-Identifier: GPL-3.0-only
// The shield has one button, Close. There is no "a few more minutes" path.
import ManagedSettings

final class ShieldActionExtension: ShieldActionDelegate {
    override func handle(action: ShieldAction, for application: ApplicationToken,
                         completionHandler: @escaping (ShieldActionResponse) -> Void) { completionHandler(.close) }
    override func handle(action: ShieldAction, for webDomain: WebDomainToken,
                         completionHandler: @escaping (ShieldActionResponse) -> Void) { completionHandler(.close) }
    override func handle(action: ShieldAction, for category: ActivityCategoryToken,
                         completionHandler: @escaping (ShieldActionResponse) -> Void) { completionHandler(.close) }
}
