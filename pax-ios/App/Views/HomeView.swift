// SPDX-License-Identifier: GPL-3.0-only
import SwiftUI

struct HomeView: View {
    @EnvironmentObject var model: AppModel
    @State private var newSite = ""
    @State private var revealedPasscode: String?
    @State private var confirmTurnOff = false
    @State private var now = Date()
    private let tick = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                PaxLogo().padding(.top, 24)

                PaxCard {
                    Text("Pax is on").font(.paxHeading(26)).foregroundColor(.paxNavy)
                    Text("Explicit websites are blocked, and Pax can't be deleted.").foregroundColor(.paxSlate)
                    Label(model.dnsOn ? "Encrypted DNS is on" : "Encrypted DNS is off. Turn it on in Settings › General › VPN & Device Management › DNS.",
                          systemImage: model.dnsOn ? "checkmark.circle" : "exclamationmark.circle")
                        .font(.footnote).foregroundColor(.paxSlate)
                    Label("Turn-off wait: \(model.policy.waitDays) days", systemImage: "hourglass")
                        .font(.footnote).foregroundColor(.paxSlate)
                }

                PaxCard {
                    Text("Your blocked sites").font(.paxHeading(20)).foregroundColor(.paxNavy)
                    HStack {
                        TextField("example.com", text: $newSite)
                            .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                        Button("Add") { Task { await model.addSite(newSite); newSite = "" } }
                    }
                    ForEach(model.policy.blockedDomains, id: \.self) { d in
                        Text(d).font(.callout).foregroundColor(.paxSlate)
                    }
                    Text("Adding a site is instant. Removing one takes your turn-off wait.")
                        .font(.footnote).foregroundColor(.paxSlate)
                }

                PaxCard {
                    Text("Turn off Pax").font(.paxHeading(20)).foregroundColor(.paxNavy)
                    if let unlock = model.turnOffUnlockAt {
                        let left = unlock.timeIntervalSince(now)
                        Text(left > 0 ? "You can turn Pax off in \(TurnOffRules.describe(remaining: left))."
                                      : "Your wait has ended.").foregroundColor(.paxSlate)
                        if left <= 0 {
                            Button("Turn off now") {
                                Task { revealedPasscode = await model.confirmTurnOff() }
                            }.buttonStyle(PaxPillButtonStyle())
                        }
                        Button("Keep Pax on") { Task { await model.cancelTurnOff() } }
                            .buttonStyle(PaxPillButtonStyle(filled: false))
                    } else {
                        Text("You can always turn Pax off. It takes your wait\(model.policy.hasPartner ? ", and your partner is told first" : "").")
                            .foregroundColor(.paxSlate)
                        Button("Ask to turn off") { confirmTurnOff = true }
                            .buttonStyle(PaxPillButtonStyle(filled: false))
                    }
                }

                Text("A computer restore removes Pax on any iPhone. For something stronger, there's Pax Strict for Mac.")
                    .font(.footnote).foregroundColor(.paxSlate).multilineTextAlignment(.center)

                if let m = model.message { Text(m).font(.footnote).foregroundColor(.paxSlate) }
            }
            .padding(24).frame(maxWidth: 560).frame(maxWidth: .infinity)
        }
        .onReceive(tick) { now = $0 }
        .confirmationDialog("Start your turn-off wait?", isPresented: $confirmTurnOff, titleVisibility: .visible) {
            Button("Start the wait") { Task { await model.requestTurnOff() } }
            Button("Keep Pax on", role: .cancel) {}
        }
        .alert("Pax is off", isPresented: Binding(get: { revealedPasscode != nil }, set: { if !$0 { revealedPasscode = nil } })) {
            Button("Done") { revealedPasscode = nil }
        } message: {
            Text("Your Screen Time passcode is \(revealedPasscode ?? ""). You can change or remove it in Settings › Screen Time.")
        }
    }
}
