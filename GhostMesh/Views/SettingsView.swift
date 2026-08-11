import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var vm: AppViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section("Privacy") {
                    Toggle("Keep local message history", isOn: $vm.persistHistoryLocally)
                    Text(vm.persistHistoryLocally
                         ? "Messages are kept on this device only, encrypted with a Keychain-protected key. Nothing is ever sent to a server."
                         : "Messages exist only in memory. Closing the app clears them. Nothing is ever sent to a server — there is no server.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section("Network") {
                    LabeledContent("Tor status", value: vm.torStatus)
                    if let onion = vm.myOnionAddress {
                        LabeledContent("My onion address", value: onion)
                            .font(.system(.caption, design: .monospaced))
                    }
                    LabeledContent("Mesh peers nearby", value: "\(vm.meshPeerCount)")
                }
                Section("Identity") {
                    Text(vm.identity.fingerprint)
                        .font(.system(.caption, design: .monospaced))
                    Text("This fingerprint is your entire identity. There's no account, phone number, or recovery — losing your device means losing this identity.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }
}

#Preview {
    SettingsView().environmentObject(AppViewModel())
}
