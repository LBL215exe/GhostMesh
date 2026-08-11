import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vm: AppViewModel
    @State private var showPairing = false
    @State private var showSettings = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack {
                        Circle()
                            .fill(vm.myOnionAddress != nil ? Color.green : Color.orange)
                            .frame(width: 8, height: 8)
                        Text(vm.torStatus)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text("\(vm.meshPeerCount) mesh peer(s)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Section("Contacts") {
                    ForEach(vm.contacts) { contact in
                        NavigationLink(value: contact.id) {
                            HStack {
                                Circle()
                                    .fill(contact.isOnlineMesh ? Color.green : (contact.onionAddress != nil ? Color.purple : Color.gray))
                                    .frame(width: 8, height: 8)
                                VStack(alignment: .leading) {
                                    Text(contact.displayName).bold()
                                    Text(contact.id.prefix(16) + "…")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                    if vm.contacts.isEmpty {
                        Text("No contacts yet. Tap + to pair with someone nearby or share your QR code.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("GhostMesh")
            .navigationDestination(for: String.self) { contactID in
                if let contact = vm.contacts.first(where: { $0.id == contactID }) {
                    ChatView(contact: contact)
                }
            }
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showPairing = true } label: { Image(systemName: "plus") }
                }
            }
            .sheet(isPresented: $showPairing) { PairingView() }
            .sheet(isPresented: $showSettings) { SettingsView() }
            .fullScreenCover(isPresented: Binding(
                get: { vm.calls.state != .idle },
                set: { if !$0 { } }
            )) {
                CallView(calls: vm.calls)
            }
        }
    }
}

#Preview {
    ContentView().environmentObject(AppViewModel())
}
