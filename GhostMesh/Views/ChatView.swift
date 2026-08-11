import SwiftUI

struct ChatView: View {
    @EnvironmentObject var vm: AppViewModel
    @ObservedObject var contact: Contact
    @State private var draft = ""

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(vm.messagesByContact[contact.id] ?? []) { msg in
                            bubble(msg).id(msg.id)
                        }
                    }
                    .padding(12)
                }
                .onChange(of: vm.messagesByContact[contact.id]?.count) { _, _ in
                    if let last = vm.messagesByContact[contact.id]?.last {
                        withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }
            HStack {
                TextField("Message (E2E encrypted)", text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(sendDraft)
                Button("Send", action: sendDraft)
                    .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(12)
        }
        .navigationTitle(contact.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    vm.calls.startCall(to: contact)
                } label: {
                    Image(systemName: "phone.fill")
                }
                .disabled(!contact.isOnlineMesh && contact.onionAddress == nil)
            }
        }
    }

    private func sendDraft() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        vm.send(text: text, to: contact)
        draft = ""
    }

    @ViewBuilder
    private func bubble(_ msg: ChatMessage) -> some View {
        HStack {
            if msg.outgoing { Spacer(minLength: 40) }
            VStack(alignment: .leading, spacing: 2) {
                Text(msg.text)
                HStack(spacing: 4) {
                    Image(systemName: iconFor(msg.path))
                    Text(msg.path.rawValue).font(.system(size: 9))
                }
                .foregroundStyle(.secondary)
            }
            .padding(10)
            .background(msg.outgoing ? Color.accentColor.opacity(0.25) : Color(.secondarySystemBackground))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            if !msg.outgoing { Spacer(minLength: 40) }
        }
    }

    private func iconFor(_ path: DeliveryPath) -> String {
        switch path {
        case .mesh: return "antenna.radiowaves.left.and.right"
        case .tor: return "circle.hexagongrid.fill"
        case .pending: return "clock"
        case .system: return "info.circle"
        }
    }
}
