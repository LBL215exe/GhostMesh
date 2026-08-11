import SwiftUI

struct CallView: View {
    @ObservedObject var calls: CallViewModel

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Text(calls.activeContact?.displayName ?? "Unknown")
                .font(.largeTitle.bold())
            Text(statusText)
                .foregroundStyle(.secondary)

            if calls.usingTor {
                Label("Routed via Tor — expect delay", systemImage: "circle.hexagongrid.fill")
                    .font(.caption)
                    .foregroundStyle(.purple)
                    .padding(8)
                    .background(Color.purple.opacity(0.15))
                    .clipShape(Capsule())
            }

            Spacer()

            switch calls.state {
            case .incomingRinging:
                HStack(spacing: 40) {
                    Button {
                        calls.declineIncoming()
                    } label: {
                        Image(systemName: "phone.down.fill")
                            .font(.title)
                            .frame(width: 64, height: 64)
                            .background(Color.red)
                            .foregroundStyle(.white)
                            .clipShape(Circle())
                    }
                    Button {
                        calls.acceptIncoming()
                    } label: {
                        Image(systemName: "phone.fill")
                            .font(.title)
                            .frame(width: 64, height: 64)
                            .background(Color.green)
                            .foregroundStyle(.white)
                            .clipShape(Circle())
                    }
                }
            case .outgoingRinging:
                Button {
                    calls.cancelOutgoing()
                } label: {
                    Image(systemName: "phone.down.fill")
                        .font(.title)
                        .frame(width: 64, height: 64)
                        .background(Color.red)
                        .foregroundStyle(.white)
                        .clipShape(Circle())
                }
            case .connected:
                HStack(spacing: 40) {
                    Button {
                        calls.toggleMute()
                    } label: {
                        Image(systemName: calls.muted ? "mic.slash.fill" : "mic.fill")
                            .font(.title2)
                            .frame(width: 56, height: 56)
                            .background(Color(.secondarySystemBackground))
                            .clipShape(Circle())
                    }
                    Button {
                        calls.endCall()
                    } label: {
                        Image(systemName: "phone.down.fill")
                            .font(.title)
                            .frame(width: 64, height: 64)
                            .background(Color.red)
                            .foregroundStyle(.white)
                            .clipShape(Circle())
                    }
                }
            case .idle:
                EmptyView()
            }
            Spacer()
        }
        .padding()
    }

    private var statusText: String {
        switch calls.state {
        case .idle: return ""
        case .outgoingRinging: return "Calling…"
        case .incomingRinging: return "Incoming call"
        case .connected: return calls.usingTor ? "Connected via Tor" : "Connected — local mesh"
        }
    }
}
