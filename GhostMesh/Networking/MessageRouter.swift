import Foundation

/// Decides how to move a given WireMessage: mesh if the contact is
/// currently reachable over the local peer-to-peer network (fast, free,
/// works with no internet at all), otherwise Tor if we know their onion
/// address, otherwise held in a short-lived in-memory retry queue — never
/// written to disk, never touches any third-party server.
@MainActor
final class MessageRouter: ObservableObject {

    let mesh: MeshTransport
    let tor: TorTransport

    @Published var pendingCount = 0
    private var retryQueue: [(Contact, WireMessage)] = []
    private var retryTask: Task<Void, Never>?

    init(mesh: MeshTransport, tor: TorTransport) {
        self.mesh = mesh
        self.tor = tor
        retryTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(20))
                await self?.drainRetryQueue()
            }
        }
    }

    deinit {
        retryTask?.cancel()
    }

    func route(_ message: WireMessage, to contact: Contact) async {
        if contact.isOnlineMesh {
            mesh.flood(message)
            return
        }
        if let onion = contact.onionAddress {
            do {
                try await tor.send(message, toOnion: onion)
                return
            } catch {
                // fall through to queueing — Tor may just not have a
                // circuit yet, or the peer is temporarily offline.
            }
        }
        retryQueue.append((contact, message))
        pendingCount = retryQueue.count
    }

    private func drainRetryQueue() async {
        guard !retryQueue.isEmpty else { return }
        var stillPending: [(Contact, WireMessage)] = []
        for (contact, message) in retryQueue {
            if contact.isOnlineMesh {
                mesh.flood(message)
                continue
            }
            if let onion = contact.onionAddress, let _ = try? await tor.send(message, toOnion: onion) {
                continue
            }
            stillPending.append((contact, message))
        }
        retryQueue = stillPending
        pendingCount = retryQueue.count
    }
}
