import Foundation
import MultipeerConnectivity

/// Local, internet-free mesh transport over Bluetooth/WiFi via
/// MultipeerConnectivity. Every device advertises and browses at once, so
/// the mesh forms opportunistically: the more copies of the app are open
/// nearby, the more relay paths exist and the further a message can hop.
///
/// Peers relay ciphertext blindly — a relay never has the keys to read what
/// it's forwarding. Flood routing with a TTL and a short-lived seen-ID cache
/// keeps a message from looping forever.
final class MeshTransport: NSObject, ObservableObject {

    @Published var connectedPeerCount = 0
    @Published var connectedPeerDisplayNames: Set<String> = []

    private let myPeerID: MCPeerID
    private let serviceType = "ghostmesh-p2p" // must be <=15 chars, alnum+hyphen
    private var session: MCSession!
    private var advertiser: MCNearbyServiceAdvertiser!
    private var browser: MCNearbyServiceBrowser!

    private var seenMessageIDs = Set<UUID>()
    private let seenIDLimit = 500
    private var seenIDOrder: [UUID] = []

    /// Wire framing: every payload sent over an MCSession carries a 1-byte
    /// type tag so a raw real-time call frame is never mistaken for a
    /// flooded chat/control WireMessage or vice versa.
    private enum FrameType: UInt8 { case wireMessage = 0x01, callFrame = 0x02 }

    /// Called with a WireMessage that arrived addressed to (or relayed
    /// through) this device. The router decides whether it's for us or
    /// needs re-flooding.
    var onReceive: ((WireMessage) -> Void)?
    /// Called for real-time call audio frames, received directly (never
    /// flooded/relayed — calls require a direct mesh link).
    var onCallFrame: ((CallFrame) -> Void)?

    init(displayName: String) {
        myPeerID = MCPeerID(displayName: displayName)
        super.init()
        session = MCSession(peer: myPeerID, securityIdentity: nil, encryptionPreference: .required)
        session.delegate = self
        advertiser = MCNearbyServiceAdvertiser(peer: myPeerID, discoveryInfo: nil, serviceType: serviceType)
        advertiser.delegate = self
        browser = MCNearbyServiceBrowser(peer: myPeerID, serviceType: serviceType)
        browser.delegate = self
    }

    func start() {
        advertiser.startAdvertisingPeer()
        browser.startBrowsingForPeers()
    }

    func stop() {
        advertiser.stopAdvertisingPeer()
        browser.stopBrowsingForPeers()
        session.disconnect()
    }

    /// Floods a message to all currently connected peers. `originating`
    /// should be true only when this device authored the message (so it
    /// gets a fresh TTL); relays just decrement and forward.
    func flood(_ message: WireMessage) {
        guard message.ttl > 0 else { return }
        markSeen(message.id)
        guard let payload = try? JSONEncoder().encode(message) else { return }
        guard !session.connectedPeers.isEmpty else { return }
        try? session.send(frame(.wireMessage, payload), toPeers: session.connectedPeers, with: .reliable)
    }

    /// Sends one call audio frame directly to a specific peer (identified
    /// by the display-name prefix we use, the contact's fingerprint
    /// prefix) — never flooded/relayed, and best-effort/unreliable since a
    /// dropped audio frame should be skipped, not retried.
        func sendCallFrame(_ callFrame: CallFrame, toPeerDisplayName name: String) {
        guard let peer = session.connectedPeers.first(where: { $0.displayName == name }) else { return }
        guard let payload = try? JSONEncoder().encode(callFrame) else { return }
        try? session.send(frame(.callFrame, payload), toPeers: [peer], with: .unreliable)
    }

    private func frame(_ type: FrameType, _ payload: Data) -> Data {
        var data = Data([type.rawValue])
        data.append(payload)
        return data
    }

    private func markSeen(_ id: UUID) {
        seenMessageIDs.insert(id)
        seenIDOrder.append(id)
        if seenIDOrder.count > seenIDLimit {
            let removed = seenIDOrder.removeFirst()
            seenMessageIDs.remove(removed)
        }
    }
}

extension MeshTransport: MCSessionDelegate {
    func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
        DispatchQueue.main.async {
            self.connectedPeerCount = session.connectedPeers.count
            self.connectedPeerDisplayNames = Set(session.connectedPeers.map { $0.displayName })
        }
    }

    func session(_ session: MCSession, didReceive data: Data, fromPeer peerID: MCPeerID) {
        guard let typeByte = data.first, let type = FrameType(rawValue: typeByte) else { return }
        let payload = data.dropFirst()

        switch type {
        case .callFrame:
            guard let callFrame = try? JSONDecoder().decode(CallFrame.self, from: payload) else { return }
            DispatchQueue.main.async { [weak self] in self?.onCallFrame?(callFrame) }

        case .wireMessage:
            guard let message = try? JSONDecoder().decode(WireMessage.self, from: payload) else { return }
            guard !seenMessageIDs.contains(message.id) else { return } // already handled, drop
            markSeen(message.id)

            DispatchQueue.main.async { [weak self] in
                self?.onReceive?(message)
            }

            // Relay onward with decremented TTL, regardless of whether it was
            // addressed to us — the sender can't be identified from ciphertext
            // alone, so every node just keeps the flood moving.
            var relayed = message
            relayed.ttl -= 1
            if relayed.ttl > 0 {
                flood(relayed)
            }
        }
    }

    func session(_ session: MCSession, didReceive stream: InputStream, withName streamName: String, fromPeer peerID: MCPeerID) {}
    func session(_ session: MCSession, didStartReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, with progress: Progress) {}
    func session(_ session: MCSession, didFinishReceivingResourceWithName resourceName: String, fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?) {}
}

extension MeshTransport: MCNearbyServiceAdvertiserDelegate {
    func advertiser(_ advertiser: MCNearbyServiceAdvertiser, didReceiveInvitationFromPeer peerID: MCPeerID, withContext context: Data?, invitationHandler: @escaping (Bool, MCSession?) -> Void) {
        invitationHandler(true, session)
    }
}

extension MeshTransport: MCNearbyServiceBrowserDelegate {
    func browser(_ browser: MCNearbyServiceBrowser, foundPeer peerID: MCPeerID, withDiscoveryInfo info: [String: String]?) {
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 15)
    }

    func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
        DispatchQueue.main.async {
            self.connectedPeerCount = self.session.connectedPeers.count
            self.connectedPeerDisplayNames = Set(self.session.connectedPeers.map { $0.displayName })
        }
    }
}
