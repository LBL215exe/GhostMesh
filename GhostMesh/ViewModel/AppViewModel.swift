import Foundation
import CryptoKit
import Combine

@MainActor
final class AppViewModel: ObservableObject {

    @Published var identity: Identity
    @Published var contacts: [Contact] = []
    @Published var messagesByContact: [String: [ChatMessage]] = [:]
    @Published var torStatus = "Starting Tor..."
    @Published var myOnionAddress: String?
    @Published var meshPeerCount = 0
    @Published var persistHistoryLocally = false {
        didSet { UserDefaults.standard.set(persistHistoryLocally, forKey: "gm_persist") }
    }

    let calls: CallViewModel

    private let mesh: MeshTransport
    private let tor = TorTransport()
    private var router: MessageRouter!

    init() {
        identity = Identity.generate()
        persistHistoryLocally = UserDefaults.standard.bool(forKey: "gm_persist")
        // Unspaced raw fingerprint — must match how Contact.id is derived
        // from a scanned PairingBundle, since mesh peer matching compares
        // these strings directly.
        mesh = MeshTransport(displayName: identity.rawFingerprint.prefix(8).description)
        let torTransport = tor
        router = MessageRouter(mesh: mesh, tor: torTransport)
        calls = CallViewModel(mesh: mesh, tor: torTransport)

        mesh.onReceive = { [weak self] wire in
            Task { @MainActor in self?.handleIncoming(wire) }
        }
        mesh.$connectedPeerDisplayNames
            .receive(on: DispatchQueue.main)
            .sink { [weak self] names in self?.updateMeshPresence(names) }
            .store(in: &cancellables)
        mesh.$connectedPeerCount
            .receive(on: DispatchQueue.main)
            .sink { [weak self] count in self?.meshPeerCount = count }
            .store(in: &cancellables)

        mesh.start()

        calls.sendControl = { [weak self] payload, contact in
            self?.sendControl(payload, to: contact)
        }

        Task {
            do {
                try await tor.start()
                await MainActor.run { self.torStatus = "Tor bootstrapped" }
                let address = try await tor.publishInbox()
                await MainActor.run {
                    self.myOnionAddress = address
                    self.torStatus = "Onion inbox live"
                }
                await tor.setInboxHandler { [weak self] wire in
                    Task { @MainActor in self?.handleIncoming(wire) }
                }
            } catch {
                await MainActor.run { self.torStatus = "Tor unavailable: \(error.localizedDescription)" }
            }
        }
    }

    private var cancellables = Set<AnyCancellable>()

    private func updateMeshPresence(_ connectedDisplayNames: Set<String>) {
        for contact in contacts {
            contact.isOnlineMesh = connectedDisplayNames.contains(String(contact.id.prefix(8)))
            if contact.isOnlineMesh { contact.lastSeenViaMesh = Date() }
        }
    }

    // MARK: - Pairing

    func myPairingBundle() -> PairingBundle {
        var bundle = identity.exportBundle()
        bundle.onionAddress = myOnionAddress
        return bundle
    }

    func addContact(named name: String, bundle: PairingBundle) {
        guard bundle.verify() else { return }
        let contact = Contact(displayName: name, bundle: bundle)
        do {
            let (rootKey, ephemeralPublic) = try X3DH.initiate(myIdentity: identity, theirBundle: bundle)
            let theirRatchetKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: bundle.signedPrekey)
            contact.session = RatchetSession(rootKey: rootKey, theirRatchetPublicKey: theirRatchetKey)
            contacts.append(contact)
            messagesByContact[contact.id] = []
            _ = ephemeralPublic // in a full X3DH handshake this rides on the
            // first WireMessage so the responder can complete their side;
            // simplified here since pairing already exchanges full bundles
            // (including signed prekeys) directly via QR, not through a
            // server-hosted prekey store.
        } catch {
            print("X3DH init failed: \(error)")
        }
    }

    // MARK: - Sending (chat)

    func send(text: String, to contact: Contact) {
        guard let session = contact.session, let data = try? JSONEncoder().encode(PlaintextPayload(kind: .chat, text: text)) else { return }
        do {
            let envelope = try session.encrypt(plaintext: data, associatedData: Data(identity.rawFingerprint.utf8))
            let wire = WireMessage(id: UUID(), senderFingerprint: identity.rawFingerprint, envelope: envelope, ttl: 8)
            let path: DeliveryPath = contact.isOnlineMesh ? .mesh : (contact.onionAddress != nil ? .tor : .pending)
            appendMessage(ChatMessage(contactID: contact.id, text: text, outgoing: true, path: path, timestamp: Date()), for: contact.id)
            Task { await router.route(wire, to: contact) }
        } catch {
            print("Encrypt failed: \(error)")
        }
    }

    // MARK: - Sending (call signaling — not shown in chat UI)

    private func sendControl(_ payload: PlaintextPayload, to contact: Contact) {
        guard let session = contact.session, let data = try? JSONEncoder().encode(payload) else { return }
        do {
            let envelope = try session.encrypt(plaintext: data, associatedData: Data(identity.rawFingerprint.utf8))
            let wire = WireMessage(id: UUID(), senderFingerprint: identity.rawFingerprint, envelope: envelope, ttl: 8)
            Task { await router.route(wire, to: contact) }
        } catch {
            print("Control encrypt failed: \(error)")
        }
    }

    // MARK: - Receiving

    private func handleIncoming(_ wire: WireMessage) {
        guard let contact = contacts.first(where: { $0.id == wire.senderFingerprint }) else {
            return // unknown sender — silently dropped, never logged
        }
        guard let session = contact.session else { return }
        do {
            let plaintext = try session.decrypt(envelope: wire.envelope, associatedData: Data(wire.senderFingerprint.utf8))
            guard let payload = try? JSONDecoder().decode(PlaintextPayload.self, from: plaintext) else { return }

            switch payload.kind {
            case .chat:
                guard let text = payload.text else { return }
                appendMessage(ChatMessage(contactID: contact.id, text: text, outgoing: false, path: .mesh, timestamp: Date()), for: contact.id)
            case .callOffer:
                guard let callID = payload.callID, let key = payload.ephemeralPublicKey else { return }
                calls.handleOffer(callID: callID, ephemeralPublicKey: key, from: contact)
            case .callAnswer:
                guard let callID = payload.callID, let key = payload.ephemeralPublicKey else { return }
                calls.handleAnswer(callID: callID, ephemeralPublicKey: key)
            case .callEnd:
                guard let callID = payload.callID else { return }
                calls.handleRemoteEnd(callID: callID)
            }
        } catch {
            print("Decrypt failed (possibly out-of-order beyond skip window): \(error)")
        }
    }

    private func appendMessage(_ message: ChatMessage, for contactID: String) {
        messagesByContact[contactID, default: []].append(message)
        // Deliberately not persisted unless persistHistoryLocally is on;
        // even then, persistence would write to a Keychain-encrypted store,
        // never anything resembling a server log.
    }
}
