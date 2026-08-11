import Foundation
import Combine

@MainActor
final class CallViewModel: ObservableObject {

    @Published var state: CallState = .idle
    @Published var activeContact: Contact?
    @Published var usingTor = false
    @Published var muted = false

    private let mesh: MeshTransport
    private let tor: TorTransport
    private let audio = CallAudioEngine()
    private var pendingOffer: CallSession.PendingOffer?
    private var session: CallSession?
    private var incomingOfferEphemeral: Data?

    /// Set by AppViewModel: how to reach the outgoing control channel
    /// (encrypt+route a PlaintextPayload through the contact's text
    /// ratchet), since CallViewModel doesn't own contacts/router itself.
    var sendControl: ((PlaintextPayload, Contact) -> Void)?

    init(mesh: MeshTransport, tor: TorTransport) {
        self.mesh = mesh
        self.tor = tor
        mesh.onCallFrame = { [weak self] frame in
            Task { @MainActor in self?.handleIncomingFrame(frame) }
        }
        Task { await tor.setCallFrameHandler { [weak self] frame in
            Task { @MainActor in self?.handleIncomingFrame(frame) }
        }}
    }

    // MARK: - Outgoing

    func startCall(to contact: Contact) {
        guard state == .idle else { return }
        let (pending, ephemeralPublicKey) = CallSession.makeOffer()
        pendingOffer = pending
        activeContact = contact
        state = .outgoingRinging(callID: pending.callID)
        sendControl?(PlaintextPayload(kind: .callOffer, callID: pending.callID, ephemeralPublicKey: ephemeralPublicKey), contact)
    }

    func cancelOutgoing() {
        guard case .outgoingRinging(let callID) = state else { return }
        if let contact = activeContact {
            sendControl?(PlaintextPayload(kind: .callEnd, callID: callID), contact)
        }
        reset()
    }

    // MARK: - Incoming (called by AppViewModel when a callOffer arrives)

    func handleOffer(callID: UUID, ephemeralPublicKey: Data, from contact: Contact) {
        guard state == .idle else {
            sendControl?(PlaintextPayload(kind: .callEnd, callID: callID), contact)
            return
        }
        activeContact = contact
        incomingOfferEphemeral = ephemeralPublicKey
        state = .incomingRinging(callID: callID)
    }

    func acceptIncoming() {
        guard case .incomingRinging(let callID) = state,
              let contact = activeContact,
              let theirKey = incomingOfferEphemeral else { return }
        do {
            let (newSession, myKey) = try CallSession.completeAsCallee(callID: callID, theirEphemeralPublicKeyRaw: theirKey)
            session = newSession
            sendControl?(PlaintextPayload(kind: .callAnswer, callID: callID, ephemeralPublicKey: myKey), contact)
            Task { await beginMedia(with: contact, callID: callID) }
        } catch {
            print("Call accept failed: \(error)")
            reset()
        }
    }

    func declineIncoming() {
        guard case .incomingRinging(let callID) = state, let contact = activeContact else { return }
        sendControl?(PlaintextPayload(kind: .callEnd, callID: callID), contact)
        reset()
    }

    // MARK: - Answer arriving (caller side, called by AppViewModel)

    func handleAnswer(callID: UUID, ephemeralPublicKey: Data) {
        guard case .outgoingRinging(let ringingCallID) = state, ringingCallID == callID,
              let pending = pendingOffer, let contact = activeContact else { return }
        do {
            let newSession = try CallSession.completeAsCaller(pending: pending, theirEphemeralPublicKeyRaw: ephemeralPublicKey)
            session = newSession
            Task { await beginMedia(with: contact, callID: callID) }
        } catch {
            print("Call completion failed: \(error)")
            reset()
        }
    }

    func handleRemoteEnd(callID: UUID) {
        guard callIDMatches(callID) else { return }
        reset()
    }

    func endCall() {
        guard let contact = activeContact, let callID = currentCallID else { return }
        sendControl?(PlaintextPayload(kind: .callEnd, callID: callID), contact)
        reset()
    }

    func toggleMute() { muted.toggle() }

    // MARK: - Media

    private func beginMedia(with contact: Contact, callID: UUID) async {
        let viaMesh = contact.isOnlineMesh
        usingTor = !viaMesh

        if !viaMesh {
            guard let onion = contact.onionAddress else {
                reset(); return
            }
            do {
                try await tor.openCallStream(callID: callID, toOnion: onion)
            } catch {
                print("Tor call stream failed: \(error)")
                reset(); return
            }
        }

        audio.onCapturedFrame = { [weak self] pcm in
            guard let self, !self.muted, let session = self.session else { return }
            guard let frame = try? session.encryptFrame(pcm) else { return }
            if viaMesh {
                self.mesh.sendCallFrame(frame, toPeerDisplayName: contact.id.prefix(8).description)
            } else {
                Task { try? await self.tor.sendCallFrame(frame, callID: callID) }
            }
        }

        do {
            try audio.start()
            state = .connected(callID: callID)
        } catch {
            print("Audio start failed: \(error)")
            reset()
        }
    }

    private func handleIncomingFrame(_ frame: CallFrame) {
        guard let session, frame.callID == currentCallID else { return }
        guard let pcm = try? session.decryptFrame(frame) else { return }
        audio.enqueueForPlayback(sequence: frame.sequence, pcm: pcm)
    }

    private var currentCallID: UUID? {
        switch state {
        case .outgoingRinging(let id), .incomingRinging(let id), .connected(let id): return id
        case .idle: return nil
        }
    }

    private func callIDMatches(_ id: UUID) -> Bool { currentCallID == id }

    private func reset() {
        audio.stop()
        if let callID = currentCallID, usingTor {
            Task { await tor.closeCallStream(callID: callID) }
        }
        state = .idle
        activeContact = nil
        pendingOffer = nil
        session = nil
        incomingOfferEphemeral = nil
        usingTor = false
        muted = false
    }
}
