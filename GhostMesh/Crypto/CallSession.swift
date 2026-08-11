import Foundation
import CryptoKit

/// Call-time crypto: a fresh, ephemeral X25519 key exchange per call (so a
/// compromised long-term identity key never exposes a past call's audio,
/// and one call's key material is unrelated to any other call's or to the
/// text ratchet's), followed by two one-directional frame ratchets — one
/// per speaking direction — so every audio frame is encrypted under its
/// own single-use key, the same forward-secrecy property as the text
/// ratchet, just applied per-frame instead of per-message.
///
/// The call offer/answer (the two ephemeral public keys) travel as control
/// messages through the already-authenticated text Double Ratchet channel,
/// so a network attacker can't substitute their own key into the call setup
/// even though the call media itself may go over a separate connection.
final class CallSession {

    let callID: UUID
    private var sendChain: SymmetricKey
    private var receiveChain: SymmetricKey
    private(set) var sendFrameCounter: UInt32 = 0
    private(set) var receiveFrameCounter: UInt32 = 0

    struct PendingOffer {
        let callID: UUID
        let ephemeral: Curve25519.KeyAgreement.PrivateKey
    }

    /// Caller side: generate our ephemeral key, remember it until the
    /// answer arrives.
    static func makeOffer() -> (pending: PendingOffer, ephemeralPublicKey: Data) {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        return (PendingOffer(callID: UUID(), ephemeral: ephemeral), ephemeral.publicKey.rawRepresentation)
    }

    /// Caller side: once the answer's ephemeral public key arrives, derive
    /// the two directional chains. Caller sends on "A2B", receives on "B2A".
    static func completeAsCaller(pending: PendingOffer, theirEphemeralPublicKeyRaw: Data) throws -> CallSession {
        let theirKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirEphemeralPublicKeyRaw)
        let shared = try pending.ephemeral.sharedSecretFromKeyAgreement(with: theirKey)
        let ikm = SymmetricKey(data: shared.withUnsafeBytes { Data($0) })
        let salt = Data("GhostMesh-Call-v1".utf8)
        let a2b = RatchetPrimitives.hkdf(ikm: ikm, salt: salt, info: Data("A2B".utf8), outputByteCount: 32)
        let b2a = RatchetPrimitives.hkdf(ikm: ikm, salt: salt, info: Data("B2A".utf8), outputByteCount: 32)
        return CallSession(callID: pending.callID, sendChain: SymmetricKey(data: a2b), receiveChain: SymmetricKey(data: b2a))
    }

    /// Callee side: given the caller's ephemeral public key from the offer,
    /// generate our own ephemeral key, derive chains (mirrored: we send on
    /// "B2A", receive on "A2B"), and return the public key to send back as
    /// the answer.
    static func completeAsCallee(callID: UUID, theirEphemeralPublicKeyRaw: Data) throws -> (session: CallSession, myEphemeralPublicKey: Data) {
        let myEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let theirKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirEphemeralPublicKeyRaw)
        let shared = try myEphemeral.sharedSecretFromKeyAgreement(with: theirKey)
        let ikm = SymmetricKey(data: shared.withUnsafeBytes { Data($0) })
        let salt = Data("GhostMesh-Call-v1".utf8)
        let a2b = RatchetPrimitives.hkdf(ikm: ikm, salt: salt, info: Data("A2B".utf8), outputByteCount: 32)
        let b2a = RatchetPrimitives.hkdf(ikm: ikm, salt: salt, info: Data("B2A".utf8), outputByteCount: 32)
        let session = CallSession(callID: callID, sendChain: SymmetricKey(data: b2a), receiveChain: SymmetricKey(data: a2b))
        return (session, myEphemeral.publicKey.rawRepresentation)
    }

    private init(callID: UUID, sendChain: SymmetricKey, receiveChain: SymmetricKey) {
        self.callID = callID
        self.sendChain = sendChain
        self.receiveChain = receiveChain
    }

    /// Encrypts one audio frame. Each call advances the send chain and
    /// discards the previous key — a memory snapshot after frame N cannot
    /// decrypt frame N-1. The nonce is deterministic (derived from the
    /// frame counter) which is safe here specifically because every frame
    /// key is itself single-use — there is never a nonce reused under the
    /// same key.
    func encryptFrame(_ pcm: Data) throws -> CallFrame {
        let (next, frameKey) = RatchetPrimitives.kdfChainKey(sendChain)
        sendChain = next
        let counter = sendFrameCounter
        sendFrameCounter += 1

        let nonce = try Self.nonce(for: counter)
        let sealed = try AES.GCM.seal(pcm, using: frameKey, nonce: nonce)
        guard let combined = sealed.combined else { throw CallCryptoError.sealFailed }
        return CallFrame(callID: callID, sequence: counter, ciphertext: combined)
    }

    /// Decrypts one audio frame. If frames were dropped in transit, fast-
    /// forwards the receive chain to match (their keys are simply discarded
    /// — never rewound, so nothing is ever decrypted with a reused key).
    func decryptFrame(_ frame: CallFrame) throws -> Data {
        guard frame.sequence >= receiveFrameCounter else { throw CallCryptoError.replayOrTooOld }
        while receiveFrameCounter < frame.sequence {
            let (next, _) = RatchetPrimitives.kdfChainKey(receiveChain)
            receiveChain = next
            receiveFrameCounter += 1
        }
        let (next, frameKey) = RatchetPrimitives.kdfChainKey(receiveChain)
        receiveChain = next
        receiveFrameCounter += 1

        let box = try AES.GCM.SealedBox(combined: frame.ciphertext)
        return try AES.GCM.open(box, using: frameKey)
    }

    private static func nonce(for counter: UInt32) throws -> AES.GCM.Nonce {
        var bytes = Data(count: 8) // zero-padded high bytes
        bytes.append(withUnsafeBytes(of: counter.bigEndian) { Data($0) })
        return try AES.GCM.Nonce(data: bytes)
    }

    enum CallCryptoError: Error { case sealFailed, replayOrTooOld }
}

/// One encrypted audio frame as it goes over the wire (mesh or Tor).
struct CallFrame: Codable {
    let callID: UUID
    let sequence: UInt32
    let ciphertext: Data
}
