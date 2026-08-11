import Foundation
import CryptoKit

/// A from-scratch implementation of the Signal-style Double Ratchet
/// algorithm: a Diffie-Hellman ratchet (rotates on every direction change)
/// composed with a symmetric-key ratchet (rotates on every single message).
/// Net effect: every message is encrypted under its own one-time key, and
/// that key is discarded immediately after use — forward secrecy per the
/// requirement. A handful of skipped-message keys are retained briefly to
/// tolerate messages arriving out of order over mesh/Tor.
///
/// NOTE: from-scratch, not upstream libsignal. Not independently audited.
final class RatchetSession {

    struct Header: Codable {
        let dhPublicKey: Data
        let previousChainLength: Int
        let messageNumber: Int
    }

    struct Envelope: Codable {
        let header: Header
        let ciphertext: Data
    }

    private var rootKey: SymmetricKey
    private var dhSelf: Curve25519.KeyAgreement.PrivateKey
    private var dhRemote: Curve25519.KeyAgreement.PublicKey?
    private var chainKeySend: SymmetricKey?
    private var chainKeyReceive: SymmetricKey?
    private var sendCount = 0
    private var receiveCount = 0
    private var previousSendChainLength = 0
    private var skippedKeys: [String: SymmetricKey] = [:] // "dhPubKeyBase64:N" -> message key
    private let maxSkip = 1000

    /// Initiator side: has already done the DH ratchet step conceptually
    /// via X3DH, and knows the responder's current ratchet public key
    /// (their signed prekey, reused as the initial DHr).
    init(rootKey: SymmetricKey, theirRatchetPublicKey: Curve25519.KeyAgreement.PublicKey) {
        self.rootKey = rootKey
        self.dhSelf = Curve25519.KeyAgreement.PrivateKey()
        self.dhRemote = theirRatchetPublicKey
        let shared = try? dhSelf.sharedSecretFromKeyAgreement(with: theirRatchetPublicKey)
        if let shared {
            let (rk, ck) = Self.kdfRootKey(rootKey: rootKey, dhOutput: shared)
            self.rootKey = rk
            self.chainKeySend = ck
        }
    }

    /// Responder side: starts with no send chain until the first message
    /// arrives and triggers a DH ratchet step.
    init(rootKey: SymmetricKey, myRatchetKeyPair: Curve25519.KeyAgreement.PrivateKey) {
        self.rootKey = rootKey
        self.dhSelf = myRatchetKeyPair
        self.dhRemote = nil
        self.chainKeySend = nil
        self.chainKeyReceive = nil
    }

    // MARK: - Encrypt

    func encrypt(plaintext: Data, associatedData: Data) throws -> Envelope {
        guard let ck = chainKeySend else { throw RatchetError.noSendChain }
        let (newCK, messageKey) = Self.kdfChainKey(chainKey: ck)
        chainKeySend = newCK

        let header = Header(dhPublicKey: dhSelf.publicKey.rawRepresentation,
                             previousChainLength: previousSendChainLength,
                             messageNumber: sendCount)
        sendCount += 1

        let headerData = (try? JSONEncoder().encode(header)) ?? Data()
        let sealed = try AES.GCM.seal(plaintext, using: messageKey, authenticating: associatedData + headerData)
        guard let combined = sealed.combined else { throw RatchetError.sealFailed }
        return Envelope(header: header, ciphertext: combined)
    }

    // MARK: - Decrypt

    func decrypt(envelope: Envelope, associatedData: Data) throws -> Data {
        let headerData = (try? JSONEncoder().encode(envelope.header)) ?? Data()

        // 1. Try skipped-message cache (out-of-order delivery).
        let skipKey = "\(envelope.header.dhPublicKey.base64EncodedString()):\(envelope.header.messageNumber)"
        if let mk = skippedKeys[skipKey] {
            skippedKeys.removeValue(forKey: skipKey)
            let box = try AES.GCM.SealedBox(combined: envelope.ciphertext)
            return try AES.GCM.open(box, using: mk, authenticating: associatedData + headerData)
        }

        let incomingDH = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: envelope.header.dhPublicKey)

        // 2. New DH ratchet step if the sender rotated their ratchet key.
        if dhRemote == nil || incomingDH.rawRepresentation != dhRemote!.rawRepresentation {
            try skipMessageKeys(until: envelope.header.previousChainLength)
            try dhRatchetStep(newRemotePublicKey: incomingDH)
        }

        try skipMessageKeys(until: envelope.header.messageNumber)

        guard let ck = chainKeyReceive else { throw RatchetError.noReceiveChain }
        let (newCK, messageKey) = Self.kdfChainKey(chainKey: ck)
        chainKeyReceive = newCK
        receiveCount += 1

        let box = try AES.GCM.SealedBox(combined: envelope.ciphertext)
        return try AES.GCM.open(box, using: messageKey, authenticating: associatedData + headerData)
    }

    private func skipMessageKeys(until: Int) throws {
        guard let ck = chainKeyReceive else { return }
        guard until - receiveCount <= maxSkip else { throw RatchetError.tooManySkipped }
        var chainKey = ck
        while receiveCount < until {
            let (newCK, mk) = Self.kdfChainKey(chainKey: chainKey)
            chainKey = newCK
            if let dhRemote {
                let key = "\(dhRemote.rawRepresentation.base64EncodedString()):\(receiveCount)"
                skippedKeys[key] = mk
            }
            receiveCount += 1
        }
        chainKeyReceive = chainKey
    }

    private func dhRatchetStep(newRemotePublicKey: Curve25519.KeyAgreement.PublicKey) throws {
        previousSendChainLength = sendCount
        sendCount = 0
        receiveCount = 0
        dhRemote = newRemotePublicKey

        let sharedRecv = try dhSelf.sharedSecretFromKeyAgreement(with: newRemotePublicKey)
        let (rk1, ckRecv) = Self.kdfRootKey(rootKey: rootKey, dhOutput: sharedRecv)
        rootKey = rk1
        chainKeyReceive = ckRecv

        dhSelf = Curve25519.KeyAgreement.PrivateKey()
        let sharedSend = try dhSelf.sharedSecretFromKeyAgreement(with: newRemotePublicKey)
        let (rk2, ckSend) = Self.kdfRootKey(rootKey: rootKey, dhOutput: sharedSend)
        rootKey = rk2
        chainKeySend = ckSend
    }

    // MARK: - KDFs

    private static func kdfRootKey(rootKey: SymmetricKey, dhOutput: SharedSecret) -> (SymmetricKey, SymmetricKey) {
        let ikm = dhOutput.withUnsafeBytes { Data($0) }
        let outputData = RatchetPrimitives.hkdf(
            ikm: SymmetricKey(data: ikm),
            salt: rootKey.withUnsafeBytes { Data($0) },
            info: Data("GhostMesh-DHRatchet".utf8),
            outputByteCount: 64
        )
        let newRoot = SymmetricKey(data: outputData.prefix(32))
        let newChain = SymmetricKey(data: outputData.suffix(32))
        return (newRoot, newChain)
    }

    private static func kdfChainKey(chainKey: SymmetricKey) -> (SymmetricKey, SymmetricKey) {
        let (next, messageKey) = RatchetPrimitives.kdfChainKey(chainKey)
        return (next, messageKey)
    }

    enum RatchetError: Error { case noSendChain, noReceiveChain, sealFailed, tooManySkipped }
}
