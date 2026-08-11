import Foundation
import CryptoKit

/// KDF building blocks shared by the text Double Ratchet (DoubleRatchet.swift)
/// and the per-call ratchet (CallSession.swift), so both derive keys the
/// same, reviewed way instead of two copies of similar-looking crypto code.
enum RatchetPrimitives {

    /// One step of a symmetric-key ratchet: given the current chain key,
    /// returns the next chain key and a one-time message/frame key. The
    /// chain key is discarded immediately by the caller — that's what makes
    /// each step forward-secret.
    static func kdfChainKey(_ chainKey: SymmetricKey) -> (next: SymmetricKey, messageKey: SymmetricKey) {
        let ckData = chainKey.withUnsafeBytes { Data($0) }
        let nextMAC = HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: SymmetricKey(data: ckData))
        let msgMAC = HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: SymmetricKey(data: ckData))
        return (SymmetricKey(data: Data(nextMAC)), SymmetricKey(data: Data(msgMAC)))
    }

    /// General-purpose HKDF-SHA256 derive, used for the root-key step after
    /// a Diffie-Hellman exchange (text ratchet DH step, or call setup DH).
    static func hkdf(ikm: SymmetricKey, salt: Data, info: Data, outputByteCount: Int) -> Data {
        let output = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: info, outputByteCount: outputByteCount)
        return output.withUnsafeBytes { Data($0) }
    }
}
