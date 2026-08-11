import Foundation
import CryptoKit

/// A simplified X3DH ("Extended Triple Diffie-Hellman") handshake, in the
/// spirit of the Signal protocol, used once per new contact to derive the
/// shared secret that seeds that contact's Double Ratchet session.
///
/// NOTE: this is a from-scratch educational implementation, not the
/// upstream libsignal library. It has not been independently audited.
/// For a threat model where your safety genuinely depends on this, get it
/// reviewed by a cryptographer before relying on it.
enum X3DH {

    /// Run by the party who initiates contact (the one who scans the QR /
    /// receives the other party's PairingBundle first).
    static func initiate(myIdentity: Identity, theirBundle: PairingBundle) throws -> (rootKey: SymmetricKey, ephemeralPublic: Data) {
        guard theirBundle.verify() else {
            throw X3DHError.invalidSignature
        }
        let theirIdentityAgreement = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirBundle.agreementKey)
        let theirSignedPrekey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirBundle.signedPrekey)

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()

        // DH1 = IK_A x SPK_B, DH2 = EK_A x IK_B, DH3 = EK_A x SPK_B
        let dh1 = try myIdentity.agreementKey.sharedSecretFromKeyAgreement(with: theirSignedPrekey)
        let dh2 = try ephemeral.sharedSecretFromKeyAgreement(with: theirIdentityAgreement)
        let dh3 = try ephemeral.sharedSecretFromKeyAgreement(with: theirSignedPrekey)

        let rootKey = deriveRootKey(dh1: dh1, dh2: dh2, dh3: dh3)
        return (rootKey, ephemeral.publicKey.rawRepresentation)
    }

    /// Run by the responding party once they receive the initiator's
    /// ephemeral public key (carried in the first message).
    static func respond(myIdentity: Identity, theirIdentityAgreementKeyRaw: Data, theirEphemeralRaw: Data) throws -> SymmetricKey {
        let theirIdentityAgreement = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirIdentityAgreementKeyRaw)
        let theirEphemeral = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirEphemeralRaw)

        let dh1 = try myIdentity.signedPrekey.sharedSecretFromKeyAgreement(with: theirIdentityAgreement)
        let dh2 = try myIdentity.agreementKey.sharedSecretFromKeyAgreement(with: theirEphemeral)
        let dh3 = try myIdentity.signedPrekey.sharedSecretFromKeyAgreement(with: theirEphemeral)

        return deriveRootKey(dh1: dh1, dh2: dh2, dh3: dh3)
    }

    private static func deriveRootKey(dh1: SharedSecret, dh2: SharedSecret, dh3: SharedSecret) -> SymmetricKey {
        var combined = Data()
        combined.append(dh1.withUnsafeBytes { Data($0) })
        combined.append(dh2.withUnsafeBytes { Data($0) })
        combined.append(dh3.withUnsafeBytes { Data($0) })
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: combined),
            salt: Data("GhostMesh-X3DH-v1".utf8),
            info: Data("RootKey".utf8),
            outputByteCount: 32
        )
    }

    enum X3DHError: Error { case invalidSignature }
}
