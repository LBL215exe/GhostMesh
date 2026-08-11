import Foundation
import CryptoKit

/// A device's long-term identity: a Curve25519 signing + agreement keypair.
/// There is no account, phone number, or server registration — the public
/// key fingerprint *is* the identity, exchanged out-of-band via QR.
struct Identity {
    let signingKey: Curve25519.Signing.PrivateKey
    let agreementKey: Curve25519.KeyAgreement.PrivateKey

    /// Medium-term "signed prekey" used for X3DH-style handshakes so a new
    /// session can be started even if the other party is offline at pairing
    /// time (the prekey is published in the QR payload alongside the
    /// identity key, signed by the identity key).
    let signedPrekey: Curve25519.KeyAgreement.PrivateKey
    let signedPrekeySignature: Data

    var publicSigningKey: Curve25519.Signing.PublicKey { signingKey.publicKey }
    var publicAgreementKey: Curve25519.KeyAgreement.PublicKey { agreementKey.publicKey }
    var publicSignedPrekey: Curve25519.KeyAgreement.PublicKey { signedPrekey.publicKey }

    /// Human-shareable fingerprint, e.g. shown under a QR code so two people
    /// can verbally confirm they scanned the right code (a "safety number").
    /// Spaced, human-readable form for display/safety-number confirmation.
    var fingerprint: String {
        let digest = SHA256.hash(data: publicSigningKey.rawRepresentation)
        return digest.map { String(format: "%02x", $0) }.joined()
            .enumerated()
            .reduce(into: "") { acc, pair in
                acc += String(pair.element)
                if pair.offset % 4 == 3 && pair.offset != 63 { acc += " " }
            }
    }

    /// Unspaced full-hex form used for machine matching (mesh peer display
    /// names, Contact.id) — must stay byte-identical to how Contact.id is
    /// derived from a scanned PairingBundle.
    var rawFingerprint: String {
        SHA256.hash(data: publicSigningKey.rawRepresentation).map { String(format: "%02x", $0) }.joined()
    }

    static func generate() -> Identity {
        let signing = Curve25519.Signing.PrivateKey()
        let agreement = Curve25519.KeyAgreement.PrivateKey()
        let prekey = Curve25519.KeyAgreement.PrivateKey()
        let signature = (try? signing.signature(for: prekey.publicKey.rawRepresentation)) ?? Data()
        return Identity(signingKey: signing, agreementKey: agreement,
                         signedPrekey: prekey, signedPrekeySignature: signature)
    }

    /// The payload embedded in the pairing QR code.
    func exportBundle() -> PairingBundle {
        PairingBundle(
            identityKey: publicSigningKey.rawRepresentation,
            agreementKey: publicAgreementKey.rawRepresentation,
            signedPrekey: publicSignedPrekey.rawRepresentation,
            signedPrekeySignature: signedPrekeySignature,
            onionAddress: nil // filled in once Tor has bootstrapped and hosts a service
        )
    }
}

/// What's encoded into (and scanned from) a pairing QR code.
struct PairingBundle: Codable {
    let identityKey: Data
    let agreementKey: Data
    let signedPrekey: Data
    let signedPrekeySignature: Data
    var onionAddress: String?

    func verify() -> Bool {
        guard let idKey = try? Curve25519.Signing.PublicKey(rawRepresentation: identityKey) else { return false }
        return idKey.isValidSignature(signedPrekeySignature, for: signedPrekey)
    }

    func base64URL() throws -> String {
        let data = try JSONEncoder().encode(self)
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
    }

    static func from(base64URL: String) throws -> PairingBundle {
        var s = base64URL.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        guard let data = Data(base64Encoded: s) else {
            throw NSError(domain: "PairingBundle", code: 1)
        }
        return try JSONDecoder().decode(PairingBundle.self, from: data)
    }
}
