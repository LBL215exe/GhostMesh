import Foundation
import CryptoKit

final class Contact: Identifiable, ObservableObject {
    let id: String // fingerprint of their identity key
    let displayName: String
    let bundle: PairingBundle
    @Published var onionAddress: String?
    @Published var lastSeenViaMesh: Date?
    @Published var isOnlineMesh = false

    var session: RatchetSession?

    init(displayName: String, bundle: PairingBundle) {
        let digest = SHA256.hash(data: bundle.identityKey)
        self.id = digest.map { String(format: "%02x", $0) }.joined()
        self.displayName = displayName
        self.bundle = bundle
        self.onionAddress = bundle.onionAddress
    }
}
