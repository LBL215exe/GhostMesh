import Foundation

/// What actually goes inside a text-ratchet-encrypted envelope. Ordinary
/// chat messages and call signaling (offer/answer/end) both travel through
/// the same authenticated channel — call setup can't be spoofed by a
/// network attacker even though the call's audio itself may move over a
/// separate connection.
struct PlaintextPayload: Codable {
    enum Kind: String, Codable { case chat, callOffer, callAnswer, callEnd }

    let kind: Kind
    var text: String?
    var callID: UUID?
    var ephemeralPublicKey: Data?
}

enum CallState: Equatable {
    case idle
    case outgoingRinging(callID: UUID)
    case incomingRinging(callID: UUID)
    case connected(callID: UUID)
}
