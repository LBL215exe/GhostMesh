import Foundation

enum DeliveryPath: String, Codable {
    case mesh = "MESH"
    case tor = "TOR"
    case pending = "PENDING"
    case system = "SYSTEM"
}

struct ChatMessage: Identifiable, Equatable {
    let id = UUID()
    let contactID: String
    let text: String
    let outgoing: Bool
    let path: DeliveryPath
    let timestamp: Date

    static func == (lhs: ChatMessage, rhs: ChatMessage) -> Bool { lhs.id == rhs.id }
}

/// Wire format for a message once encrypted, before it's handed to a
/// transport. This — and only this — is what ever leaves the device or
/// touches a relay peer's memory.
struct WireMessage: Codable {
    let id: UUID
    let senderFingerprint: String
    let envelope: RatchetSession.Envelope
    var ttl: Int // mesh flood hop budget
}
