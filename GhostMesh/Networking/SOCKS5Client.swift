import Foundation
import Network

/// A minimal SOCKS5 client (RFC 1928) supporting only the "no
/// authentication" method and CONNECT-by-domain-name — exactly what's
/// needed to ask the local Tor SOCKS proxy to open a circuit to a peer's
/// .onion address. Not a general-purpose SOCKS implementation.
final class SOCKS5Client {

    enum SOCKSError: Error { case unexpectedResponse, connectionFailed }

    /// Opens a connection to `host:port` (a .onion address and the port the
    /// remote peer's hidden service is listening on) via the SOCKS5 proxy
    /// at `socksHost:socksPort` (Tor's local SOCKS port). Returns a raw
    /// NWConnection ready for framed read/write once the SOCKS handshake
    /// completes.
    static func connect(
        socksHost: String = "127.0.0.1",
        socksPort: UInt16,
        targetHost: String,
        targetPort: UInt16
    ) async throws -> NWConnection {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(socksHost),
            port: NWEndpoint.Port(rawValue: socksPort)!
        )
        let connection = NWConnection(to: endpoint, using: .tcp)

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: cont.resume()
                case .failed(let err): cont.resume(throwing: err)
                default: break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
        }

        // Greeting: version 5, 1 auth method, method 0x00 (no auth).
        try await send(connection, Data([0x05, 0x01, 0x00]))
        let greetingReply = try await receive(connection, count: 2)
        guard greetingReply.count == 2, greetingReply[0] == 0x05, greetingReply[1] == 0x00 else {
            throw SOCKSError.unexpectedResponse
        }

        // CONNECT request, address type 0x03 = domain name.
        var request = Data([0x05, 0x01, 0x00, 0x03])
        let hostBytes = Array(targetHost.utf8)
        request.append(UInt8(hostBytes.count))
        request.append(contentsOf: hostBytes)
        request.append(UInt8(targetPort >> 8))
        request.append(UInt8(targetPort & 0xFF))
        try await send(connection, request)

        // Reply: VER REP RSV ATYP [addr] [port]. Read the fixed 4-byte
        // header first, then the variable-length address.
        let header = try await receive(connection, count: 4)
        guard header.count == 4, header[0] == 0x05 else { throw SOCKSError.unexpectedResponse }
        guard header[1] == 0x00 else { throw SOCKSError.connectionFailed }

        let atyp = header[3]
        switch atyp {
        case 0x01: _ = try await receive(connection, count: 4 + 2)      // IPv4 + port
        case 0x03:
            let lenByte = try await receive(connection, count: 1)
            let len = Int(lenByte[0])
            _ = try await receive(connection, count: len + 2)
        case 0x04: _ = try await receive(connection, count: 16 + 2)     // IPv6 + port
        default: throw SOCKSError.unexpectedResponse
        }

        return connection
    }

    private static func send(_ connection: NWConnection, _ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    private static func receive(_ connection: NWConnection, count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error { cont.resume(throwing: error); return }
                guard let data else { cont.resume(throwing: SOCKSError.unexpectedResponse); return }
                cont.resume(returning: data)
            }
        }
    }
}

/// Sends/receives length-prefixed JSON frames over an already-established
/// NWConnection (either an outbound SOCKS5 connection, or an inbound
/// connection accepted on the local port an onion service forwards to).
enum FramedTransport {
    static func send<T: Encodable>(_ value: T, on connection: NWConnection) async throws {
        let payload = try JSONEncoder().encode(value)
        var lengthPrefixed = Data()
        var length = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &length) { lengthPrefixed.append(contentsOf: $0) }
        lengthPrefixed.append(payload)
        try await sendRaw(lengthPrefixed, on: connection)
    }

    /// Writes a single tag byte (used at the start of an outbound TorTransport
    /// connection to mark it as e.g. a call stream) with no length prefix.
    static func sendRawTag(_ tag: RawTag, on connection: NWConnection) async throws {
        try await sendRaw(Data([tag.rawValue]), on: connection)
    }

    /// Reads the single leading tag byte an inbound TorTransport connection
    /// starts with, before any length-prefixed frames follow.
    static func receiveRawTag(on connection: NWConnection) async throws -> UInt8 {
        let data = try await receiveExact(connection, count: 1)
        return data[data.startIndex]
    }

    /// Convenience used by TorTransport.send: writes the one-shot-message
    /// tag byte immediately followed by the length-prefixed WireMessage, in
    /// a single call so a one-off connection doesn't need two round trips.
    static func sendTagged<T: Encodable>(_ tag: RawTag, _ value: T, on connection: NWConnection) async throws {
        try await sendRawTag(tag, on: connection)
        try await send(value, on: connection)
    }

    enum RawTag: UInt8 { case oneShotMessage = 0x01, callStream = 0x02 }

    static func receive<T: Decodable>(_ type: T.Type, on connection: NWConnection) async throws -> T {
        let lengthData = try await receiveExact(connection, count: 4)
        let length = UInt32(bigEndian: lengthData.withUnsafeBytes { $0.load(as: UInt32.self) })
        let payload = try await receiveExact(connection, count: Int(length))
        return try JSONDecoder().decode(T.self, from: payload)
    }

    private static func sendRaw(_ data: Data, on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    private static func receiveExact(_ connection: NWConnection, count: Int) async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: count, maximumLength: count) { data, _, _, error in
                if let error { cont.resume(throwing: error); return }
                guard let data, data.count == count else {
                    cont.resume(throwing: SOCKS5Client.SOCKSError.unexpectedResponse); return
                }
                cont.resume(returning: data)
            }
        }
    }
}
