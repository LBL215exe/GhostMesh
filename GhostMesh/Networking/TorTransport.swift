import Foundation
import Network
import Tor

/// Wraps `swift-tor` (github.com/21-DOT-DEV/swift-tor): boots an in-process
/// Tor instance, exposes its SOCKS5 port for outbound connections to peers'
/// .onion addresses, and publishes this device's own v3 onion service as
/// its inbox — so receiving a message never depends on any server, only on
/// this device's own Tor circuit.
///
/// IMPORTANT: swift-tor is explicitly pre-1.0 with an unstable API (see its
/// README). The exact accessor used below to reach the control-protocol
/// client (`client.control`) is the one part of this file most likely to
/// need a small adjustment to match whatever version you add to the
/// project — check autocomplete on `TorClient` if this doesn't compile.
actor TorTransport {

    private(set) var client: TorClient?
    private(set) var socksPort: UInt16 = 0
    private(set) var onionAddress: String?
    private var inboxListener: NWListener?
    private var localInboxPort: UInt16 = 0

    /// Wire framing on the raw TCP connection an onion service forwards to:
    /// the first byte a new inbound connection sends says what it's for.
    /// (Shares byte values with FramedTransport.RawTag by construction.)
    private var onInboxMessage: ((WireMessage) -> Void)?
    private var onCallFrame: ((CallFrame) -> Void)?
    private var activeCallConnections: [UUID: NWConnection] = [:]

    func setInboxHandler(_ handler: @escaping (WireMessage) -> Void) {
        onInboxMessage = handler
    }

    func setCallFrameHandler(_ handler: @escaping (CallFrame) -> Void) {
        onCallFrame = handler
    }

    func start() async throws {
        let dataDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("tor-data-\(UUID().uuidString)").path
        let cacheDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ghostmesh-tor-cache").path
        try? FileManager.default.createDirectory(atPath: cacheDir, withIntermediateDirectories: true)

        let config = TorConfiguration(
            dataDirectory: dataDir,
            cacheDirectory: cacheDir,
            socksPort: .ephemeral
        )
        let client = TorClient(configuration: config)
        try await client.start()
        try await client.waitUntilBootstrapped()
        self.client = client

        let endpoint = await client.socksEndpoint
        self.socksPort = UInt16(endpoint.port ?? 0)
    }

    /// Publishes an ephemeral v3 onion service that forwards to a local TCP
    /// listener we own, and starts accepting inbound framed WireMessages on
    /// it. `privateKey`, if supplied, restores a previously-created address
    /// instead of generating a new one each launch (kept in Keychain by the
    /// caller — never on a server).
    func publishInbox(existingPrivateKey: String? = nil) async throws -> String {
        guard let client else { throw TorTransportError.notStarted }
        localInboxPort = UInt16.random(in: 40000...60000)

        let key: OnionServiceKey = existingPrivateKey.map { .providedV3($0) } ?? .newV3(discardPrivateKey: false)
        let service = try await client.control().addOnion(
           key: key,
           ports: [.toLocalPort(8443, localPort: Int(localInboxPort))]
        )
        onionAddress = service.onionAddress
        startInboxListener(on: localInboxPort)
        return service.onionAddress
    }

    /// Sends one WireMessage to a contact's onion address over a fresh
    /// circuit. Fire-and-forget from the caller's perspective; failures
    /// propagate so the router can decide to retry later.
    func send(_ message: WireMessage, toOnion onion: String, port: UInt16 = 8443) async throws {
        guard socksPort != 0 else { throw TorTransportError.notStarted }
        let connection = try await SOCKS5Client.connect(socksPort: socksPort, targetHost: onion, targetPort: port)
        defer { connection.cancel() }
        try await FramedTransport.sendTagged(.oneShotMessage, message, on: connection)
    }

    /// Opens (and keeps open) a persistent connection to a contact's onion
    /// address for the duration of a call, tagged so the receiving side's
    /// listener treats it as a call stream rather than a one-shot message.
    /// Real-time audio over Tor inherits Tor's latency (typically several
    /// hundred ms to a couple seconds) — usable, not snappy.
    func openCallStream(callID: UUID, toOnion onion: String, port: UInt16 = 8443) async throws {
        guard socksPort != 0 else { throw TorTransportError.notStarted }
        let connection = try await SOCKS5Client.connect(socksPort: socksPort, targetHost: onion, targetPort: port)
        try await FramedTransport.sendRawTag(.callStream, on: connection)
        activeCallConnections[callID] = connection
        listenForCallFrames(on: connection)
    }

    func sendCallFrame(_ frame: CallFrame, callID: UUID) async throws {
        guard let connection = activeCallConnections[callID] else { throw TorTransportError.noCallStream }
        try await FramedTransport.send(frame, on: connection)
    }

    func closeCallStream(callID: UUID) {
        activeCallConnections[callID]?.cancel()
        activeCallConnections.removeValue(forKey: callID)
    }

    private func listenForCallFrames(on connection: NWConnection) {
        Task {
            while true {
                guard let frame = try? await FramedTransport.receive(CallFrame.self, on: connection) else { break }
                onCallFrame?(frame)
            }
        }
    }

    private func startInboxListener(on port: UInt16) {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return }
        let params = NWParameters.tcp
        guard let listener = try? NWListener(using: params, on: nwPort) else { return }
        listener.newConnectionHandler = { [weak self] connection in
            connection.start(queue: .global(qos: .userInitiated))
            Task { [weak self] in
                guard let self else { return }
                guard let tagByte = try? await FramedTransport.receiveRawTag(on: connection),
                      let kind = FramedTransport.RawTag(rawValue: tagByte) else {
                    connection.cancel()
                    return
                }
                switch kind {
                case .oneShotMessage:
                    if let message = try? await FramedTransport.receive(WireMessage.self, on: connection) {
                        await self.deliverInbound(message)
                    }
                    connection.cancel()
                case .callStream:
                    if let first = try? await FramedTransport.receive(CallFrame.self, on: connection) {
                        await self.registerInboundCallStream(callID: first.callID, connection: connection)
                        await self.deliverCallFrame(first)
                        await self.listenForCallFramesActor(on: connection)
                    }
                }
            }
        }
        listener.start(queue: .global(qos: .utility))
        inboxListener = listener
    }

    private func registerInboundCallStream(callID: UUID, connection: NWConnection) {
        activeCallConnections[callID] = connection
    }

    private func listenForCallFramesActor(on connection: NWConnection) async {
        while true {
            guard let frame = try? await FramedTransport.receive(CallFrame.self, on: connection) else { break }
            deliverCallFrame(frame)
        }
    }

    private func deliverInbound(_ message: WireMessage) {
        onInboxMessage?(message)
    }

    private func deliverCallFrame(_ frame: CallFrame) {
        onCallFrame?(frame)
    }

    enum TorTransportError: Error { case notStarted, noCallStream }
}
