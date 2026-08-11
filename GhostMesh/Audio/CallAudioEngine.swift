import Foundation
import AVFoundation

/// Captures the mic as small raw-PCM frames for encryption+send, and plays
/// back decrypted frames through a small fixed-depth jitter buffer.
///
/// Deliberately uses uncompressed 16kHz mono 16-bit PCM rather than a
/// speech codec (Opus etc.) to avoid taking on a second unverified
/// third-party dependency in the same project as Tor/ggwave. That's a
/// bandwidth/quality trade-off: ~32kbps per direction, fine for mesh, a bit
/// heavy but workable for Tor. Swapping in Opus later is a drop-in change
/// at the frame-encode/decode boundary — everything else (crypto, jitter
/// buffer, transport) is codec-agnostic.
final class CallAudioEngine {

    static let sampleRate: Double = 16000
    static let frameDurationMs = 20
    static let samplesPerFrame = Int(sampleRate) * frameDurationMs / 1000 // 320
    static let bytesPerFrame = samplesPerFrame * 2 // Int16 mono

    private let engine = AVAudioEngine()
    private var playerNode: AVAudioPlayerNode?
    private var micConverter: AVAudioConverter?
    private var playbackFormat: AVAudioFormat?

    /// Called on a background queue with one 640-byte raw PCM frame roughly
    /// every 20ms while the call is active.
    var onCapturedFrame: ((Data) -> Void)?

    private var jitterBuffer: [UInt32: Data] = [:]
    private var jitterLock = NSLock()
    private var nextPlaySequence: UInt32 = 0
    private let jitterTargetDepth = 3 // ~60ms of buffering before playback starts

    private(set) var isRunning = false

    func start() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.defaultToSpeaker, .allowBluetooth])
        try session.setActive(true)

        let input = engine.inputNode
        let inputFormat = input.outputFormat(forBus: 0)
        guard let targetFormat = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: Self.sampleRate, channels: 1, interleaved: true) else {
            throw NSError(domain: "CallAudioEngine", code: 1)
        }
        micConverter = AVAudioConverter(from: inputFormat, to: targetFormat)

        input.removeTap(onBus: 0)
        var accumulated = Data()
        input.installTap(onBus: 0, bufferSize: 1024, format: inputFormat) { [weak self] buffer, _ in
            guard let self, let converter = self.micConverter else { return }
            let ratio = targetFormat.sampleRate / inputFormat.sampleRate
            let outCapacity = AVAudioFrameCount(Double(buffer.frameLength) * ratio) + 16
            guard let outBuffer = AVAudioPCMBuffer(pcmFormat: targetFormat, frameCapacity: outCapacity) else { return }
            var consumed = false
            var convError: NSError?
            converter.convert(to: outBuffer, error: &convError) { _, status in
                if consumed { status.pointee = .noDataNow; return nil }
                consumed = true
                status.pointee = .haveData
                return buffer
            }
            guard convError == nil, let ch = outBuffer.int16ChannelData else { return }
            let count = Int(outBuffer.frameLength) * 2
            let bytes = Data(bytes: ch[0], count: count)
            accumulated.append(bytes)
            while accumulated.count >= Self.bytesPerFrame {
                let frame = accumulated.prefix(Self.bytesPerFrame)
                accumulated.removeFirst(Self.bytesPerFrame)
                self.onCapturedFrame?(Data(frame))
            }
        }

        guard let playFormat = AVAudioFormat(commonFormat: .pcmFormatInt16, sampleRate: Self.sampleRate, channels: 1, interleaved: true) else {
            throw NSError(domain: "CallAudioEngine", code: 2)
        }
        playbackFormat = playFormat
        let player = AVAudioPlayerNode()
        engine.attach(player)
        engine.connect(player, to: engine.mainMixerNode, format: playFormat)
        playerNode = player

        engine.prepare()
        try engine.start()
        player.play()
        isRunning = true
        startJitterDrain()
    }

    func stop() {
        engine.inputNode.removeTap(onBus: 0)
        playerNode?.stop()
        engine.stop()
        isRunning = false
        jitterLock.lock()
        jitterBuffer.removeAll()
        jitterLock.unlock()
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
    }

    /// Feed a decrypted, decoded PCM frame (with its original sequence
    /// number) in for playback; may arrive out of order.
    func enqueueForPlayback(sequence: UInt32, pcm: Data) {
        jitterLock.lock()
        jitterBuffer[sequence] = pcm
        jitterLock.unlock()
    }

    private func startJitterDrain() {
        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            while let self, self.isRunning {
                self.drainOneFrame()
                Thread.sleep(forTimeInterval: Double(Self.frameDurationMs) / 1000.0)
            }
        }
    }

    private func drainOneFrame() {
        jitterLock.lock()
        let haveEnoughBuffered = jitterBuffer.count >= jitterTargetDepth || jitterBuffer[nextPlaySequence] != nil
        let frame = jitterBuffer.removeValue(forKey: nextPlaySequence)
        jitterLock.unlock()

        guard haveEnoughBuffered else { return } // still filling initial buffer
        nextPlaySequence += 1

        guard let frame, let format = playbackFormat, let player = playerNode else { return } // dropped/late frame: skip, don't stall

        let frameCount = AVAudioFrameCount(frame.count / 2)
        guard let buffer = AVAudioPCMBuffer(pcmFormat: format, frameCapacity: frameCount) else { return }
        buffer.frameLength = frameCount
        if let ch = buffer.int16ChannelData {
            frame.withUnsafeBytes { raw in
                if let base = raw.bindMemory(to: Int16.self).baseAddress {
                    ch[0].update(from: base, count: Int(frameCount))
                }
            }
        }
        player.scheduleBuffer(buffer)
    }
}
