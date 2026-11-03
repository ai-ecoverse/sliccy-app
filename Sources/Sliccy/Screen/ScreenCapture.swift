import Foundation
@preconcurrency import ScreenCaptureKit
import ImageIO
import UniformTypeIdentifiers

/// One encoder and one replaceable pending sample. No image is written to disk.
/// Production start stays gated on reviewed scope and native identity evidence.
final class ScreenCapture: NSObject, SCStreamOutput, SCStreamDelegate, @unchecked Sendable {
    struct Image: Sendable { let jpeg: Data; let width: Int; let height: Int; let captured: ContinuousClock.Instant; let monoMs: String }
    private struct Sample { let buffer: CVPixelBuffer; let captured: ContinuousClock.Instant; let monoMs: String }
    private let lock = NSLock()
    private var stream: SCStream?
    private var stopTask: Task<Bool, Never>?
    private var pending: Sample?
    private var encoding = false
    private var stopped = false
    private let encoder = DispatchQueue(label: "ai.sliccy.screen.encode", qos: .userInitiated)
    private let samples = DispatchQueue(label: "ai.sliccy.screen.samples", qos: .userInitiated)
    private let gate: ScreenOutputGate
    private let binding: ScreenBinding
    private let protection: @Sendable () -> Bool
    private let output: @Sendable (Image) throws -> Void
    private let failure: @Sendable (ScreenFailure) -> Void

    init(gate: ScreenOutputGate, binding: ScreenBinding, protection: @escaping @Sendable () -> Bool,
         output: @escaping @Sendable (Image) throws -> Void, failure: @escaping @Sendable (ScreenFailure) -> Void) {
        self.gate = gate; self.binding = binding; self.protection = protection; self.output = output; self.failure = failure
    }
    @MainActor func start(filter: SCContentFilter, scope: String, width: Int, height: Int) async throws {
        guard ScreenReleasePolicy.identityProofApproved, ScreenReleasePolicy.provenScopes.contains(scope),
              protection(), gate.allows(binding), CGPreflightScreenCaptureAccess() else { throw ScreenFailure.protection }
        try await startStream(filter: filter, width: width, height: height)
    }
#if SLICCY_CAPTURE_RUNNER_PROOF
    @MainActor func startProof(source: ScreenRunnerCaptureSource) async throws {
        _ = try ScreenRunnerHost.require()
        guard protection(), gate.allows(binding), CGPreflightScreenCaptureAccess() else { throw ScreenFailure.protection }
        try await startStream(filter: source.filter, width: source.width, height: source.height)
    }
#endif
    @MainActor private func startStream(filter: SCContentFilter, width: Int, height: Int) async throws {
        let capture = SCStream(filter: filter, configuration: try ScreenFilterBuilder.configuration(width: width, height: height), delegate: self)
        try capture.addStreamOutput(self, type: .screen, sampleHandlerQueue: samples)
        try setStream(capture)
        do { try await capture.startCapture() }
        catch { stop(.sourceChanged); throw error }
        guard isAllowed else { stop(.stopped); throw ScreenFailure.stopped }
    }
    private func setStream(_ value: SCStream) throws {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, stream == nil else { throw ScreenFailure.stopped }
        stream = value
    }
    private var isAllowed: Bool {
        guard gate.allows(binding), protection() else { return false }
        lock.lock(); defer { lock.unlock() }; return !stopped
    }
    func stop(_ reason: ScreenFailure = .stopped) {
        gate.invalidate()
        lock.lock()
        let notify = !stopped; stopped = true; pending = nil
        let capture = stream; stream = nil
        if let capture { stopTask = Task { do { try await capture.stopCapture(); return true } catch { return false } } }
        lock.unlock()
        if notify { failure(reason) }
    }
#if SLICCY_CAPTURE_RUNNER_PROOF
    func proofAwaitStopped() async -> Bool {
        await stopJob()?.value ?? false
    }
    private func stopJob() -> Task<Bool, Never>? {
        lock.lock(); defer { lock.unlock() }; return stopTask
    }
#endif
    func stream(_ stream: SCStream, didStopWithError error: any Error) { stop(.sourceChanged) }
    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen, isAllowed, sampleBuffer.isValid,
              let info = (CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]])?.first,
              let raw = info[.status] as? Int, let status = SCFrameStatus(rawValue: raw) else { return }
        if status == .idle || status == .started { return }
        guard status == .complete else { stop(.sourceChanged); return }
        guard let tick = info[.displayTime] as? UInt64, tick <= mach_absolute_time(),
              let buffer = sampleBuffer.imageBuffer else { stop(.sourceChanged); return }
        var timebase = mach_timebase_info_data_t()
        guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom != 0 else { stop(.stalled); return }
        let multiplier = Double(timebase.numer) / Double(timebase.denom)
        let age = Double(mach_absolute_time() - tick) * multiplier / 1e9
        guard age <= 0.5 else { return }
        let sample = Sample(buffer: buffer, captured: .now.advanced(by: .nanoseconds(-Int64(age * 1e9))),
                            monoMs: String(UInt64(Double(tick) * multiplier / 1e6)))
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        pending = sample
        let start = !encoding; encoding = true
        lock.unlock()
        if start { encoder.async { [self] in encodePending() } }
    }
    private func take() -> Sample? {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, let sample = pending else { encoding = false; return nil }
        pending = nil; return sample
    }
    private func encodePending() {
        while let sample = take() {
            guard isAllowed, sample.captured.duration(to: .now) <= .milliseconds(500) else { continue }
            do {
                let jpeg = try autoreleasepool { try ScreenJPEG.encode(sample.buffer) }
                guard isAllowed, sample.captured.duration(to: .now) <= .milliseconds(500) else { continue }
                try output(.init(jpeg: jpeg, width: CVPixelBufferGetWidth(sample.buffer), height: CVPixelBufferGetHeight(sample.buffer),
                                 captured: sample.captured, monoMs: sample.monoMs))
            } catch { stop(error as? ScreenFailure ?? .resourceLimit); return }
        }
    }
}

enum ScreenJPEG {
    private final class Sink {
        var bytes = Data()
        var exceeded = false
        func append(_ pointer: UnsafeRawPointer, count: Int) -> Int {
            guard count <= 2_097_152 - bytes.count else { exceeded = true; return 0 }
            bytes.append(pointer.assumingMemoryBound(to: UInt8.self), count: count); return count
        }
    }
    static func encode(_ buffer: CVPixelBuffer) throws -> Data {
        let width = CVPixelBufferGetWidth(buffer), height = CVPixelBufferGetHeight(buffer)
        let row = CVPixelBufferGetBytesPerRow(buffer)
        guard width > 0, height > 0, max(width, height) <= 2560, width <= 4_000_000 / height,
              row >= width * 4, row <= 16_000_000 / height,
              CVPixelBufferGetPixelFormatType(buffer) == kCVPixelFormatType_32BGRA,
              CVPixelBufferLockBaseAddress(buffer, .readOnly) == kCVReturnSuccess else { throw ScreenFailure.resourceLimit }
        defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
        guard let pixels = CVPixelBufferGetBaseAddress(buffer),
              let provider = CGDataProvider(dataInfo: nil, data: pixels, size: row * height, releaseData: { _, _, _ in }),
              let color = CGColorSpace(name: CGColorSpace.sRGB),
              let image = CGImage(width: width, height: height, bitsPerComponent: 8, bitsPerPixel: 32, bytesPerRow: row,
                space: color, bitmapInfo: CGBitmapInfo.byteOrder32Little.union(.init(rawValue: CGImageAlphaInfo.noneSkipFirst.rawValue)),
                provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent) else { throw ScreenFailure.resourceLimit }
        let sink = Sink()
        var callbacks = CGDataConsumerCallbacks(putBytes: { info, bytes, count in
            guard let info else { return 0 }
            return Unmanaged<Sink>.fromOpaque(info).takeUnretainedValue().append(bytes, count: count)
        }, releaseConsumer: nil)
        guard let consumer = CGDataConsumer(info: Unmanaged.passUnretained(sink).toOpaque(), cbks: &callbacks),
              let destination = CGImageDestinationCreateWithDataConsumer(consumer, UTType.jpeg.identifier as CFString, 1, nil) else { throw ScreenFailure.resourceLimit }
        CGImageDestinationAddImage(destination, image, [kCGImageDestinationLossyCompressionQuality: 0.65] as CFDictionary)
        guard CGImageDestinationFinalize(destination), !sink.exceeded else { throw ScreenFailure.resourceLimit }
        // A newly constructed CGImage has no source metadata. Remove APP/COM
        // segments as well, including ImageIO-added profiles, before transmission.
        return try withoutMetadata(sink.bytes)
    }
    static func withoutMetadata(_ data: Data) throws -> Data {
        guard data.count >= 4, data[0] == 0xff, data[1] == 0xd8 else { throw ScreenFailure.incompatible }
        var result = Data([0xff, 0xd8]), offset = 2
        while offset + 1 < data.count {
            guard data[offset] == 0xff else { throw ScreenFailure.incompatible }
            let marker = data[offset + 1]
            if marker == 0xda { result.append(data[offset...]); return result }
            guard marker != 0xd9, offset + 3 < data.count else { throw ScreenFailure.incompatible }
            let length = Int(data[offset + 2]) * 256 + Int(data[offset + 3])
            guard length >= 2, offset + 2 + length <= data.count else { throw ScreenFailure.incompatible }
            if !(0xe0...0xef).contains(marker) && marker != 0xfe { result.append(data[offset..<offset + 2 + length]) }
            offset += 2 + length
        }
        throw ScreenFailure.incompatible
    }
}
