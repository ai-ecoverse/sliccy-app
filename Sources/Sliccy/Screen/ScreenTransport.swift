import Foundation
#if SLICCY_NATIVE_SCREEN_PROOF
import Darwin
#endif

/// Paired private lanes. Every callback is off the UI thread; the owner supplies a
/// current source/indicator check. Authentication and the child lifetime are owned
/// by ScreenHandshake's caller, never inferred from a supplied PID alone.
final class ScreenTransport: @unchecked Sendable {
    enum Event: Sendable {
        case ready
#if SLICCY_NATIVE_SCREEN_PROOF
        case proofControlSent(ContinuousClock.Instant)
        case proofControlEchoed(ContinuousClock.Instant)
#endif
        case revocationConfirmed
        case revokeQueued(ContinuousClock.Instant)
        case link(String, ScreenRecipient, ScreenBrowserEvidence)
        case granted(ScreenBinding)
        case stopped(ScreenFailure)
    }
    let gate = ScreenOutputGate()
    private let lock = NSLock()
    private let safety: ScreenSocket
    private let frames: ScreenSocket
    private let identity: ScreenAuditIdentity
    private let verifier: ScreenPeerVerifier
    private var state: ScreenSafetyState
    private var ended = false
    private var outbound: [ScreenSafety] = []
    private var latest: (ScreenFrameHeader, Data, ContinuousClock.Instant)?
    private var lastImage: ContinuousClock.Instant?
    private var imageBudget = ScreenRate(capacity: 2_097_152, rate: 8_388_608)
    private var inputRecords = ScreenRate(capacity: 16, rate: 16)
    private var inputBytes = ScreenRate(capacity: 65536, rate: 65536)
    private var outputRecords = ScreenRate(capacity: 16, rate: 16)
    private var outputBytes = ScreenRate(capacity: 65536, rate: 65536)
    private let outputQueue = DispatchQueue(label: "ai.sliccy.screen.safety-write", qos: .userInteractive)
    private let imageQueue = DispatchQueue(label: "ai.sliccy.screen.frames", qos: .userInitiated)
    private var imageWriting = false
    private var controlWriting = false
    private var timer: DispatchSourceTimer?
    private var nextHeartbeat = ContinuousClock.now
#if SLICCY_NATIVE_SCREEN_PROOF
    private var proofPaused = false
    private var proofControlSeq: UInt64?
    private var proofControlSentAt: ContinuousClock.Instant?
    private var proofControlEchoedAt: ContinuousClock.Instant?
#endif
    private let currentProtection: @Sendable () -> Bool
    private let noCapture: Bool
    private let event: @Sendable (Event) -> Void

    init(pair: ScreenHandshake.Pair, verifier: ScreenPeerVerifier,
         noCapture: Bool = false,
         currentProtection: @escaping @Sendable () -> Bool,
         event: @escaping @Sendable (Event) -> Void) {
        safety = pair.safety; frames = pair.frames; identity = pair.identity; self.verifier = verifier
        state = ScreenSafetyState(launch: pair.launch, connection: pair.connection, now: pair.authenticatedAt, readyDeadline: pair.readyDeadline)
        self.currentProtection = currentProtection; self.event = event
        self.noCapture = noCapture
    }
    func start() {
        // Timers are independent of the blocking safety reader and frame writer.
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "ai.sliccy.screen.health", qos: .userInteractive))
        timer.schedule(deadline: .now(), repeating: .milliseconds(50), leeway: .milliseconds(5))
        timer.setEventHandler { [weak self] in self?.tick() }
        lock.lock(); self.timer = timer; lock.unlock()
        timer.resume()
        DispatchQueue(label: "ai.sliccy.screen.safety-read", qos: .userInteractive).async { [self] in
            do {
                while true {
                    let data = try safety.readSafety()
                    _ = try verifier.verifyCLI(socket: safety.fd, expectedPID: identity.pid, expectedIdentity: identity)
                    let message = try ScreenSafety.decode(data)
                    if message.type == "revoke" { quiesceOutput() }
                    let outcome: (ScreenSafety?, Event?) = try locked {
                        guard !ended else { throw ScreenFailure.stopped }
                        try inputRecords.consume(1); try inputBytes.consume(data.count + 8)
                        let previous = state.phase
                        let wasReady = state.ready
                        let reply = try state.receive(message)
                        if message.type == "heartbeat", state.phase != .revoked { try gate.renew(until: state.healthUntil) }
                        if message.type == "link", let link = state.link, let recipient = state.recipient, let evidence = state.evidence {
                            return (reply, .link(link, recipient, evidence))
                        }
                        if previous == .pending, state.phase == .active, let binding = state.binding {
                            guard !noCapture, currentProtection() else { throw ScreenFailure.protection }
                            try gate.activate(binding)
                            return (reply, .granted(binding))
                        }
#if SLICCY_NATIVE_SCREEN_PROOF
                        if message.type == "heartbeat", let sequence = proofControlSeq,
                           proofControlSentAt != nil, proofControlEchoedAt == nil, state.echoed >= sequence {
                            let now = ContinuousClock.now
                            proofControlEchoedAt = now
                            return (reply, .proofControlEchoed(now))
                        }
#endif
                        if !wasReady, state.ready { return (reply, .ready) }
                        if message.type == "revoked" { return (reply, .revocationConfirmed) }
                        return (reply, message.type == "revoke" ? .stopped(ScreenFailure(rawValue: message.reason ?? "") ?? .stopped) : nil)
                    }
                    if let reply = outcome.0 { try enqueue(reply) }
                    if let value = outcome.1 { event(value) }
                }
            } catch { fail(error as? ScreenFailure ?? .peerLost) }
        }
    }

    /// Caller has already recorded consent/intent and installed source and indicator.
    func grant(_ binding: ScreenBinding, scope: String) throws {
        do {
            guard !noCapture, currentProtection() else { throw ScreenFailure.protection }
            _ = try verifier.verifyCLI(socket: safety.fd, expectedPID: identity.pid, expectedIdentity: identity)
            let message = try locked {
                guard !ended else { throw ScreenFailure.stopped }
                return try state.grant(binding, scope: scope)
            }
            try enqueue(message)
        } catch {
            // A refused or unqueueable grant cannot leave prior output authority
            // alive. Invalidate and close both lanes before reporting the error.
            fail(error as? ScreenFailure ?? .peerUntrusted)
            throw error
        }
    }

    /// This invalidates synchronously, before locks, encoding, audit, or network work.
    func stop(_ reason: ScreenFailure = .stopped) {
        quiesceOutput()
        do {
            let message = try locked {
                guard !ended else { throw ScreenFailure.stopped }
                return try state.revoke(reason)
            }
            let queuedAt = try enqueue(message)
            event(.revokeQueued(queuedAt))
            event(.stopped(reason))
        } catch { fail(reason) }
    }

    /// End image authority before the safety exchange. Socket lifetime and image
    /// authority are distinct: an early frame EOF also kills the peer's safety lane.
    func quiesceOutput() {
        gate.invalidate()
        // Keep even a partial record uncontinued until safety confirmation or
        // the existing absolute deadlines close the association. EOF here would
        // make the peer discard the safety lane before its acknowledgement.
        locked {
            latest = nil
            outbound.removeAll { $0.type == "grant" }
        }
    }
    func close() { fail(.stopped) }

    /// Bounded latest-frame slot; stale or old-binding frames are dropped.
    func submit(_ header: ScreenFrameHeader, jpeg: Data, captured: ContinuousClock.Instant) throws {
        guard !noCapture, header.codec == "jpeg", jpeg.count <= 2_097_152, !jpeg.isEmpty,
              header.width > 0, header.height > 0, max(header.width, header.height) <= 2560,
              header.width <= 4_000_000 / header.height,
              gate.allows(header.binding), captured <= .now,
              captured.duration(to: .now) <= .milliseconds(500) else { throw ScreenFailure.stopped }
        let start = try locked {
            guard !ended, state.phase == .active, state.binding == header.binding,
                  header.launch == state.launch, header.connection == state.connection else { throw ScreenFailure.stopped }
            latest = (header, jpeg, captured)
            if imageWriting { return false }
            imageWriting = true; return true
        }
        if start { imageQueue.async { [self] in writeImages() } }
    }
    private func writeImages() {
        do {
            while let next = locked({ () -> (ScreenFrameHeader, Data, ContinuousClock.Instant)? in
                guard !ended, let next = latest else { imageWriting = false; return nil }
                latest = nil; return next
            }) {
                let now = ContinuousClock.now
                guard next.2.duration(to: now) <= .milliseconds(500), gate.allows(next.0.binding), currentProtection() else { continue }
                _ = try verifier.verifyCLI(socket: frames.fd, expectedPID: identity.pid, expectedIdentity: identity)
                let send = try locked {
                    if let lastImage, lastImage.duration(to: now) < .milliseconds(100) { return false }
                    try imageBudget.consume(next.1.count, now: now); lastImage = now; return true
                }
                if !send { continue }
                try frames.writeRecord(header: JSONEncoder().encode(next.0), body: next.1,
                    until: now.advanced(by: .seconds(2)), allowed: { [self] in gate.allows(next.0.binding) && currentProtection() })
            }
        } catch {
            if error as? ScreenFailure == .stopped, gate.isInvalidated {
                // The terminal gate cancels this record permanently. No later
                // frame may reuse the lane or continue the partial bytes.
                locked { latest = nil; imageWriting = false }
                return
            }
            fail(error as? ScreenFailure ?? .peerLost)
        }
    }
    private func tick() {
        do {
            let start = try locked { () -> Bool in
                guard !ended else { return false }
                try state.checkHealth()
#if SLICCY_NATIVE_SCREEN_PROOF
                if proofPaused { return false }
#endif
                if state.phase == .active || state.phase == .pending {
                    guard currentProtection() else { throw ScreenFailure.protection }
                }
                guard state.received > 0, ContinuousClock.now >= nextHeartbeat else { return false }
                nextHeartbeat = .now.advanced(by: .milliseconds(500))
                return try appendLocked(state.heartbeat()).0
            }
            if start { outputQueue.async { [self] in writeControl() } }
        } catch { fail(error as? ScreenFailure ?? .leaseExpired) }
    }
    @discardableResult
    private func enqueue(_ message: ScreenSafety) throws -> ContinuousClock.Instant {
        let (start, queuedAt) = try locked { try appendLocked(message) }
        if start { outputQueue.async { [self] in writeControl() } }
        return queuedAt
    }
    /// Caller holds lock: heartbeat sequence assignment and queue admission must
    /// be atomic even when a diagnostic control is requested between timer ticks.
    private func appendLocked(_ message: ScreenSafety) throws -> (Bool, ContinuousClock.Instant) {
        guard !ended, outbound.count < 16 else { throw ScreenFailure.resourceLimit }
        outbound.append(message)
        if controlWriting { return (false, .now) }
        controlWriting = true
        return (true, .now)
    }
    private func writeControl() {
        do {
            while let next = locked({ () -> ScreenSafety? in
                guard !ended, !outbound.isEmpty else { controlWriting = false; return nil }
                return outbound.removeFirst()
            }) {
                let data = try next.data()
                try locked { try state.checkHealth(); try outputRecords.consume(1); try outputBytes.consume(data.count + 8) }
                _ = try verifier.verifyCLI(socket: safety.fd, expectedPID: identity.pid, expectedIdentity: identity)
#if SLICCY_NATIVE_SCREEN_PROOF
                let proofSent: ContinuousClock.Instant? = locked {
                    guard next.type == "heartbeat", next.seq.flatMap(UInt64.init) == proofControlSeq,
                          proofControlSeq != nil else { return nil }
                    let now = ContinuousClock.now; proofControlSentAt = now; return now
                }
#endif
                try safety.writeRecord(header: data, until: .now.advanced(by: .seconds(1)), allowed: { [self] in
                    locked { !ended && (next.type != "grant" || (state.phase == .pending && !gate.isInvalidated)) }
                })
#if SLICCY_NATIVE_SCREEN_PROOF
                if let proofSent { event(.proofControlSent(proofSent)) }
#endif
            }
        } catch { fail(error as? ScreenFailure ?? .peerLost) }
    }
    private func fail(_ reason: ScreenFailure) {
        gate.invalidate(); frames.stop(); safety.stop()
        let notify = locked {
            guard !ended else { return false }
            ended = true; latest = nil; outbound.removeAll(); timer?.cancel(); timer = nil
            return true
        }
        if notify { event(.stopped(reason)) }
    }
    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }; return try body()
    }

#if SLICCY_NATIVE_SCREEN_PROOF
    func proofBeginExecControl() {
        outputQueue.async { [self] in
            do {
                let start = try locked {
                    guard noCapture, !ended, state.ready, !imageWriting, state.phase == .linked,
                          !proofPaused else { throw ScreenFailure.incompatible }
                    proofPaused = true
                    let message = try state.heartbeat()
                    proofControlSeq = state.sent
                    return try appendLocked(message).0
                }
                if start { outputQueue.async { [self] in writeControl() } }
            } catch { fail(error as? ScreenFailure ?? .peerLost) }
        }
    }

    /// The fixed diagnostic caller receives only the established lanes and a
    /// current heartbeat record; this API is absent from ordinary app builds.
    func proofExecAfterFreshControl(action: @escaping @Sendable (Int32, Int32, Data, ContinuousClock.Instant) throws -> Void) {
        outputQueue.async { [self] in
            do {
                let (heartbeat, deadline) = try locked {
                    let now = ContinuousClock.now
                    guard noCapture, !ended, proofPaused, state.ready, !imageWriting,
                          state.phase == .linked, !controlWriting, outbound.isEmpty,
                          let sent = proofControlSentAt, let echoed = proofControlEchoedAt,
                          sent.duration(to: now) <= .milliseconds(750), echoed.duration(to: now) <= .milliseconds(100)
                    else { throw ScreenFailure.stalled }
                    return (try state.heartbeat(), sent.advanced(by: .milliseconds(750)))
                }
                let data = try heartbeat.data()
                let record = ScreenSocket.prefix(data.count) + data + ScreenSocket.prefix(0)
                try action(safety.fd, frames.fd, record, deadline)
                throw ScreenFailure.peerLost // A successful same-PID exec never returns.
            } catch { fail(error as? ScreenFailure ?? .peerLost) }
        }
    }
#endif
}

struct ScreenRate {
    let capacity: Double
    let rate: Double
    private var tokens: Double
    private var last: ContinuousClock.Instant
    init(capacity: Double, rate: Double, now: ContinuousClock.Instant = .now) {
        self.capacity = capacity; self.rate = rate; tokens = capacity; last = now
    }
    mutating func consume(_ count: Int, now: ContinuousClock.Instant = .now) throws {
        let interval = last.duration(to: now).components
        let seconds = Double(interval.seconds) + Double(interval.attoseconds) / 1e18
        guard seconds >= 0, count >= 0 else { throw ScreenFailure.resourceLimit }
        tokens = min(capacity, tokens + seconds * rate); last = now
        guard Double(count) <= tokens else { throw ScreenFailure.resourceLimit }
        tokens -= Double(count)
    }
}
