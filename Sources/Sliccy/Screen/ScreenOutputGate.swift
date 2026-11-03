import Foundation

/// Tiny synchronous invalidation boundary. Never holds its lock during I/O,
/// encoding, MainActor work or audit. An invalidated session cannot be resumed.
final class ScreenOutputGate: @unchecked Sendable {
    private let lock = NSLock()
    private var binding: ScreenBinding?
    private var healthUntil: ContinuousClock.Instant?
    private var invalidated = Set<String>()
    private var stopped = false
    private var frameSeq: UInt64 = 0

    var isInvalidated: Bool { lock.lock(); defer { lock.unlock() }; return stopped }

    func renew(until: ContinuousClock.Instant, now: ContinuousClock.Instant = .now) throws {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, until > now else { throw ScreenFailure.leaseExpired }
        if healthUntil.map({ now >= $0 }) == true {
            if let binding { invalidated.insert(binding.session) }
            self.binding = nil; healthUntil = nil
            stopped = true
            throw ScreenFailure.leaseExpired
        }
        healthUntil = until
    }
    func activate(_ proposed: ScreenBinding, now: ContinuousClock.Instant = .now) throws {
        try proposed.validate()
        lock.lock(); defer { lock.unlock() }
        guard !stopped, binding == nil, !invalidated.contains(proposed.session), let healthUntil, now < healthUntil else { throw ScreenFailure.leaseExpired }
        binding = proposed; frameSeq = 0
    }
    @discardableResult
    func invalidate() -> ScreenBinding? {
        lock.lock(); defer { lock.unlock() }
        let previous = binding
        stopped = true
        if let previous { invalidated.insert(previous.session) }
        binding = nil; healthUntil = nil
        return previous
    }
    func allows(_ candidate: ScreenBinding, now: ContinuousClock.Instant = .now) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return binding == candidate && healthUntil.map { now < $0 } == true
    }
    func nextFrame(now: ContinuousClock.Instant = .now) throws -> (ScreenBinding, UInt64) {
        let result = try admitFrame(now: now)
        return (result.0, result.1)
    }
    func withAdmission<T>(_ candidate: ScreenBinding, _ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        guard !stopped, binding == candidate, let healthUntil, ContinuousClock.now < healthUntil else { throw ScreenFailure.stopped }
        return try body()
    }
    func admitFrame(now: ContinuousClock.Instant = .now) throws -> (ScreenBinding, UInt64, ContinuousClock.Instant) {
        lock.lock(); defer { lock.unlock() }
        guard let binding, let healthUntil, now < healthUntil, frameSeq < UInt64.max else { throw ScreenFailure.leaseExpired }
        frameSeq += 1
        return (binding, frameSeq, .now)
    }
}
