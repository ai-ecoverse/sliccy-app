#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

/// One observer's local delivery ledger. It supplies no process/signal authority.
final class ScreenRunnerLaunchBarrier: @unchecked Sendable {
    static let maximumEvents = 64
    static let labels = ["a-1", "a-2", "b-1", "b-2"]
    enum Phase { case collecting, candidate, armed, failed, closed }
    enum Failure: String, Error, Sendable {
        case eventLimit = "launch-event-limit", invalidPayload = "launch-payload"
        case bsdBefore = "launch-bsd-before", bsdAfter = "launch-bsd-after", instance = "launch-instance"
        case identity = "launch-identity", registration = "launch-registration", duplicate = "launch-duplicate"
        case revision = "launch-revision", pending = "launch-pending", deadline = "launch-deadline"
        case cancelled = "launch-cancelled", marker = "launch-marker", lifecycle = "launch-lifecycle"
    }
    struct Ticket: Equatable, Sendable { let sequence: Int; let at: ContinuousClock.Instant }
    struct Observation: Equatable, Sendable {
        let ticket: Ticket
        let before: ScreenRunnerBSD.Sample, after: ScreenRunnerBSD.Sample
        let bundle: String
        let finished: Bool, terminated: Bool
        let observedAt: ContinuousClock.Instant
        var instanceEqual = false
        var beforeBegan: ContinuousClock.Instant? = nil
        var beforeEnded: ContinuousClock.Instant? = nil
        var instanceCompared: ContinuousClock.Instant? = nil
        var afterBegan: ContinuousClock.Instant? = nil
    }
    struct Owner: Equatable, Sendable {
        let label: String
        let original: ScreenRunnerProcessSample
        let observation: Observation
    }
    struct Candidate: Equatable, Sendable { let revision: UInt64; let owners: [Owner] }
    enum Admission { case collect(Ticket), stop(ScreenStopRelay), refuse }
    private let lock = NSLock()
    private var phase: Phase = .collecting
    private var revision: UInt64 = 0, sequence = 0
    private var pending: Set<Int> = []
    private var expected: [String: ScreenRunnerProcessSample] = [:]
    private var observations: [Int32: Observation] = [:]
    private var failure: Failure?
    private var candidate: Candidate?
    private var verificationPending = false, verified = false
    private var relay: ScreenStopRelay?
    let changes: AsyncStream<Void>
    private let changed: AsyncStream<Void>.Continuation

    init() {
        let pair = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        changes = pair.stream; changed = pair.continuation
    }
    private func reject(_ value: Failure) {
        if failure == nil { failure = value }
        if phase != .closed && phase != .armed { phase = .failed }
    }
    private func wake() { changed.yield(()) }
    func begin(at: ContinuousClock.Instant = .now) -> Admission {
        lock.lock()
        if phase == .armed, let relay { lock.unlock(); return .stop(relay) }
        guard phase == .collecting else {
            if phase == .candidate { revision += 1; reject(.revision) }
            lock.unlock(); wake(); return .refuse
        }
        revision += 1; sequence += 1
        guard sequence <= Self.maximumEvents else { reject(.eventLimit); lock.unlock(); wake(); return .refuse }
        let ticket = Ticket(sequence: sequence, at: at)
        pending.insert(sequence)
        lock.unlock(); wake(); return .collect(ticket)
    }
    func register(label: String, original: ScreenRunnerProcessSample) {
        lock.lock()
        if phase != .collecting || !Self.labels.contains(label) || expected[label] != nil ||
            expected.values.contains(where: { $0.pid == original.pid }) || original.pid <= 0 {
            reject(.identity)
        } else { expected[label] = original; revision += 1 }
        lock.unlock(); wake()
    }
    func complete(_ ticket: Ticket, observation: Observation?, failure error: Failure? = nil) {
        lock.lock()
        guard pending.remove(ticket.sequence) != nil else { reject(.lifecycle); lock.unlock(); wake(); return }
        revision += 1
        if let error { reject(error) }
        if let value = observation {
            if value.ticket.sequence != ticket.sequence || value.ticket.at != ticket.at ||
                !value.instanceEqual || value.bundle != "com.google.Chrome" || !value.finished || value.terminated {
                reject(.registration)
            } else if observations[value.before.pid] != nil { reject(.duplicate) }
            else { observations[value.before.pid] = value }
        }
        lock.unlock(); wake()
    }
    private static func matches(_ sample: ScreenRunnerProcessSample, _ value: ScreenRunnerBSD.Sample) -> Bool {
        sample.pid == value.pid && sample.parent == value.parent && sample.uid == value.effectiveUID &&
            sample.seconds == value.seconds && sample.microseconds == value.microseconds
    }
    static func matchesOwned(_ original: ScreenRunnerProcessSample, _ observed: Observation) -> Bool {
        guard matches(original, observed.before) else { return false }
        guard matches(original, observed.after) else { return false }
        return observed.before.realUID == observed.after.realUID && observed.before.savedUID == observed.after.savedUID
    }
    /// Latches ONCE before any ready rows. Later activity can only invalidate it.
    func latch() throws -> Candidate? {
        lock.lock(); defer { lock.unlock() }
        if let failure { throw failure }
        guard phase == .collecting else { throw Failure.lifecycle }
        guard pending.isEmpty, expected.count == 4 else { return nil }
        var owners: [Owner] = []
        for label in Self.labels {
            guard let original = expected[label], let observed = observations[original.pid] else { return nil }
            guard Self.matchesOwned(original, observed) else { reject(.identity); throw Failure.identity }
            owners.append(.init(label: label, original: original, observation: observed))
        }
        let value = Candidate(revision: revision, owners: owners)
        candidate = value; phase = .candidate; return value
    }
    func beginVerification(_ value: Candidate) throws {
        lock.lock(); defer { lock.unlock() }
        guard failure == nil, phase == .candidate, candidate == value,
              revision == value.revision, pending.isEmpty, !verificationPending, !verified else {
            reject(.revision); throw failure ?? Failure.revision
        }
        verificationPending = true
    }
    func endVerification(_ value: Candidate, observations values: [Observation]?) throws {
        lock.lock(); defer { lock.unlock() }
        guard verificationPending else { reject(.lifecycle); throw failure ?? Failure.lifecycle }
        verificationPending = false
        guard failure == nil, phase == .candidate, candidate == value, revision == value.revision, let values, values.count == 4 else {
            reject(.revision); throw failure ?? Failure.revision
        }
        for (owner, observed) in zip(value.owners, values) {
            guard observed.ticket == owner.observation.ticket, observed.instanceEqual, Self.matchesOwned(owner.original, observed),
                  observed.before == owner.observation.before,
                  observed.bundle == "com.google.Chrome", observed.finished, !observed.terminated else {
                reject(.identity); throw Failure.identity
            }
        }
        verified = true
    }
    @discardableResult func arm(_ target: ScreenStopRelay) throws -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        guard failure == nil, phase == .candidate, let candidate, revision == candidate.revision,
              pending.isEmpty, !verificationPending, verified else {
            reject(.revision); throw failure ?? Failure.revision
        }
        relay = target; phase = .armed; return candidate.revision
    }
    func fail(_ reason: Failure) { lock.lock(); reject(reason); lock.unlock(); wake() }
    func close() -> (pending: Int, failed: Bool) {
        lock.lock()
        let count = pending.count + (verificationPending ? 1 : 0)
        if phase != .armed && failure == nil { reject(.cancelled) }
        let failed = failure != nil
        phase = .closed; relay = nil
        lock.unlock(); changed.finish(); return (count, failed)
    }
    func awaitCandidate(until deadline: ContinuousClock.Instant) async throws -> Candidate {
        try await withThrowingTaskGroup(of: Candidate.self) { group in
            group.addTask { [self] in
                if let value = try latch() { return value }
                for await _ in changes {
                    try Task.checkCancellation()
                    if let value = try latch() { return value }
                }
                throw Failure.cancelled
            }
            group.addTask {
                try await ContinuousClock().sleep(until: deadline)
                throw Failure.deadline
            }
            defer { group.cancelAll() }
            guard let value = try await group.next() else { throw Failure.cancelled }
            return value
        }
    }
}
#endif
