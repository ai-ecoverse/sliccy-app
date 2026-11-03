#if SLICCY_HOSTED_PID_PROOF
import Foundation

struct ScreenHostedPIDBudget {
    enum Stop: String { case unsupportedTarget = "unsupported-target", timeLimit = "time-limit", cpuDebtAtDeadline = "cpu-debt-at-deadline", invalidAccounting = "invalid-accounting", invalidLifecycle = "invalid-lifecycle", wrapLimit = "wrap-limit" }
    enum Decision: Equatable { case spawnCycler, pace(Duration), attemptCLI, stop(Stop) }
    static let limit: Duration = .seconds(900)
    private enum Phase { case cycling, nearTarget, exhausted, stopped }
    private let original: Int32
    let started: ContinuousClock.Instant
    private let initialSelf: Duration, initialChildren: Duration
    private var lastSelf: Duration, lastChildren: Duration
    private var phase: Phase = .cycling
    private var permitted = false, childOutstanding = false
    private var outstandingPID: Int32?
    private var lastReturned: Int32?
    private var approachRecorded = false, missRecorded = false
    private(set) var wraps = 0
    private(set) var closestBelow: Int32?, closestAbove: Int32?
    struct Observation: Equatable {
        enum Kind: String { case wrap, approach, missed }
        let kind: Kind
        let wrap: Int
        let previousPID: Int32?
        let returnedPID: Int32
        let distance: Int64
        let closestBelow: Int32?
        let closestAbove: Int32?
    }
    private(set) var spawned: UInt64 = 0, reaped: UInt64 = 0
    private(set) var maximumTransientDebt: Duration = .zero
    var deadline: ContinuousClock.Instant { started.advanced(by: Self.limit) }

    init(original: Int32, started: ContinuousClock.Instant, selfCPU: Duration, childrenCPU: Duration) {
        self.original = original; self.started = started
        initialSelf = selfCPU; initialChildren = childrenCPU
        lastSelf = selfCPU; lastChildren = childrenCPU
    }
    mutating func decision(now: ContinuousClock.Instant, selfCPU: Duration, childrenCPU: Duration) -> Decision {
        guard original > 2 else { phase = .stopped; return .stop(.unsupportedTarget) }
        guard phase != .stopped, !permitted, !childOutstanding, spawned == reaped else {
            phase = .stopped; return .stop(.invalidLifecycle)
        }
        let wall = started.duration(to: now), cpu = selfCPU + childrenCPU - initialSelf - initialChildren
        guard wall >= .zero, selfCPU >= .zero, childrenCPU >= .zero, selfCPU >= lastSelf,
              childrenCPU >= lastChildren, cpu >= .zero else { phase = .stopped; return .stop(.invalidAccounting) }
        lastSelf = selfCPU; lastChildren = childrenCPU
        let debt = max(.zero, cpu - wall)
        maximumTransientDebt = max(maximumTransientDebt, debt)
        guard wall < Self.limit else {
            phase = .stopped; return .stop(debt > .zero ? .cpuDebtAtDeadline : .timeLimit)
        }
        if debt > .zero { return .pace(min(debt, .milliseconds(25), Self.limit - wall)) }
        if phase == .nearTarget { phase = .stopped; return .attemptCLI }
        if phase == .exhausted { phase = .stopped; return .stop(.wrapLimit) }
        permitted = true
        return .spawnCycler
    }
    mutating func didSpawnCycler(pid: Int32) throws {
        guard phase == .cycling, permitted, !childOutstanding, outstandingPID == nil, pid > 0, spawned == reaped else { throw ScreenFailure.incompatible }
        permitted = false; childOutstanding = true; outstandingPID = pid; spawned += 1
    }
    @discardableResult
    mutating func didReapCycler(pid: Int32) throws -> [Observation] {
        guard phase == .cycling, childOutstanding, outstandingPID == pid, pid > 0 else { throw ScreenFailure.incompatible }
        childOutstanding = false; outstandingPID = nil; reaped += 1
        let previous = lastReturned
        let wrapped = previous.map { pid < $0 } ?? false
        guard !wrapped || wraps < 2 else { phase = .stopped; throw ScreenFailure.incompatible }
        var observations: [Observation] = []
        let distance = Int64(original) - Int64(pid)
        func observation(_ kind: Observation.Kind) -> Observation {
            Observation(kind: kind, wrap: wraps, previousPID: previous, returnedPID: pid,
                        distance: distance, closestBelow: closestBelow, closestAbove: closestAbove)
        }
        if wrapped {
            wraps += 1
            observations.append(observation(.wrap))
            approachRecorded = false; missRecorded = false
            closestBelow = nil; closestAbove = nil
        }
        lastReturned = pid
        if pid < original { closestBelow = min(closestBelow ?? Int32.max, original - pid) }
        else { closestAbove = min(closestAbove ?? Int32.max, pid - original) }
        let inApproach = distance > 0 && distance <= 2000
        let wrappedOverTarget = wrapped && pid >= original
        if !approachRecorded, inApproach || wrappedOverTarget {
            approachRecorded = true; observations.append(observation(.approach))
        }
        let crossedTarget = previous.map { $0 < original && pid >= original } ?? false
        if !missRecorded, wrappedOverTarget || crossedTarget {
            missRecorded = true; observations.append(observation(.missed))
            if wraps == 2 { phase = .exhausted }
        }
        if pid == original - 1 { phase = .nearTarget }
        return observations
    }
    func cpu(selfCPU: Duration, childrenCPU: Duration) -> Duration { selfCPU + childrenCPU - initialSelf - initialChildren }
    static func sameCredentialPrefixAndNewVersion(saved: ScreenAuditIdentity, current: ScreenAuditIdentity) -> Bool {
        saved.words.prefix(7).elementsEqual(current.words.prefix(7)) && saved.words[7] != current.words[7]
    }
}
#endif
