#if SLICCY_HOSTED_PID_PROOF
import Foundation

struct ScreenHostedPIDBudget {
    enum Stop: String { case unsupportedTarget = "unsupported-target", timeLimit = "time-limit", cpuDebtAtDeadline = "cpu-debt-at-deadline", invalidAccounting = "invalid-accounting", invalidLifecycle = "invalid-lifecycle" }
    enum Decision: Equatable { case spawnCycler, pace(Duration), attemptCLI, stop(Stop) }
    static let limit: Duration = .seconds(600)
    private enum Phase { case cycling, nearTarget, stopped }
    private let original: Int32
    let started: ContinuousClock.Instant
    private let initialSelf: Duration, initialChildren: Duration
    private var lastSelf: Duration, lastChildren: Duration
    private var phase: Phase = .cycling
    private var permitted = false, childOutstanding = false
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
        permitted = true
        return .spawnCycler
    }
    mutating func didSpawnCycler() throws {
        guard phase == .cycling, permitted, !childOutstanding, spawned == reaped else { throw ScreenFailure.incompatible }
        permitted = false; childOutstanding = true; spawned += 1
    }
    mutating func didReapCycler(pid: Int32) throws {
        guard phase == .cycling, childOutstanding, pid > 0 else { throw ScreenFailure.incompatible }
        childOutstanding = false; reaped += 1
        if pid == original - 1 { phase = .nearTarget }
    }
    func cpu(selfCPU: Duration, childrenCPU: Duration) -> Duration { selfCPU + childrenCPU - initialSelf - initialChildren }
    static func sameCredentialPrefixAndNewVersion(saved: ScreenAuditIdentity, current: ScreenAuditIdentity) -> Bool {
        saved.words.prefix(7).elementsEqual(current.words.prefix(7)) && saved.words[7] != current.words[7]
    }
}
#endif
