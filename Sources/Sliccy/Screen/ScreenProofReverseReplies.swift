#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

struct ScreenProofReverseReplies {
    enum Stage: String, Sendable { case received, enqueued, written }
    struct Notice: Sendable {
        let stage: Stage
        let ordinal: Int
        let at: ContinuousClock.Instant
        let invalidation: (ContinuousClock.Instant, ContinuousClock.Instant)?
    }
    struct Cutoff: Sendable {
        let at: ContinuousClock.Instant
        let transportWasOpen: Bool
        let pending: Int
        let readInFlight: Bool
    }
    struct Closure: Sendable {
        let notices: [Notice]
        let cutoff: Cutoff
        let requests: Int
        let written: Int
        let pending: Int
        let invalid: Bool
        let workersSettled: Bool
        var succeeded: Bool {
            cutoff.transportWasOpen && cutoff.pending == 0 && !cutoff.readInFlight &&
                pending == 0 && !invalid && workersSettled
        }
    }
    private var cutoff: Cutoff?
    private var phases: [String: (Int, Stage)] = [:]
    private var notices: [Notice] = []
    private(set) var invalid = false
    var complete: Bool { !invalid && !phases.isEmpty && pending == 0 }
    private var pending: Int { phases.values.filter { $0.1 != .written }.count }
    mutating func invalidate() { invalid = true }
    mutating func beginCutoff(transportWasOpen: Bool, readInFlight: Bool, at: ContinuousClock.Instant = .now) {
        guard cutoff == nil else { invalid = true; return }
        cutoff = Cutoff(at: at, transportWasOpen: transportWasOpen, pending: pending, readInFlight: readInFlight)
    }
    mutating func closedSnapshot(workersSettled: Bool) -> Closure {
        let point = cutoff ?? Cutoff(at: .now, transportWasOpen: false, pending: pending, readInFlight: true)
        if cutoff == nil { invalid = true }
        return Closure(notices: drain(), cutoff: point, requests: phases.count, written: phases.count - pending,
                       pending: pending, invalid: invalid, workersSettled: workersSettled)
    }

    mutating func record(_ stage: Stage, request: String?, at: ContinuousClock.Instant = .now, invalidation: (ContinuousClock.Instant, ContinuousClock.Instant)? = nil) {
        guard let request else { invalid = true; return }
        guard cutoff == nil || stage == .written else { invalid = true; return }
        let ordinal: Int
        switch stage {
        case .received:
            guard phases[request] == nil, phases.count < 8 else { invalid = true; return }
            ordinal = phases.count + 1
        case .enqueued:
            guard let prior = phases[request], prior.1 == .received else { invalid = true; return }
            ordinal = prior.0
        case .written:
            guard let prior = phases[request], prior.1 == .enqueued else { invalid = true; return }
            ordinal = prior.0
        }
        guard notices.count < 24 else { invalid = true; return }
        phases[request] = (ordinal, stage)
        notices.append(.init(stage: stage, ordinal: ordinal, at: at, invalidation: invalidation))
    }
    mutating func drain() -> [Notice] {
        let result = notices; notices.removeAll(keepingCapacity: true); return result
    }
}
#endif
