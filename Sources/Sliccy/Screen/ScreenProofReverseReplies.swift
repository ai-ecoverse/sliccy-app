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
    private var phases: [String: (Int, Stage)] = [:]
    private var notices: [Notice] = []
    private(set) var invalid = false
    var complete: Bool { !invalid && !phases.isEmpty && phases.values.allSatisfy { $0.1 == .written } }

    mutating func record(_ stage: Stage, request: String?, at: ContinuousClock.Instant = .now, invalidation: (ContinuousClock.Instant, ContinuousClock.Instant)? = nil) {
        guard !invalid, let request else { invalid = true; return }
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
