#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

/// Shared sampling order. The production caller invokes this from Task.detached;
/// only registration uses an asynchronous MainActor hop. Samples are later facts.
enum ScreenRunnerLaunchSampling {
    static func observe(ticket: ScreenRunnerLaunchBarrier.Ticket, bundle: String,
                        before: @Sendable () throws -> ScreenRunnerBSD.Sample,
                        registration: @Sendable () async -> Bool,
                        after: @Sendable () throws -> ScreenRunnerBSD.Sample) async throws -> ScreenRunnerLaunchBarrier.Observation {
        try Task.checkCancellation()
        let beforeBegan = ContinuousClock.now
        let first: ScreenRunnerBSD.Sample
        do { first = try before() } catch { throw ScreenRunnerLaunchBarrier.Failure.bsdBefore }
        let beforeEnded = ContinuousClock.now
        let equal = await registration()
        let compared = ContinuousClock.now
        let afterBegan = ContinuousClock.now
        let second: ScreenRunnerBSD.Sample
        do { second = try after() } catch { throw ScreenRunnerLaunchBarrier.Failure.bsdAfter }
        let afterEnded = ContinuousClock.now
        try Task.checkCancellation()
        guard equal else { throw ScreenRunnerLaunchBarrier.Failure.instance }
        return .init(ticket: ticket, before: first, after: second, bundle: bundle,
            finished: true, terminated: false, observedAt: afterEnded, instanceEqual: equal,
            beforeBegan: beforeBegan, beforeEnded: beforeEnded, instanceCompared: compared, afterBegan: afterBegan)
    }
}
#endif
