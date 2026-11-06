#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerLaunchAsyncTests {
    typealias F = ScreenRunnerLaunchBarrierTests
    typealias B = ScreenRunnerLaunchBarrier
    final class Registration: NSObject, @unchecked Sendable {
        @objc dynamic var finished = false
    }
    @Test @MainActor func actualFoundationKVOAndCancellationCannotReviveCompletion() async throws {
        let object = Registration(), completion = ScreenRunnerLaunchCompletion()
        let observation = object.observe(\.finished, options: [.initial, .new]) { object, _ in
            if object.finished { completion.finish(.success(())) }
        }
        defer { observation.invalidate() }
        let wait = Task { try await completion.wait() }
        wait.cancel()
        do { try await wait.value; Issue.record("launch-cancellation-cannot-succeed") }
        catch { #expect(error as? B.Failure == .cancelled, "launch-cancellation-cannot-succeed") }
        object.finished = true // real late KVO delivery, after cancellation completed.
        do { try await completion.wait(); Issue.record("launch-late-kvo-cannot-revive") }
        catch { #expect(error as? B.Failure == .cancelled, "launch-late-kvo-cannot-revive") }
        let early = ScreenRunnerLaunchCompletion()
        early.finish(.success(()))
        try await early.wait() // callback before continuation installation is retained.
    }
    @Test func actualSamplingAdapterRejectsInstanceReuseAndKeepsBothOriginalReads() async throws {
        typealias I = ScreenRunnerLaunchInstanceTests
        let original = I.Instance(1), ticket = B.Ticket(sequence: 1, at: .now)
        for variant in 0..<5 {
            let current: I.Instance? = variant == 4 ? nil : I.Instance(variant == 1 ? 2 : 1)
            do {
                let value = try await ScreenRunnerLaunchSampling.observe(ticket: ticket, bundle: "com.google.Chrome", before: {
                    F.sample(100, seconds: variant == 2 ? 11 : 10)
                }, registration: {
                    ScreenRunnerLaunchInstance.matches(original: original, current: current, originalFacts: I.facts,
                        currentFacts: current == nil ? nil : I.facts, expectedPID: 100, expectedBundle: "com.google.Chrome")
                }, after: { F.sample(100, seconds: variant == 3 ? 11 : 10) })
                #expect(variant != 1 && variant != 4, "launch-sampling-instance-boundary")
                #expect(B.matchesOwned(F.original(100), value) == (variant == 0), "launch-sampling-original-bracket")
                let before = try #require(value.beforeBegan), end = try #require(value.beforeEnded)
                let comparison = try #require(value.instanceCompared), after = try #require(value.afterBegan)
                #expect(ticket.at <= before && before <= end && end <= comparison && comparison <= after && after <= value.observedAt,
                        "launch-sampling-causal-timestamps")
            } catch {
                #expect((variant == 1 || variant == 4) && error as? B.Failure == .instance, "launch-sampling-instance-boundary")
            }
        }
    }
    @Test func sameRevisionCannotSubstituteCandidateOrNotificationAfterMarker() throws {
        let b = try F.setup(), ready = try #require(try b.latch())
        var owners = ready.owners
        owners[0] = .init(label: owners[0].label, original: F.original(999), observation: owners[0].observation)
        let forged = B.Candidate(revision: ready.revision, owners: owners)
        #expect(throws: (any Error).self, "launch-candidate-object-bound") { try b.beginVerification(forged) }
        let next = try F.setup(), candidate = try #require(try next.latch())
        try next.beginVerification(candidate)
        var values = candidate.owners.map(\.observation)
        values[0] = F.observation(.init(sequence: 63, at: .now), pid: 100)
        #expect(throws: (any Error).self, "launch-recheck-original-notification") {
            try next.endVerification(candidate, observations: values)
        }
        let swapped = try F.setup(), held = try #require(try swapped.latch())
        try swapped.beginVerification(held)
        var falseInstance = held.owners.map(\.observation)
        falseInstance[3].instanceEqual = false
        #expect(throws: (any Error).self, "launch-post-marker-instance-substitution") {
            try swapped.endVerification(held, observations: falseInstance)
        }
    }
    @Test func pendingNativeCompletionStaysCountedAfterCancellationAndClose() throws {
        let b = B()
        guard case .collect(let ticket) = b.begin() else { Issue.record("launch-fixture-admission"); return }
        b.fail(.cancelled) // waiter canceled; outstanding callback has not returned.
        let closed = b.close()
        #expect(closed.pending == 1 && closed.failed, "launch-cancelled-native-still-pending")
        b.complete(ticket, observation: F.observation(ticket, pid: 100))
        #expect(throws: (any Error).self, "launch-late-native-cannot-revive") { _ = try b.latch() }
        #expect(b.close().pending == 0 && b.close().failed)
    }
}
#endif
