#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerLaunchInstanceTests {
    final class Instance: NSObject, @unchecked Sendable {
        let token: Int, pid: Int32
        init(_ token: Int, pid: Int32 = 100) { self.token = token; self.pid = pid }
        override func isEqual(_ object: Any?) -> Bool { (object as? Instance)?.token == token }
        override var hash: Int { token }
    }
    static let facts = ScreenRunnerLaunchInstance.Facts(pid: 100, bundle: "com.google.Chrome", finished: true, terminated: false)
    @Test func actualFoundationSemanticEqualityNeverFallsBackToPIDOrPointer() {
        let original = Instance(1), current = Instance(1), reused = Instance(2)
        #expect(original !== current)
        #expect(ScreenRunnerLaunchInstance.matches(original: original, current: current, originalFacts: Self.facts,
            currentFacts: Self.facts, expectedPID: 100, expectedBundle: "com.google.Chrome"), "launch-instance-semantic-positive")
        #expect(!ScreenRunnerLaunchInstance.matches(original: original, current: reused, originalFacts: Self.facts,
            currentFacts: Self.facts, expectedPID: 100, expectedBundle: "com.google.Chrome"), "launch-instance-same-pid-refused")
        #expect(!ScreenRunnerLaunchInstance.matches(original: original, current: nil, originalFacts: Self.facts,
            currentFacts: nil, expectedPID: 100, expectedBundle: "com.google.Chrome"), "launch-instance-missing-current")
    }
    @Test func registrationFlagsDoNotReplaceSemanticIdentity() {
        let original = Instance(1), current = Instance(1)
        for facts in [ScreenRunnerLaunchInstance.Facts(pid: 101, bundle: "com.google.Chrome", finished: true, terminated: false),
                      .init(pid: 100, bundle: "com.other.Chrome", finished: true, terminated: false),
                      .init(pid: 100, bundle: "com.google.Chrome", finished: false, terminated: false),
                      .init(pid: 100, bundle: "com.google.Chrome", finished: true, terminated: true)] {
            #expect(!ScreenRunnerLaunchInstance.matches(original: original, current: current, originalFacts: Self.facts,
                currentFacts: facts, expectedPID: 100, expectedBundle: "com.google.Chrome"), "launch-registration-fields-required")
        }
    }
    @Test func bothLaterBSDReadsMustMatchOriginalEvenWithEqualInstance() {
        typealias F = ScreenRunnerLaunchBarrierTests
        let at = ContinuousClock.now, ticket = ScreenRunnerLaunchBarrier.Ticket(sequence: 1, at: at)
        let good = F.observation(ticket, pid: 100)
        #expect(ScreenRunnerLaunchBarrier.matchesOwned(F.original(100), good))
        let beforeChanged = ScreenRunnerLaunchBarrier.Observation(ticket: ticket, before: F.sample(100, seconds: 11),
            after: F.sample(100), bundle: "com.google.Chrome", finished: true, terminated: false, observedAt: .now)
        #expect(!ScreenRunnerLaunchBarrier.matchesOwned(F.original(100), beforeChanged), "launch-original-bsd-before")
        let afterChanged = ScreenRunnerLaunchBarrier.Observation(ticket: ticket, before: F.sample(100),
            after: F.sample(100, seconds: 11), bundle: "com.google.Chrome", finished: true, terminated: false, observedAt: .now)
        #expect(!ScreenRunnerLaunchBarrier.matchesOwned(F.original(100), afterChanged), "launch-original-bsd-after")
    }
}
#endif
