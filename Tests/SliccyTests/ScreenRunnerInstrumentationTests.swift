#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerInstrumentationTests {
    @Test func browserPagesCannotCarryTheJoinCapabilityOrAcceptEndpointOverrides() throws {
        let join = "http://127.0.0.1:43210/join/private.secret?key=secret#secret"
        for window in ScreenRunnerBrowserWindow.allCases {
            let page = try window.page(join: join)
            #expect(page.absoluteString == "http://127.0.0.1:43210/screen-proof/" + window.rawValue)
            #expect(!page.absoluteString.contains("secret"))
        }
        for invalid in ["https://127.0.0.1:43210/join/a.b", "http://localhost:43210/join/a.b", "http://127.0.0.1:9222/join/a.b", "http://secret@127.0.0.1:43210/join/a.b"] {
            #expect(throws: ScreenFailure.incompatible) { try ScreenRunnerBrowserWindow.a1.page(join: invalid) }
        }
    }
    @Test func fixedPageGeometryAndTitlesMatchIndependentPageContract() {
        let expected: [(String, String, String, CGRect)] = [
            ("host-a-1", "a-1", "Sliccy proof host A1", CGRect(x: 416, y: 64, width: 288, height: 224)),
            ("host-a-2", "a-2", "Sliccy proof host A2", CGRect(x: 720, y: 64, width: 288, height: 224)),
            ("host-b-1", "b-1", "Sliccy proof host B1", CGRect(x: 416, y: 320, width: 288, height: 224)),
            ("host-b-2", "b-2", "Sliccy proof host B2", CGRect(x: 720, y: 320, width: 288, height: 224))]
        #expect(ScreenRunnerBrowserWindow.allCases.count == expected.count)
        for (window, row) in zip(ScreenRunnerBrowserWindow.allCases, expected) {
            #expect(window.rawValue == row.0 && window.profile == row.1 && window.title == row.2 && window.rect == row.3)
        }
    }
    @Test func nativeAdmissionCannotCommitAfterGateInvalidation() throws {
        let gate = ScreenOutputGate(), binding = try ScreenSafetyTests().binding()
        try gate.renew(until: .now.advanced(by: .seconds(1)))
        try gate.activate(binding)
        var committed = 0
        try gate.withAdmission(binding) { committed += 1 }
        gate.invalidate()
        #expect(throws: ScreenFailure.stopped) { try gate.withAdmission(binding) { committed += 1 } }
        #expect(committed == 1)
    }
    @Test func closedRunnerCasesCannotEnableLocalCaptureOrPIDChurn() throws {
        let arguments = ["--screen-runner-proof", "--case", "selected-window"]
        #expect(try ScreenRunnerHost.validate(arguments: arguments, environment: ScreenRunnerHost.assertions, major: 27, arm: true) == .selectedWindow)
        #expect(throws: ScreenFailure.incompatible) { try ScreenRunnerHost.validate(arguments: arguments, environment: [:], major: 27, arm: true) }
        #expect(throws: ScreenFailure.incompatible) { try ScreenRunnerHost.validate(arguments: ["--screen-runner-proof", "--case", "pid-reuse-hosted"], environment: ScreenRunnerHost.assertions, major: 27, arm: true) }
        #expect(throws: ScreenFailure.incompatible) { try ScreenRunnerHost.validate(arguments: arguments + ["--window", "1"], environment: ScreenRunnerHost.assertions, major: 27, arm: true) }
    }
    @Test func reverseQueueAdmissionIsNotWriteCompletion() {
        var trace = ScreenProofReverseReplies()
        trace.record(.received, request: "private-request")
        trace.record(.enqueued, request: "private-request")
        #expect(!trace.complete && !trace.invalid)
        let queued = trace.drain()
        #expect(queued.map(\.stage) == [.received, .enqueued])
        #expect(queued.map(\.ordinal) == [1, 1])
        trace.record(.written, request: "private-request")
        #expect(trace.complete && trace.drain().map(\.ordinal) == [1])
    }
    @Test func unmatchedDuplicateAndOverLimitRepliesCannotComplete() {
        for stage in [ScreenProofReverseReplies.Stage.enqueued, .written] {
            var trace = ScreenProofReverseReplies()
            trace.record(stage, request: "missing")
            #expect(trace.invalid && !trace.complete)
        }
        var duplicate = ScreenProofReverseReplies()
        duplicate.record(.received, request: "same")
        duplicate.record(.received, request: "same")
        #expect(duplicate.invalid && !duplicate.complete)
        var bounded = ScreenProofReverseReplies()
        for index in 1...8 {
            bounded.record(.received, request: String(index)); bounded.record(.enqueued, request: String(index))
            bounded.record(.written, request: String(index))
        }
        #expect(bounded.complete)
        bounded.record(.received, request: "ninth")
        #expect(bounded.invalid && !bounded.complete)
    }
    @Test func correlatedCompletionRequiresAllActualWrites() {
        var trace = ScreenProofReverseReplies()
        trace.record(.received, request: "a"); trace.record(.received, request: "b")
        trace.record(.enqueued, request: "b"); trace.record(.written, request: "b")
        #expect(!trace.complete)
        trace.record(.enqueued, request: "a"); trace.record(.written, request: "a")
        #expect(trace.complete)
        #expect(trace.drain().map(\.ordinal) == [1, 2, 2, 2, 1, 1])
    }
    @Test func captureLimitCannotFireAfterCancellationOrFireTwice() {
        final class Counter: @unchecked Sendable {
            private let lock = NSLock()
            private var value = 0
            func add() { lock.lock(); value += 1; lock.unlock() }
            var count: Int { lock.lock(); defer { lock.unlock() }; return value }
        }
        let first = Counter(), second = Counter()
        let cancelled = ScreenRunnerCaptureLimit { first.add() }
        cancelled.arm(); cancelled.cancel(); cancelled.expire()
        #expect(first.count == 0)
        let expired = ScreenRunnerCaptureLimit { second.add() }
        expired.arm(); expired.expire(); expired.expire(); expired.cancel()
        #expect(second.count == 1)
    }
    @Test func mandatoryStopPrecedesBlockedObserver() {
        for blockEntered in [true, false] {
            let gate = ScreenOutputGate()
            let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
            let stopped = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
            let block: @Sendable () -> Void = {
                entered.signal()
                _ = release.wait(timeout: .now() + 2)
            }
            let relay = ScreenStopRelay(gate: gate, entered: { _, _ in if blockEntered { block() } },
                observed: { _, _ in if !blockEntered { block() } }, stop: { _ in stopped.signal() })
            Thread { relay.invoke(.stopped, origin: .button); finished.signal() }.start()
            #expect(entered.wait(timeout: .now() + 1) == .success)
            #expect(gate.isInvalidated)
            #expect(stopped.wait(timeout: .now() + .milliseconds(100)) == .success)
            release.signal()
            #expect(finished.wait(timeout: .now() + 1) == .success)
        }
    }
    @Test func stopCallbacksObserveAlreadyInvalidatedGateAndActualOrigin() {
        let gate = ScreenOutputGate()
        let relay = ScreenStopRelay(gate: gate, entered: { origin, _ in
            #expect(gate.isInvalidated)
            #expect(origin == .hotkey)
        }, observed: { start, invalidated in
            #expect(gate.isInvalidated && invalidated >= start)
        }, stop: { _ in #expect(gate.isInvalidated) })
        relay.invoke(.stopped, origin: .hotkey)
    }
}
#endif
