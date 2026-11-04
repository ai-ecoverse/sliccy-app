#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerCauseTests {
    final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var notices: [ScreenRunnerCauseLedger.Notice] = []
        func append(_ notice: ScreenRunnerCauseLedger.Notice) { lock.lock(); notices.append(notice); lock.unlock() }
        var rows: [ScreenRunnerCauseLedger.Notice] { lock.lock(); defer { lock.unlock() }; return notices }
    }
    @Test func firstPreGrantCauseSurvivesConcurrentRepeatedStopsAndCleanup() throws {
        let sink = Sink(), now = ContinuousClock.now
        let ledger = ScreenRunnerCauseLedger { sink.append($0) }
        ledger.advance(.inventory)
        ledger.record(.stop, reason: .screen(.sourceChanged), origin: .workspaceLaunch, at: now)
        ledger.advance(.cleanup)
        DispatchQueue.concurrentPerform(iterations: 64) { _ in
            ledger.record(.stop, reason: .screen(.stopped), origin: .cancelled, at: now.advanced(by: .milliseconds(100)))
        }
        let row = try #require(sink.rows.first)
        #expect(sink.rows.count == 1 && row.phase == .inventory && row.origin == .workspaceLaunch)
        #expect(row.reason.value == "screen-source-changed" && row.at == now && ledger.firstStopAt == now)
    }
    @Test func independentFailureKindsStayBoundedAndNeverExposeErrorText() {
        struct ContentError: Error { let text = "private-title-and-path" }
        let sink = Sink(), ledger = ScreenRunnerCauseLedger { sink.append($0) }
        ledger.advance(.preparing)
        for _ in 0..<3 {
            ledger.record(.inventory, reason: .inventory(.authorizationMissing), origin: .inventory)
            ledger.record(.launcherReap, reason: .reaped, origin: .launcher)
            ledger.record(.childLoss, reason: .screen(.peerLost), origin: .nativeChild)
            ledger.record(.failure, reason: .error(ContentError()), origin: .fixture)
        }
        #expect(sink.rows.count == 4)
        #expect(sink.rows.map(\.reason.value) == ["inventory-authorization-missing", "reaped", "screen-peer-lost", "unexpected"])
        #expect(sink.rows.allSatisfy { $0.phase == .preparing })
    }
    @Test func stopClockCannotBeExtendedByDelayedObservation() {
        let now = ContinuousClock.now, ledger = ScreenRunnerCauseLedger { _ in }
        ledger.noteStop(at: now.advanced(by: .milliseconds(20)))
        ledger.record(.stop, reason: .screen(.stopped), origin: .button, at: now)
        ledger.noteStop(at: now.advanced(by: .seconds(2)))
        #expect(ledger.firstStopAt == now)
    }
    @Test func queuedStopKeepsPreGrantPhaseDespiteDelayedCauseCallback() throws {
        let sink = Sink(), ledger = ScreenRunnerCauseLedger { sink.append($0) }
        let now = ContinuousClock.now
        ledger.advance(.inventory); ledger.noteStop(at: now)
        ledger.advance(.stopping); ledger.advance(.cleanup)
        ledger.record(.stop, reason: .screen(.sourceChanged), origin: .workspaceLaunch, at: now)
        #expect(try #require(sink.rows.first).phase == .inventory)
    }
    @Test func causeObserverCannotBlockMandatoryStop() {
        let gate = ScreenOutputGate(), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let stopped = DispatchSemaphore(value: 0), done = DispatchSemaphore(value: 0)
        let relay = ScreenStopRelay(gate: gate, cause: { reason, origin, _ in
            #expect(reason == .sourceChanged && origin == .workspaceTerminate)
            entered.signal(); _ = release.wait(timeout: .now() + 2)
        }, stop: { _ in stopped.signal() })
        Thread { relay.invoke(.sourceChanged, origin: .workspaceTerminate); done.signal() }.start()
        #expect(entered.wait(timeout: .now() + 1) == .success)
        #expect(gate.isInvalidated && stopped.wait(timeout: .now() + .milliseconds(100)) == .success)
        release.signal()
        #expect(done.wait(timeout: .now() + 1) == .success)
    }
}
#endif
