#if SLICCY_CAPTURE_RUNNER_PROOF
import Darwin
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerJournalTests {
    private func pipePair() throws -> [Int32] {
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else { throw ScreenFailure.resourceLimit }
        return descriptors
    }
    private func fill(_ descriptor: Int32) throws {
        let bytes = [UInt8](repeating: 0x78, count: 512)
        for _ in 0..<2048 {
            let count = bytes.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
            if count < 0, errno == EAGAIN || errno == EWOULDBLOCK { return }
            guard count == bytes.count else { throw ScreenFailure.incompatible }
        }
        throw ScreenFailure.resourceLimit
    }
    @Test func fullPipeCannotDelayMandatoryStopAndDeliveryLossCancelsAuthority() throws {
        let pipe = try pipePair(); defer { close(pipe[0]); close(pipe[1]) }
        let gate = ScreenOutputGate(), stopped = DispatchSemaphore(value: 0), loss = DispatchSemaphore(value: 0)
        let abort = ScreenRunnerDiagnosticAbort()
        abort.register { gate.invalidate(); loss.signal() }
        let journal = try ScreenRunnerJournal(.activeStop, descriptor: pipe[1], authorityFailed: { abort.fail() })
        try fill(pipe[1])
        let observerEntered = DispatchSemaphore(value: 0), finished = DispatchSemaphore(value: 0)
        let relay = ScreenStopRelay(gate: gate, entered: { _, at in
            observerEntered.signal()
            journal.emit("stop-handler-entered", ["trigger": "button"], at: at)
        }, observed: { first, last in journal.gateInvalidated(start: first, end: last) }, stop: { _ in stopped.signal() })
        Thread { relay.invoke(.stopped, origin: .button); finished.signal() }.start()
        #expect(stopped.wait(timeout: .now() + 1) == .success)
        #expect(observerEntered.wait(timeout: .now() + 1) == .success)
        #expect(finished.wait(timeout: .now() + 1) == .success)
        #expect(gate.isInvalidated && journal.failed)
        #expect(loss.wait(timeout: .now() + 1) == .success)
        #expect(!journal.emit("terminal", ["outcome": "complete", "reason": "complete"]))
        var discarded = [UInt8](repeating: 0, count: 4096)
        #expect(read(pipe[0], &discarded, discarded.count) > 0)
        #expect(!journal.emit("terminal", ["outcome": "complete", "reason": "complete"]))
    }
    @Test func lateAuthorityRegistrationAfterDiagnosticLossStopsImmediately() {
        let abort = ScreenRunnerDiagnosticAbort(), stopped = DispatchSemaphore(value: 0)
        abort.fail()
        abort.register { stopped.signal() }
        #expect(stopped.wait(timeout: .now() + 1) == .success)
    }
    @Test func oversizedRowFailsWithoutWritingOrAcceptingTerminal() throws {
        let pipe = try pipePair(); defer { close(pipe[0]); close(pipe[1]) }
        let cancelled = DispatchSemaphore(value: 0)
        let journal = try ScreenRunnerJournal(.activeStop, descriptor: pipe[1], authorityFailed: { cancelled.signal() })
        #expect(!journal.emit("test", ["oversize": String(repeating: "x", count: 5000)]))
        #expect(cancelled.wait(timeout: .now() + 1) == .success && journal.failed)
        #expect(!journal.emit("terminal", ["outcome": "complete"]))
        #expect(fcntl(pipe[0], F_SETFL, O_NONBLOCK) == 0)
        var byte: UInt8 = 0
        #expect(read(pipe[0], &byte, 1) == -1 && errno == EAGAIN)
    }
    @Test func timestampsRetainActualEventOrderSeparatelyFromSerializedEmission() throws {
        let pipe = try pipePair(); defer { close(pipe[0]); close(pipe[1]) }
        let journal = try ScreenRunnerJournal(.activeStop, descriptor: pipe[1], authorityFailed: { Issue.record("Unexpected diagnostic loss") })
        let earlier = journal.began, later = ContinuousClock.now
        #expect(journal.emit("later", at: later))
        #expect(journal.emit("earlier", at: earlier))
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = read(pipe[0], &bytes, bytes.count)
        #expect(count > 0)
        let rows = try Data(bytes.prefix(max(0, count))).split(separator: 10).map { try JSONSerialization.jsonObject(with: Data($0)) as! [String: Any] }
        try #require(rows.count == 2)
        let emission = rows.map { $0["elapsedMs"] as! Double }, events = rows.map { $0["eventElapsedMs"] as! Double }
        #expect(emission[1] >= emission[0] && events[0] >= events[1])
        #expect(zip(emission, events).allSatisfy { $0 >= $1 })
        #expect(!journal.failed)
    }
    @Test func regularFileOrReadEndCannotBecomeDiagnosticSink() throws {
        let pipe = try pipePair(); defer { close(pipe[0]); close(pipe[1]) }
        #expect(throws: ScreenFailure.incompatible) {
            _ = try ScreenRunnerJournal(.activeStop, descriptor: pipe[0], authorityFailed: {})
        }
        let descriptor = open("/dev/null", O_WRONLY | O_CLOEXEC)
        try #require(descriptor >= 0); defer { close(descriptor) }
        #expect(throws: ScreenFailure.incompatible) {
            _ = try ScreenRunnerJournal(.activeStop, descriptor: descriptor, authorityFailed: {})
        }
    }
}
#endif
