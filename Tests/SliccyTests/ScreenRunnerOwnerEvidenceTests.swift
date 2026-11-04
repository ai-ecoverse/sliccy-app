#if SLICCY_CAPTURE_RUNNER_PROOF && DEBUG
import Darwin
import Foundation
import Security
import Testing
@testable import Sliccy

private final class ScreenRunnerEvidenceTestResult: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Bool?
    func set(_ value: Bool) { lock.lock(); result = value; lock.unlock() }
    var value: Bool? { lock.lock(); defer { lock.unlock() }; return result }
}

struct ScreenRunnerOwnerEvidenceTests {
    private func fullPipe(_ descriptor: Int32) throws {
        let bytes = [UInt8](repeating: 120, count: 512)
        for _ in 0..<2048 {
            let count = bytes.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
            if count < 0, errno == EAGAIN || errno == EWOULDBLOCK { return }
            guard count == bytes.count else { throw ScreenFailure.incompatible }
        }
        throw ScreenFailure.resourceLimit
    }
    @Test func fullJournalAndConcurrentHealthCannotRetainOwnerLockDuringAbort() throws {
        var fds: [Int32] = [-1, -1]
        try #require(pipe(&fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        let owner = ScreenRunnerOwnerLock(), connection = ScreenRunnerConnection(event: { _ in })
        let gate = ScreenOutputGate(), abort = ScreenRunnerDiagnosticAbort()
        let stopped = DispatchSemaphore(value: 0), ownerEntered = DispatchSemaphore(value: 0), healthEntered = DispatchSemaphore(value: 0)
        let ownerFinished = DispatchSemaphore(value: 0), healthFinished = DispatchSemaphore(value: 0)
        let liveness = ScreenRunnerEvidenceTestResult(), synchronization = ScreenRunnerEvidenceTestResult()
        abort.register { gate.invalidate(); connection.abortDiagnostic(); stopped.signal() }
        let journal = try ScreenRunnerJournal(.activeStop, descriptor: fds[1], authorityFailed: { abort.fail() })
        try fullPipe(fds[1])
        let verification = Thread {
            owner.withEvidence(output: { phase, evidence in
                var fields = evidence.fields; fields["phase"] = phase
                journal.emit("chrome-identity", fields, at: evidence.observedAt)
            }, loss: { journal.rejectEvidence() }) { batch in
                batch.collect("live", .init(identityStatus: errSecSuccess, strictStatus: errSecCSInvalidAssociatedFileData, guestStatus: errSecSuccess))
                ownerEntered.signal()
                synchronization.set(healthEntered.wait(timeout: .now() + 1) == .success)
            }
            ownerFinished.signal()
        }
        let health = Thread {
            let result = connection.health.testOwnerCheck {
                healthEntered.signal()
                return owner.testLiveness(until: Date().addingTimeInterval(0.5))
            }
            liveness.set(result); healthFinished.signal()
        }
        verification.start()
        try #require(ownerEntered.wait(timeout: .now() + 1) == .success)
        health.start()
        #expect(healthFinished.wait(timeout: .now() + 2) == .success)
        #expect(ownerFinished.wait(timeout: .now() + 2) == .success)
        #expect(stopped.wait(timeout: .now() + 1) == .success)
        #expect(synchronization.value == true && liveness.value == true)
        #expect(gate.isInvalidated && journal.failed && !connection.health.check())
    }
    @Test func thrownVerificationStillDeliversAfterUnlockWithOriginalClock() {
        let owner = ScreenRunnerOwnerLock(), result = ScreenRunnerEvidenceTestResult()
        let evidence = ScreenRunnerChromePolicy.Evidence(identityStatus: errSecCSReqFailed, strictStatus: errSecCSInvalidAssociatedFileData, guestStatus: errSecSuccess)
        #expect(throws: ScreenFailure.peerUntrusted) {
            try owner.withEvidence(output: { phase, received in
                result.set(owner.testLiveness(until: Date().addingTimeInterval(0.1)) && phase == "live" && received.observedAt == evidence.observedAt)
            }, loss: { result.set(false) }) { batch in
                batch.collect("live", evidence)
                throw ScreenFailure.peerUntrusted
            }
        }
        #expect(result.value == true)
    }
    @Test func boundedBatchLossInvalidatesAfterUnlockWithoutDeliveringPartialSuccess() {
        let owner = ScreenRunnerOwnerLock(), result = ScreenRunnerEvidenceTestResult()
        let gate = ScreenOutputGate(), delivered = DispatchSemaphore(value: 0)
        owner.withEvidence(output: { _, _ in delivered.signal() }, loss: {
            gate.invalidate()
            result.set(owner.testLiveness(until: Date().addingTimeInterval(0.1)))
        }) { batch in
            for _ in 0..<5 { batch.collect("signal", .init(identityStatus: 0, strictStatus: 0, guestStatus: 0)) }
        }
        #expect(result.value == true && gate.isInvalidated)
        #expect(delivered.wait(timeout: .now()) == .timedOut)
    }
}
#endif
