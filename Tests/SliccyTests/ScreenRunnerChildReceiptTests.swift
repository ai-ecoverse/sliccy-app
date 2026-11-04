#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerChildReceiptTests {
    final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [ScreenRunnerSliceBinding.Evidence] = []
        private var failures = 0
        func record(_ value: ScreenRunnerSliceBinding.Evidence) { lock.lock(); values.append(value); lock.unlock() }
        func fail() { lock.lock(); failures += 1; lock.unlock() }
        var rows: [ScreenRunnerSliceBinding.Evidence] { lock.lock(); defer { lock.unlock() }; return values }
        var lost: Int { lock.lock(); defer { lock.unlock() }; return failures }
        var receipts: ScreenRunnerChildReceipts { .init(record: { self.record($0) }, lost: { self.fail() }) }
    }
    func sample() -> ScreenRunnerProcessSample { .init(pid: 42, parent: 7, uid: 501, seconds: 123, microseconds: 456) }
    func trace(_ failure: String? = nil) -> ScreenRunnerSecurityTrace {
        .init(executable: URL(fileURLWithPath: "/fixed/slicc"), failure: failure, identifier: "ai.sliccy.slicc")
    }
    @Test func actualCLICaptureDeliversSuccessAndRefusalReceipts() throws {
        for failure in ["none", "hash", "sample", "dynamic"] {
            let sink = Sink(), calls = trace(failure), value = sample()
            let capture = {
                try ScreenRunnerChildChecks.capture(pid: 42, hash: calls.hash, receipts: sink.receipts, calls: calls.calls,
                    read: { _ in if failure == "sample" { throw ScreenFailure.peerLost }; return value }, parent: 7, uid: 501)
            }
            if failure == "none" { #expect(try capture().sample == value) }
            else { #expect(throws: (any Error).self) { try capture() } }
            #expect(sink.lost == 0)
            #expect(sink.rows.last?.site == "child-initial")
            #expect(sink.rows.last?.passed == (failure == "none"))
            #expect(sink.rows.allSatisfy { $0.role == "ai.sliccy.slicc" })
            if ["none", "hash"].contains(failure) {
                #expect(sink.rows.contains { $0.site == "initial-live" && $0.passed == (failure == "none") })
            }
        }
    }
    @Test func actualCLISignalDeliversAfterUnlockOnSuccessAndRefusal() throws {
        for failure in ["none", "hash", "sample", "dynamic", "send", "missing"] {
            let sink = Sink(), calls = trace(failure), value = sample(), owner = ScreenRunnerOwnerLock()
            let identity = ScreenRunnerProcessIdentity(sample: value, role: .cli, hash: calls.hash)
            let receipts = ScreenRunnerChildReceipts(record: { evidence in
                if owner.testLiveness(until: Date(timeIntervalSinceNow: 0.2)) { sink.record(evidence) } else { sink.fail() }
            }, lost: { sink.fail() })
            var sends = 0
            let accepted = ScreenRunnerChildChecks.signalUnderLock(owner, receipts: receipts) { batch in
                ScreenRunnerChildChecks.signal(15, pid: 42, identity: failure == "missing" ? nil : identity, reaped: false,
                    batch: batch, calls: calls.calls, read: { if failure == "sample" { throw ScreenFailure.peerLost }; return value },
                    send: { _, _ in sends += 1; return failure == "send" ? -1 : 0 })
            }
            #expect(accepted == (failure == "none"))
            #expect(sends == (["none", "send"].contains(failure) ? 1 : 0))
            #expect(sink.lost == 0)
            #expect(sink.rows.last?.site == "child-signal")
            #expect(sink.rows.last?.passed == (failure == "none"))
            if ["none", "hash", "send"].contains(failure) {
                #expect(sink.rows.contains { $0.site == "signal" && $0.passed == (failure != "hash") })
            }
        }
    }
    @Test func actualCLIOverflowRetiresAfterUnlockWithoutPartialDelivery() {
        let sink = Sink(), owner = ScreenRunnerOwnerLock()
        let receipts = ScreenRunnerChildReceipts(record: { sink.record($0) }, lost: {
            if owner.testLiveness(until: Date(timeIntervalSinceNow: 0.2)) { sink.fail() }
        })
        _ = ScreenRunnerChildChecks.signalUnderLock(owner, receipts: receipts) { batch in
            for _ in 0..<5 { batch.collectSlice(ScreenRunnerChildChecks.boundary(pid: 42, identity: nil, signal: 15, passed: false)) }
            return false
        }
        #expect(sink.lost == 1 && sink.rows.isEmpty)
    }
}
#endif
