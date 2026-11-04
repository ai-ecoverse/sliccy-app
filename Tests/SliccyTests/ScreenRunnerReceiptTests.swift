#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerReceiptTests {
    final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var rows: [ScreenRunnerReceiptLedger.Delivery] = []
        private var failures = 0
        func write(_ row: ScreenRunnerReceiptLedger.Delivery) { lock.lock(); rows.append(row); lock.unlock() }
        func fail() { lock.lock(); failures += 1; lock.unlock() }
        var snapshot: [ScreenRunnerReceiptLedger.Delivery] { lock.lock(); defer { lock.unlock() }; return rows }
        var lost: Int { lock.lock(); defer { lock.unlock() }; return failures }
        func ledger() -> ScreenRunnerReceiptLedger { .init(output: { self.write($0) }, loss: { self.fail() }) }
    }
    func receipt() -> [String: Any] {
        ["role": "com.apple.WindowServer", "site": "system-owner", "passed": true, "step": "complete", "statuses": [[16, 0], [25, 0]],
         "compared": ["pid": 42, "start": ["123", 456], "hash": "fixed", "offset": "16384", "type": 2, "requirement": "fixed-rule", "status": 0]]
    }
    @Test func identicalReceiptsRetainExactCountsAndActualTimes() throws {
        let sink = Sink(), ledger = sink.ledger(), began = ContinuousClock.now, fields = receipt()
        ledger.record("code-binding", fields: fields, at: began)
        for index in 1...100 { ledger.record("code-binding", fields: fields, at: began.advanced(by: .milliseconds(index))) }
        #expect(sink.snapshot.count == 1)
        ledger.finish()
        #expect(sink.lost == 0)
        try #require(sink.snapshot.count == 2)
        #expect(sink.snapshot.map(\.count) == [1, 100])
        #expect(sink.snapshot[0].key == sink.snapshot[1].key)
        #expect(!sink.snapshot[0].aggregate && sink.snapshot[1].aggregate)
        #expect(sink.snapshot[1].journalFields.count == 2)
        #expect(sink.snapshot[0].journalFields["compared"] as? NSDictionary == fields["compared"] as? NSDictionary)
        #expect(sink.snapshot[1].first == began.advanced(by: .milliseconds(1)))
        #expect(sink.snapshot[1].last == began.advanced(by: .milliseconds(100)))
    }
    @Test func everyComparedChangeImmediatelyStartsAFullReceipt() {
        for key in ["pid", "start", "hash", "offset", "type", "requirement", "status"] {
            let sink = Sink(), ledger = sink.ledger(), at = ContinuousClock.now
            let original = receipt(); var changed = original, compared = original["compared"] as! [String: Any]
            compared[key] = "changed"; changed["compared"] = compared
            ledger.record("code-binding", fields: original, at: at)
            ledger.record("code-binding", fields: original, at: at)
            ledger.record("code-binding", fields: changed, at: at)
            #expect(sink.snapshot.last?.fields["compared"] as? NSDictionary == compared as NSDictionary)
            #expect(sink.snapshot.filter { ($0.fields["compared"] as? NSDictionary) == (compared as NSDictionary) }.count == 1)
            ledger.finish()
            #expect(sink.snapshot.reduce(0) { $0 + $1.count } == 3 && sink.lost == 0)
        }
        for key in ["role", "site", "statuses"] {
            let sink = Sink(), ledger = sink.ledger(), original = receipt()
            var changed = original; changed[key] = key == "statuses" ? [[16, 1], [25, 0]] as Any : "changed"
            ledger.record("code-binding", fields: original, at: .now)
            ledger.record("code-binding", fields: changed, at: .now)
            #expect(sink.snapshot.count == 2 && sink.lost == 0)
        }
    }
    @Test func failureFlushesEveryStreamAndCannotBeAggregated() {
        let sink = Sink(), ledger = sink.ledger(), fields = receipt()
        var other = fields; other["site"] = "other"
        for row in [fields, fields, other, other] { ledger.record("code-binding", fields: row, at: .now) }
        var failure = fields; failure["passed"] = false; failure["step"] = "refused"
        ledger.record("code-binding", fields: failure, at: .now)
        #expect(sink.snapshot.count == 5 && sink.snapshot.last?.fields["passed"] as? Bool == false)
        ledger.record("code-binding", fields: failure, at: .now)
        #expect(sink.snapshot.count == 6 && sink.snapshot.last?.count == 1)
        ledger.finish(); #expect(sink.snapshot.count == 6 && sink.lost == 0)
    }
    @Test func boundedRowsStreamsAndNumericBooleansRetireEvidence() {
        for failure in ["row", "streams", "boolean", "closed"] {
            let sink = Sink(), ledger = sink.ledger(); var fields = receipt()
            if failure == "row" { fields["extra"] = String(repeating: "x", count: 3585) }
            if failure == "boolean" { fields["passed"] = NSNumber(value: 1) }
            if failure == "closed" { ledger.finish() }
            if failure == "streams" {
                for index in 0..<256 { fields["site"] = String(index); ledger.record("code-binding", fields: fields, at: .now) }
                fields["site"] = "overflow"
            }
            ledger.record("code-binding", fields: fields, at: .now)
            #expect(sink.lost == 1)
        }
    }
    @Test func finalCutoffNeverWaitsForBlockedDelivery() {
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), ended = DispatchSemaphore(value: 0)
        let sink = Sink()
        let ledger = ScreenRunnerReceiptLedger(output: { _ in entered.signal(); _ = release.wait(timeout: .now() + 2) }, loss: { sink.fail() })
        Thread { ledger.record("code-binding", fields: ["role": "fixed", "site": "fixed", "passed": true], at: .now); ended.signal() }.start()
        #expect(entered.wait(timeout: .now() + 1) == .success)
        ledger.finish()
        #expect(sink.lost == 1)
        release.signal(); #expect(ended.wait(timeout: .now() + 1) == .success)
    }
    @Test func lossAndOutputRunAfterActualOwnerBoundaryUnlocks() throws {
        let owner = ScreenRunnerOwnerLock(), sink = Sink()
        let ledger = ScreenRunnerReceiptLedger(output: { row in
            if owner.testLiveness(until: Date(timeIntervalSinceNow: 0.2)) { sink.write(row) } else { sink.fail() }
        }, loss: {
            if owner.testLiveness(until: Date(timeIntervalSinceNow: 0.2)) { sink.fail() }
        })
        let value = ScreenRunnerSliceBinding.Evidence(role: "fixed", site: "fixed", at: .now, passed: false, step: "refused", selected: nil, statuses: [])
        owner.withEvidence(output: { _, _ in }, sliceOutput: { ledger.record("code-binding", fields: $0.fields, at: $0.at) }, loss: { sink.fail() }) { batch in
            batch.collectSlice(value)
        }
        #expect(sink.snapshot.count == 1 && sink.lost == 0)
    }
}
#endif
