#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerClosureTests {
    private func completed(_ request: String, in ledger: inout ScreenProofReverseReplies) {
        ledger.record(.received, request: request, invalidation: (.now, .now))
        ledger.record(.enqueued, request: request)
        ledger.record(.written, request: request)
    }
    @Test func lateReverseDuringCaptureStopCannotUseEarlierCompleteDecision() {
        var ledger = ScreenProofReverseReplies()
        completed("initial", in: &ledger)
        #expect(ledger.complete)
        _ = ledger.drain()
        ledger.record(.received, request: "during-sdk-await", invalidation: (.now, .now))
        ledger.record(.enqueued, request: "during-sdk-await")
        ledger.beginCutoff(transportWasOpen: true, readInFlight: false)
        let snapshot = ledger.closedSnapshot(workersSettled: true)
        #expect(!snapshot.succeeded && snapshot.pending == 1 && snapshot.cutoff.pending == 1)
        #expect(snapshot.notices.map(\.stage) == [.received, .enqueued])
        #expect(snapshot.notices.map(\.ordinal) == [2, 2])
    }
    @Test func successfulWriteReportedAfterCutoffDoesNotHideCutOffPendingReply() {
        var ledger = ScreenProofReverseReplies()
        completed("initial", in: &ledger)
        #expect(ledger.complete)
        _ = ledger.drain()
        ledger.record(.received, request: "late", invalidation: (.now, .now))
        ledger.record(.enqueued, request: "late")
        ledger.beginCutoff(transportWasOpen: true, readInFlight: false)
        ledger.record(.written, request: "late")
        let snapshot = ledger.closedSnapshot(workersSettled: true)
        #expect(snapshot.pending == 0 && snapshot.written == 2 && snapshot.cutoff.pending == 1)
        #expect(snapshot.notices.map(\.stage) == [.received, .enqueued, .written])
        #expect(!snapshot.succeeded)
    }
    @Test func lateReplyActuallyWrittenBeforeCutoffIsIncludedAndCanComplete() {
        var ledger = ScreenProofReverseReplies()
        completed("initial", in: &ledger)
        _ = ledger.drain()
        completed("late", in: &ledger)
        ledger.beginCutoff(transportWasOpen: true, readInFlight: false)
        let snapshot = ledger.closedSnapshot(workersSettled: true)
        #expect(snapshot.succeeded && snapshot.requests == 2 && snapshot.written == 2)
        #expect(snapshot.notices.map(\.stage) == [.received, .enqueued, .written])
        #expect(snapshot.notices.map(\.ordinal) == [2, 2, 2])
    }
    @Test func inFlightReadUnsettledWriterPriorFaultOrUnknownCutoffRefusesCompletion() {
        for mode in 0..<4 {
            var ledger = ScreenProofReverseReplies()
            completed("initial", in: &ledger)
            if mode != 3 { ledger.beginCutoff(transportWasOpen: mode != 2, readInFlight: mode == 0) }
            let snapshot = ledger.closedSnapshot(workersSettled: mode != 1)
            #expect(!snapshot.succeeded)
        }
    }
    @Test func postCutoffReadInvalidatesButActualPriorWriteStillGetsReported() {
        var ledger = ScreenProofReverseReplies()
        ledger.record(.received, request: "late", invalidation: (.now, .now))
        ledger.record(.enqueued, request: "late")
        ledger.beginCutoff(transportWasOpen: true, readInFlight: false)
        ledger.invalidate()
        ledger.record(.written, request: "late")
        let snapshot = ledger.closedSnapshot(workersSettled: true)
        #expect(snapshot.invalid && !snapshot.succeeded)
        #expect(snapshot.notices.last?.stage == .written && snapshot.written == 1)
    }
    @Test func everyOwnerRequiresCompleteNonduplicatedCGAndSCKSets() throws {
        try ScreenRunnerWindowSets.requireComplete(cg: [2, 1], sck: [1, 2])
        for (cg, sck): ([UInt32?], [UInt32]) in [([1, 2], [1]), ([1], [1, 2]), ([1, nil], [1]), ([1, 1], [1]), ([1], [1, 1]), ([0], [0]), ([1, 2], [1, 3])] {
            #expect(throws: ScreenFailure.protection) { try ScreenRunnerWindowSets.requireComplete(cg: cg, sck: sck) }
        }
    }
}
#endif
