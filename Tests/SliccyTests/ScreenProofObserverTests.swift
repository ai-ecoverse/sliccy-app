#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenProofObserverTests {
    private let accepted = #"{"schema":1,"event":"native-screen-verification","seq":1,"stage":"check","lane":"safety","outcome":"accepted","tokenMatched":true,"pidAgreed":true,"uidAgreed":true,"lost":false}"#
    private let refused = #"{"schema":1,"event":"native-screen-verification","seq":2,"stage":"check","lane":"safety","outcome":"refused","tokenMatched":false,"pidAgreed":null,"uidAgreed":null,"lost":false}"#
    private let complete = #"{"schema":1,"event":"native-screen-verification","seq":3,"stage":"complete","tokenMatched":null,"pidAgreed":null,"uidAgreed":null,"lost":false}"#
    private func line(_ value: String) -> Data { Data((value + "\n").utf8) }

    @Test func chunkedStreamPreservesShortCircuitNullAndNeverForwardsFollowContent() throws {
        var filter = ScreenProofObserver(), rows: [ScreenProofReport] = []
        let input = line(#"{"schema":1,"event":"linked","private":"CONTENT-SENTINEL"}"#) + line(accepted) + line(refused) + line(complete)
        for byte in input { rows += try filter.feed(Data([byte])) }
        let finished1 = filter.finish(); #expect(finished1)
        #expect(rows.count == 3 && rows[0].acceptedSafety && rows[1].refusedSafety)
        #expect(rows[1].pidAgreed == nil && rows[1].uidAgreed == nil)
        let result = try JSONSerialization.data(withJSONObject: rows.map(\.metadata))
        #expect(!String(decoding: result, as: UTF8.self).contains("CONTENT-SENTINEL"))
    }
    @Test func gapsDuplicatesUnknownFieldsAndTypesAreInconclusive() throws {
        for malformed in [accepted.replacingOccurrences(of: #""seq":1"#, with: #""seq":2"#),
            accepted.replacingOccurrences(of: #""tokenMatched":true"#, with: #""tokenMatched":1"#),
            accepted.replacingOccurrences(of: #""lost":false"#, with: #""lost":false,"extra":"hidden""#),
            accepted.replacingOccurrences(of: #""schema":1"#, with: #""schema":1,"schema":1"#),
            accepted.replacingOccurrences(of: #""lane":"safety""#, with: #""lane":"other""#),
            accepted.replacingOccurrences(of: #""schema":1"#, with: #""schema":true"#)] {
            var filter = ScreenProofObserver()
            #expect(throws: (any Error).self) { try filter.feed(line(malformed)) }
            let finished2 = !filter.finish(); #expect(finished2)
        }
        var duplicate = ScreenProofObserver()
        _ = try duplicate.feed(line(accepted))
        #expect(throws: (any Error).self) { try duplicate.feed(line(accepted.replacingOccurrences(of: #""seq":1"#, with: #""seq":2"#))) }
        let finished3 = !duplicate.finish(); #expect(finished3)
    }
    @Test func missingCompleteLossPartialAndPostCompleteRowsCannotPass() throws {
        var missing = ScreenProofObserver(); _ = try missing.feed(line(accepted)); let finished4 = !missing.finish(); #expect(finished4)
        var loss = ScreenProofObserver()
        let lost = accepted.replacingOccurrences(of: #""lost":false"#, with: #""lost":true"#)
        let rows = try loss.feed(line(lost)); let finished5 = rows[0].lost && !rows[0].acceptedSafety && !loss.finish(); #expect(finished5)
        var partial = ScreenProofObserver(); _ = try partial.feed(Data(accepted.utf8)); let finished6 = !partial.finish(); #expect(finished6)
        var ended = ScreenProofObserver()
        _ = try ended.feed(line(accepted) + line(refused) + line(complete))
        #expect(throws: (any Error).self) { try ended.feed(line(complete.replacingOccurrences(of: #""seq":3"#, with: #""seq":4"#))) }
    }
    @Test func lineAndAggregateOutputRemainBounded() throws {
        var long = ScreenProofObserver()
        #expect(throws: (any Error).self) { try long.feed(Data(repeating: 65, count: 4097)) }
        var total = ScreenProofObserver()
        #expect(throws: (any Error).self) { try total.feed(Data(repeating: 10, count: 65537)) }
    }
    @Test func nullBaselineAndUnknownRefusalAreNotIdentityEvidence() throws {
        var filter = ScreenProofObserver()
        let baseline = accepted.replacingOccurrences(of: #""tokenMatched":true"#, with: #""tokenMatched":null"#)
        let mismatch = refused.replacingOccurrences(of: #""tokenMatched":false"#, with: #""tokenMatched":null"#)
        let rows = try filter.feed(line(baseline) + line(mismatch) + line(complete))
        let finished7 = filter.finish() && !rows[0].acceptedSafety && !rows[1].refusedSafety; #expect(finished7)
    }
}
#endif
