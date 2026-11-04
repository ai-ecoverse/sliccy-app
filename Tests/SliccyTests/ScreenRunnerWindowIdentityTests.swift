#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerWindowIdentityTests {
    private let rect = CGRect(x: 416, y: 64, width: 288, height: 224)
    @Test func titlesCannotSelectOrRejectAnOtherwiseUniqueOwnedWindow() throws {
        for title in [nil, "expected", "conflicting"] as [String?] {
            let candidate = ScreenRunnerWindowSets.Candidate(id: 7, pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0, diagnosticTitle: title)
            #expect(try ScreenRunnerWindowSets.unique([candidate], pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0) == 7)
        }
    }
    @Test func wrongPIDRoleBoundsLayerOrMissingWindowNeverMatches() {
        for candidate in [
            ScreenRunnerWindowSets.Candidate(id: 7, pid: 13, bundle: "com.google.Chrome", rect: rect, layer: 0),
            .init(id: 7, pid: 12, bundle: "", rect: rect, layer: 0),
            .init(id: 7, pid: 12, bundle: "ai.sliccy.mac", rect: rect, layer: 0),
            .init(id: 7, pid: 12, bundle: "com.google.Chrome", rect: rect.offsetBy(dx: 1, dy: 0), layer: 0),
            .init(id: 7, pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 1),
            .init(id: 0, pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0)] {
            #expect(throws: ScreenRunnerInventoryIssue.windowIdentity) {
                try ScreenRunnerWindowSets.unique([candidate], pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0)
            }
        }
        #expect(throws: ScreenRunnerInventoryIssue.windowIdentity) {
            try ScreenRunnerWindowSets.unique([], pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0)
        }
    }
    @Test func ambiguousOwnerGeometryAndDuplicateIDsRefuse() throws {
        let first = ScreenRunnerWindowSets.Candidate(id: 7, pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0)
        let second = ScreenRunnerWindowSets.Candidate(id: 8, pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0)
        #expect(throws: ScreenRunnerInventoryIssue.windowIdentity) {
            try ScreenRunnerWindowSets.unique([first, second], pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 0)
        }
        for candidates in [[first, first], [first, second], [first, .init(id: 8, pid: 12, bundle: "com.google.Chrome", rect: rect, layer: 1)]] {
            #expect(throws: ScreenRunnerInventoryIssue.windowIdentity) { try ScreenRunnerWindowSets.requireUnambiguous(candidates) }
        }
        try ScreenRunnerWindowSets.requireUnambiguous([first])
    }
    @Test func completenessNeverIgnoresAnExtraCGOrSCKWindow() {
        for (cg, sck) in [([UInt32?(7), 8], [UInt32(7)]), ([UInt32?(7)], [UInt32(7), 8]), ([UInt32?(7), nil], [UInt32(7)]), ([UInt32?(7), 7], [UInt32(7)])] {
            #expect(throws: ScreenFailure.protection) { try ScreenRunnerWindowSets.requireComplete(cg: cg, sck: sck) }
        }
    }
}
#endif
