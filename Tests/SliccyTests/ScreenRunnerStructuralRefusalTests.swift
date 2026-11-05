#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
import Darwin
@testable import Sliccy

struct ScreenRunnerStructuralRefusalTests {
    typealias B = ScreenRunnerInventoryBoundary
    typealias F = ScreenRunnerInventoryBoundaryTests.Fixture
    static func fixture(_ bundle: String = "com.apple.WindowServer") -> F {
        var value = F(.selectedWindow)
        value.add(id: 50, pid: 50, bundle: bundle, apple: true)
        value.sck = value.sck.map { .init(id: $0.id, pid: $0.pid, bundle: $0.pid == 50 ? "" : $0.bundle, rect: $0.rect, layer: $0.layer) }
        return value
    }
    @Test func actualBoundaryWitnessesOnlyPairedVerifiedWindowServer() throws {
        let positive = Self.fixture()
        var accepted: B.Validated?
        do { accepted = try positive.read() }
        catch { #expect(Bool(false), "structural-windowserver-positive") }
        guard let inventory = accepted else { return }
        #expect(inventory.windowServerEmptyBundle != nil, "structural-windowserver-positive")
        let witness = try #require(inventory.windowServerEmptyBundle)
        #expect(witness.owner == positive.owners[50] && witness.pairs.count == 1)
        #expect(throws: ScreenFailure.protection) { try inventory.requireSelection([50]) }
        var ordinary = positive
        ordinary.sck = ordinary.sck.map { .init(id: $0.id, pid: $0.pid, bundle: $0.pid == 50 ? "com.apple.WindowServer" : $0.bundle, rect: $0.rect, layer: $0.layer) }
        #expect(try ordinary.read().windowServerEmptyBundle == nil)
        #expect(try ordinary.read().fingerprint != inventory.fingerprint, "structural-raw-bundle-fingerprint")
        for field in ["role", "apple", "verified", "sysctl", "parent", "effective", "real", "saved", "start", "fraction"] {
            var negative = positive
            let old = try #require(negative.owners[50])
            negative.owners[50] = .init(pid: old.pid, parent: field == "parent" ? 2 : old.parent,
                uid: field == "effective" ? 0 : old.uid, seconds: field == "start" ? 0 : old.seconds,
                microseconds: field == "fraction" ? 1_000_000 : old.microseconds,
                identifier: field == "role" ? "com.apple.dock" : old.identifier, path: old.path, hash: old.hash,
                appleAnchored: field != "apple", verified: field != "verified", sysctlBound: field != "sysctl",
                realUID: field == "real" ? 88 : 0, savedUID: field == "saved" ? 88 : 0)
            #expect(throws: (any Error).self, "structural-exact-role-and-identity") { try negative.read() }
        }
        for role in ["com.apple.SecurityAgent", "com.apple.finder", "com.apple.WindowManager"] {
            #expect(throws: (any Error).self, "structural-other-role-refused") { try Self.fixture(role).read() }
        }
    }
    @Test func actualBoundaryRequiresCompleteUnambiguousPairs() throws {
        let positive = Self.fixture()
        #expect(try positive.read().windowServerEmptyBundle != nil)
        for field in ["missing-cg", "pid", "id", "rect", "layer", "whitespace", "wrong-bundle", "mixed", "duplicate"] {
            var negative = positive
            let old = try #require(negative.sck.first { $0.pid == 50 })
            if field == "missing-cg" { negative.cg.removeAll { $0.pid == 50 } }
            else if field == "mixed" {
                negative.add(id: 51, pid: 50, bundle: "com.apple.WindowServer", rect: CGRect(x: 400, y: 500, width: 100, height: 100), apple: true)
            } else if field == "duplicate" { negative.sck.append(old) }
            else {
                negative.sck.removeAll { $0.pid == 50 }
                negative.sck.append(.init(id: field == "id" ? 51 : old.id, pid: field == "pid" ? 30 : old.pid,
                    bundle: field == "whitespace" ? " " : field == "wrong-bundle" ? "com.apple.finder" : old.bundle,
                    rect: field == "rect" ? CGRect(x: 1, y: 1, width: 10, height: 10) : old.rect,
                    layer: field == "layer" ? 1 : old.layer))
            }
            #expect(throws: (any Error).self, "structural-complete-pairs") { try negative.read() }
        }
        var titled = positive
        for index in titled.sck.indices { titled.sck[index].diagnosticTitle = "not identity" }
        #expect(try titled.read().fingerprint == positive.read().fingerprint)
    }
    @Test func actualProbeBoundaryMatchesWholeWitnessAndCallsEveryBuilder() throws {
        let fixture = Self.fixture()
        let witness = try #require(fixture.read().windowServerEmptyBundle)
        let records = fixture.sck.filter { $0.pid == 50 }
        var displayCalls = 0, windowCalls: [UInt32] = [], receipts: [ScreenProofProtectedProbe.Refusal] = []
        try ScreenProofProtectedProbe.requireStructuralRefusals(witness: witness, identity: witness.owner,
            label: .windowServer, pid: 50, bundle: "", windows: records,
            display: { displayCalls += 1; throw ScreenFailure.protection },
            window: { windowCalls.append($0); throw ScreenFailure.protection }, refused: { receipts.append($0) })
        #expect(displayCalls == 1 && windowCalls == [50], "structural-actual-builder-calls")
        #expect(receipts.count == 2 && receipts.allSatisfy { !$0.predicateEvidence && $0.structural != nil }, "structural-never-predicate")
        for field in ["identity", "label", "pid", "bundle", "missing", "extra", "duplicate", "rect", "layer"] {
            var windows = records
            let old = records[0]
            if field == "missing" { windows = [] }
            if field == "extra" { windows.append(.init(id: 51, pid: 50, bundle: "", rect: old.rect, layer: old.layer)) }
            if field == "duplicate" { windows.append(old) }
            if field == "rect" || field == "layer" { windows = [.init(id: old.id, pid: old.pid, bundle: "", rect: field == "rect" ? .zero : old.rect, layer: field == "layer" ? 1 : old.layer)] }
            let stale = F.owner(50, bundle: "com.apple.WindowServer", apple: true, seconds: witness.owner.seconds + 1)
            #expect(throws: ScreenProofProtectedProbe.Failure.unresolvedOwner, "structural-witness-target") {
                try ScreenProofProtectedProbe.requireStructuralRefusals(witness: witness, identity: field == "identity" ? stale : witness.owner,
                    label: field == "label" ? .dock : .windowServer, pid: field == "pid" ? 51 : 50,
                    bundle: field == "bundle" ? "com.apple.WindowServer" : "", windows: windows,
                    display: { throw ScreenFailure.protection }, window: { _ in throw ScreenFailure.protection }, refused: { _ in })
            }
        }
    }
    @Test func actualProbeRejectsWrongErrorAcceptanceAndConstruction() throws {
        let witness = try #require(Self.fixture().read().windowServerEmptyBundle)
        for fault in ["success", "wrong-error", "constructed"] {
            let expected: ScreenProofProtectedProbe.Failure = fault == "success" ? .unexpectedlyAccepted : fault == "wrong-error" ? .wrongRefusal : .constructionReached
            #expect(throws: expected, "structural-requires-real-preconstruction-refusal") {
                try ScreenProofProtectedProbe.requireStructuralRefusals(witness: witness, identity: witness.owner,
                    label: .windowServer, pid: 50, bundle: "", windows: witness.pairs.map(\.sck), display: {
                        if fault == "success" { return }
                        if fault == "constructed" { ScreenProofFilterConstruction.reached(); throw ScreenFailure.protection }
                        throw ScreenFailure.peerLost
                    }, window: { _ in throw ScreenFailure.protection }, refused: { _ in })
            }
        }
    }
    @Test func actualStructuralEncoderKeepsTypedUnionAndMaximumRowBound() throws {
        var fixture = Self.fixture()
        fixture.cg.removeAll { $0.pid == 50 }; fixture.sck.removeAll { $0.pid == 50 }
        for index in 0..<64 {
            let id = UInt32.max - UInt32(index)
            let rect = CGRect(x: Double(index), y: 0, width: 1, height: 1)
            fixture.cg.append(.init(id: id, pid: 50, rect: rect, layer: Int(Int32.min)))
            fixture.sck.append(.init(id: id, pid: 50, bundle: "", rect: rect, layer: Int(Int32.min)))
        }
        let witness = try #require(fixture.read().windowServerEmptyBundle)
        let display = ScreenRunnerStructuralRefusal(witness: witness, windowID: nil).fields
        #expect(display["predicateEvidence"] as? Bool == false && display["rawSCKBundleEmpty"] as? Bool == true, "structural-encoder-false-predicate")
        #expect(display["reason"] as? String == "verified-windowserver-empty-sck-bundle")
        #expect(display["windowID"] == nil && (display["pairedWindowIDs"] as? [UInt32]) == witness.pairs.map { $0.sck.id })
        let data = try JSONSerialization.data(withJSONObject: display, options: [.sortedKeys])
        #expect(data.count + 512 < 4096, "structural-max-row")
        let window = ScreenRunnerStructuralRefusal(witness: witness, windowID: UInt32.max).fields
        #expect(window["pairedWindowIDs"] == nil && window["windowID"] as? UInt32 == UInt32.max)
        var descriptors: [Int32] = [-1, -1]
        try #require(pipe(&descriptors) == 0)
        defer { close(descriptors[0]); close(descriptors[1]) }
        let journal = try ScreenRunnerJournal(.selectedWindow, descriptor: descriptors[1], authorityFailed: {})
        #expect(journal.emit("protected-structural-refused", display), "structural-actual-journal-row")
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = read(descriptors[0], &bytes, bytes.count)
        try #require(count > 0)
        let actual = try JSONSerialization.jsonObject(with: Data(bytes.prefix(count))) as! [String: Any]
        #expect(actual["stage"] as? String == "protected-structural-refused" && count <= 4096)
        #expect((actual["pairedWindowIDs"] as? [UInt32])?.count == 64)

    }
}
#endif
