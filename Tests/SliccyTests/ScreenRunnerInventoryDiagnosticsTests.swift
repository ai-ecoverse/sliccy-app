#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
import Darwin
@testable import Sliccy

struct ScreenRunnerInventoryDiagnosticsTests {
    typealias D = ScreenRunnerInventoryDiagnostics
    typealias B = ScreenRunnerInventoryBoundary
    typealias Fixture = ScreenRunnerInventoryBoundaryTests.Fixture
    final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [D.Notice] = []
        func append(_ value: D.Notice) { lock.lock(); values.append(value); lock.unlock() }
        var rows: [D.Notice] { lock.lock(); defer { lock.unlock() }; return values }
    }
    @Test func realBoundaryNamesBundleBoundsLayerAndPIDRefusals() throws {
        for field in ["bundle", "rect", "layer", "pid"] {
            var f = Fixture(.selectedWindow)
            let window = f.sck.first { $0.pid == 30 }!
            f.sck.removeAll { $0.id == window.id }
            if field == "pid" { f.owners[31] = Fixture.owner(31, bundle: "com.apple.dock", apple: true) }
            f.sck.append(.init(id: window.id, pid: field == "pid" ? 31 : window.pid,
                bundle: field == "bundle" ? "com.apple.finder" : window.bundle,
                rect: field == "rect" ? window.rect.offsetBy(dx: 1, dy: 0) : window.rect,
                layer: field == "layer" ? 1 : window.layer, diagnosticTitle: "PRIVATE-TITLE-SENTINEL"))
            let sink = Sink(), diagnostics = D(output: { sink.append($0) }), attempt = diagnostics.begin(.initial)
            #expect(throws: ScreenRunnerInventoryIssue.ownerAttribution) { try f.read(diagnostics: attempt) }
            let row = try #require(sink.rows.first)
            #expect(sink.rows.count == 1)
            #expect(row.pid == 30 && row.windowID == window.id)
            #expect(row.branch == (field == "bundle" ? .bundlePair : field == "pid" ? .pidPair : .geometryPair))
            #expect(row.comparison == (field == "bundle" ? .bundle : field == "pid" ? .sckPID : field == "rect" ? .rect : .layer))
            #expect(row.cg.count == 1 && row.sck.count == 1)
            #expect(row.sck[0].bundle == (field == "bundle" ? "com.apple.finder" : "com.apple.dock"))
            let encoded = try JSONSerialization.data(withJSONObject: row.fields, options: [.sortedKeys])
            #expect(!String(decoding: encoded, as: UTF8.self).contains("PRIVATE-TITLE-SENTINEL"))
        }
    }
    @Test func actualSCKConstructorRetainsNilOwnerAndPairedCGFacts() throws {
        let sink = Sink(), diagnostics = D(output: { sink.append($0) })
        let rect = CGRect(x: 1, y: 2, width: 300, height: 200)
        let cg: [B.CGRecord] = [.init(id: 41, pid: 99, rect: rect, layer: 1000)]
        #expect(throws: ScreenRunnerInventoryIssue.ownerAttribution) {
            try B.sckRecord(id: 41, pid: nil, bundle: nil, rect: rect, layer: 1000, diagnosticTitle: "SECRET", cg: cg, diagnostics: diagnostics.begin(.initial))
        }
        let row = try #require(sink.rows.first)
        #expect(row.branch == .sckOwner && row.comparison == .present && row.windowID == 41)
        #expect(row.sck.first != nil)
        guard let firstSCK = row.sck.first else { return }
        #expect(row.cg == cg && firstSCK.pid == nil && firstSCK.bundle == nil)
        let fields = row.fields, sck = try #require((fields["sck"] as? [[String: Any]])?.first)
        #expect(sck["ownerPresent"] as? Bool == false && sck["pid"] is NSNull)
        let result = try B.sckRecord(id: 41, pid: 99, bundle: "com.apple.finder", rect: rect, layer: 1000, diagnosticTitle: "SECRET", cg: cg, diagnostics: diagnostics.begin(.refresh))
        #expect(result.pid == 99 && sink.rows.count == 1)
    }
    @Test func actualOwnerRefusalsKeepPIDBranchAndOriginalThrownError() throws {
        let sink = Sink(), diagnostics = D(output: { sink.append($0) })
        let cg: [B.CGRecord] = [.init(id: 8, pid: 42, rect: CGRect(x: 1, y: 2, width: 3, height: 4), layer: 0)]
        let attempt = diagnostics.begin(.initial)
        #expect(throws: ScreenRunnerInventoryIssue.ownerAttribution) {
            try attempt.observe(.ownerIdentifier, pid: 42, cg: cg) { throw ScreenRunnerInventoryIssue.ownerAttribution }
        }
        attempt.reject(.unknown, .operation)
        #expect(sink.rows.count == 1 && sink.rows[0].pid == 42 && sink.rows[0].cg == cg && sink.rows[0].branch == .ownerIdentifier)
        var f = Fixture(.selectedWindow)
        let old = f.owners[30]!
        f.owners[30] = .init(pid: old.pid, parent: old.parent, uid: old.uid, seconds: 0, microseconds: old.microseconds, identifier: old.identifier, path: old.path, hash: old.hash, appleAnchored: old.appleAnchored, verified: old.verified, sysctlBound: old.sysctlBound)
        #expect(throws: ScreenRunnerInventoryIssue.ownerAttribution) { try f.read(diagnostics: diagnostics.begin(.initial)) }
        #expect(sink.rows[1].branch == .ownerFields && sink.rows[1].comparison == .startSeconds && sink.rows[1].pid == 30)
    }
    @Test func eachOwnerFieldRefusalNamesTheActualComparison() throws {
        for field in ["pid", "verified", "start-seconds", "start-microseconds", "identifier", "absolute-path", "hash-length"] {
            var fixture = Fixture(.selectedWindow)
            let old = fixture.owners[30]!
            fixture.owners[30] = .init(pid: field == "pid" ? 31 : old.pid, parent: old.parent, uid: old.uid,
                seconds: field == "start-seconds" ? 0 : old.seconds, microseconds: field == "start-microseconds" ? 1_000_000 : old.microseconds,
                identifier: field == "identifier" ? "" : old.identifier, path: field == "absolute-path" ? "relative" : old.path,
                hash: field == "hash-length" ? Data() : old.hash, appleAnchored: old.appleAnchored,
                verified: field == "verified" ? false : old.verified, sysctlBound: old.sysctlBound)
            let sink = Sink(), diagnostics = D { sink.append($0) }
            #expect(throws: ScreenRunnerInventoryIssue.ownerAttribution) { try fixture.read(diagnostics: diagnostics.begin(.initial)) }
            let row = try #require(sink.rows.first)
            #expect(row.branch == .ownerFields && row.comparison.rawValue == field && row.pid == 30)
            #expect(row.cg.count == 1 && row.sck.count == 1)
            #expect(row.fields["signingIdentifierSource"] as? String == (field == "verified" ? "tentative" : "verified"))
        }
    }
    @Test func actualEncoderRetainsBoundedPairedFactsAndIdentifierProvenance() throws {
        var descriptors: [Int32] = [0, 0]
        #expect(pipe(&descriptors) == 0)
        defer { close(descriptors[0]); close(descriptors[1]) }
        #expect(fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0)
        let journal = try ScreenRunnerJournal(.selectedWindow, descriptor: descriptors[1], authorityFailed: {})
        let diagnostics = D { notice in journal.emit("inventory-refusal", notice.fields, at: notice.at) }
        let identifier = "a." + String(repeating: "b", count: 253)
        let rect = CGRect(x: -1, y: 2, width: 3, height: 4)
        let cg: [B.CGRecord] = (1...3).map { .init(id: UInt32($0), pid: 42, rect: rect, layer: 1000) }
        var transcript = Data()
        for mode in 0...5 {
            let owner: B.Identity? = mode < 2 ? nil : .init(pid: 42, parent: 1, uid: 88, seconds: 123, microseconds: 999_999,
                identifier: identifier, path: "/PRIVATE-PATH", hash: Data(repeating: 1, count: 20),
                appleAnchored: mode % 2 == 0, verified: mode % 2 == 0, sysctlBound: mode % 2 == 0,
                realUID: mode % 2 == 0 ? 0 : nil, savedUID: mode % 2 == 0 ? 0 : nil)
            let observed = mode == 0 ? nil : identifier
            let observedRect = mode == 4 ? CGRect(x: 1, y: 2, width: -3, height: 4) : mode == 5 ? CGRect(x: Double.infinity, y: 0, width: 0, height: -1) : rect
            let sck: [D.SCKFact] = (1...3).map { .init(id: UInt32($0), pid: mode == 0 ? nil : 42,
                bundle: mode == 0 ? nil : mode == 5 ? "com.apple/PRIVATE-CONTENT" : identifier, rect: observedRect, layer: 1000) }
            diagnostics.begin(.initial).reject(.ownerAttribution, .bundlePair, pid: 42, windowID: mode == 0 ? nil : 1,
                signingIdentifier: observed, cg: cg, sck: sck, owner: owner, checks: [(.bundle, false)])
            var bytes = [UInt8](repeating: 0, count: 4096)
            let count = read(descriptors[0], &bytes, bytes.count)
            #expect(count > 0 && count <= 3072)
            let data = Data(bytes.prefix(max(0, count)))
            transcript.append(data)
            let row = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
            #expect(row["cgCount"] as? Int == 3 && row["sckCount"] as? Int == 3)
            #expect((row["cg"] as? [[String: Any]])?.count == 2 && (row["sck"] as? [[String: Any]])?.count == 2)
            #expect(row["signingIdentifierSource"] as? String == (mode == 0 ? "unavailable" : mode >= 2 && mode % 2 == 0 ? "verified" : "tentative"))
            let sckFields = try #require((row["sck"] as? [[String: Any]])?.first)
            let rectangle = try #require(sckFields["rect"] as? [String: Any])
            #expect(rectangle["width"] as? Double == (mode == 4 ? -3 : mode == 5 ? 0 : 3))
            #expect(rectangle["height"] as? Double == (mode == 5 ? -1 : 4))
            #expect((rectangle["x"] is NSNull) == (mode == 5))
            #expect((row["windowID"] is NSNull) == (mode == 0))
            if let owner {
                let fields = try #require(row["owner"] as? [String: Any])
                #expect(fields["verified"] as? Bool == owner.verified && fields["appleAnchored"] as? Bool == owner.appleAnchored && fields["sysctlBound"] as? Bool == owner.sysctlBound)
                #expect((fields["realUID"] is NSNull) == (owner.realUID == nil))
                #expect((fields["savedUID"] is NSNull) == (owner.savedUID == nil))
                #expect(fields["startSeconds"] as? UInt64 == 123 && fields["startMicroseconds"] as? UInt64 == 999_999)
            } else { #expect(row["owner"] is NSNull) }
            #expect(!String(decoding: data, as: UTF8.self).contains("PRIVATE-"))
        }
        #expect(journal.emit("clock-anchor", ScreenRunnerClockAnchor.fields))
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = read(descriptors[0], &bytes, bytes.count)
        #expect(count > 0)
        transcript.append(Data(bytes.prefix(max(0, count))))
        #expect(!journal.failed)
        if ProcessInfo.processInfo.environment["GITHUB_ACTIONS"] == "true",
           FileManager.default.fileExists(atPath: FileManager.default.currentDirectoryPath + "/build14-results") {
            let output = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appending(path: "build14-results/refusal-journal.ndjson")
            try transcript.write(to: output, options: .atomic)
        }
    }
    @Test func everyRetryKeepsItsOwnIssueWithoutDuplicateFallback() throws {
        let sink = Sink(), diagnostics = D(output: { sink.append($0) })
        for i in 1...100 {
            let attempt = diagnostics.begin(.initial)
            #expect(attempt.reject(.ownerAttribution, .bundlePair, pid: 42, windowID: UInt32(i)) == .ownerAttribution)
            attempt.reject(.unknown, .operation)
        }
        #expect(sink.rows.count == 100)
        #expect(sink.rows.map(\.attempt) == Array(1...100))
        #expect(sink.rows.map(\.windowID) == (1...100).map { UInt32($0) })
        #expect(sink.rows.allSatisfy { $0.issue == .ownerAttribution && $0.branch == .bundlePair })
    }
    @Test func identifierCodecAndNullableFactsNeverEmitContent() throws {
        for input in [nil, "", "com.apple.finder", "a." + String(repeating: "a", count: 253), "a." + String(repeating: "a", count: 254), "com..apple", "com.apple/title", "com.apple\nsecret", "com.é"] as [String?] {
            let value = D.Notice.identifier(input)
            let valid = input == "com.apple.finder" || input == "a." + String(repeating: "a", count: 253)
            #expect(value["status"] as? String == (input == nil ? "unavailable" : valid ? "present" : "invalid-identifier"))
            #expect(valid ? value["value"] as? String == input : value["value"] is NSNull)
            if let input { #expect(value["bytes"] as? Int == input.utf8.count) }
            else { #expect(value["bytes"] is NSNull) }
            _ = try JSONSerialization.data(withJSONObject: value)
        }
        let value = D.Notice.rect(CGRect(x: Double.infinity, y: 2, width: 3, height: 4))
        #expect(value["x"] is NSNull)
    }
    @Test func realJournalEncodesRefusalAndEarlyClockWithinExistingBounds() throws {
        var descriptors: [Int32] = [0, 0]
        #expect(pipe(&descriptors) == 0)
        defer { close(descriptors[0]); close(descriptors[1]) }
        #expect(fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0)
        let journal = try ScreenRunnerJournal(.selectedWindow, descriptor: descriptors[1], authorityFailed: {})
        let diagnostics = D { notice in journal.emit("inventory-refusal", notice.fields, at: notice.at) }
        let rect = CGRect(x: 1, y: 2, width: 3, height: 4), identifier = "a." + String(repeating: "a", count: 253)
        diagnostics.begin(.initial).reject(.ownerAttribution, .bundlePair, pid: 42, windowID: 9, signingIdentifier: identifier,
            cg: [.init(id: 9, pid: 42, rect: rect, layer: 1)], sck: [.init(id: 9, pid: 42, bundle: identifier, rect: rect, layer: 1)])
        #expect(journal.emit("clock-anchor", ScreenRunnerClockAnchor.fields))
        #expect(!journal.failed)
        var bytes = [UInt8](repeating: 0, count: 8192)
        let count = read(descriptors[0], &bytes, bytes.count)
        #expect(count > 0)
        let lines = Data(bytes.prefix(max(0, count))).split(separator: 10)
        #expect(lines.count == 2)
        let rows = try lines.map { try JSONSerialization.jsonObject(with: Data($0)) as! [String: Any] }
        #expect(lines.allSatisfy { $0.count <= 4096 })
        #expect(rows[0]["stage"] as? String == "inventory-refusal" && rows[0]["attempt"] as? Int == 1)
        #expect(rows[1]["stage"] as? String == "clock-anchor" && rows[1]["marker"] as? String == "runner-clock-anchor")
        #expect(rows.allSatisfy { $0["schema"] as? Int == 6 && $0["eventElapsedMs"] is NSNumber })
    }
    @Test func setupAllowancesPreserveMeasuredRemainingBudget() {
        #expect(ScreenRunnerSetupAllowance.watchdogSeconds == 120)
        #expect(ScreenRunnerSetupAllowance.finalSeconds == 150)
        #expect(ScreenRunnerSetupAllowance.cleanupRemaining(elapsed: 40) == 110)
        #expect(ScreenRunnerSetupAllowance.cleanupRemaining(elapsed: 149.5) == 0.5)
        #expect(ScreenRunnerSetupAllowance.cleanupRemaining(elapsed: 151) == 0)
        #expect(ScreenRunnerClockAnchor.marker == "runner-clock-anchor")
    }
}
#endif
