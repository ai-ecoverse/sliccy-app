#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
import Darwin
import Security
@testable import Sliccy

struct ScreenRunnerSurfaceDiagnosticsTests {
    typealias D = ScreenRunnerSurfaceDiagnostics
    final class Sink: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [D.Notice] = []
        func append(_ value: D.Notice) { lock.lock(); values.append(value); lock.unlock() }
        var rows: [D.Notice] { lock.lock(); defer { lock.unlock() }; return values }
    }
    @Test func actualHashBoundaryNamesFailureAndPreservesPositiveControl() throws {
        let sink = Sink(), diagnostics = D { sink.append($0) }
        try diagnostics.verifyHash(ScreenRunnerOwnedProcess.surfaceSHA256, expected: ScreenRunnerOwnedProcess.surfaceSHA256)
        #expect(sink.rows.isEmpty)
        #expect(throws: ScreenFailure.peerUntrusted) { try diagnostics.verifyHash("wrong", expected: ScreenRunnerOwnedProcess.surfaceSHA256) }
        #expect(sink.rows.count == 1)
        #expect(sink.rows.first?.predicate == .hash && sink.rows.first?.operation == .executableHash)
    }
    @Test func firstRefusalCannotBeOverwritten() {
        let sink = Sink(), diagnostics = D { sink.append($0) }
        diagnostics.reject(.path, .executableRead)
        diagnostics.reject(.operation, .launch)
        #expect(sink.rows.count == 1)
        #expect(sink.rows.first?.predicate == .path && sink.rows.first?.operation == .executableRead)
    }
    @Test func actualPreflightNamesPolicyAndRoleWithoutExtraNativeCalls() throws {
        let path = URL(fileURLWithPath: "/fixed/surface")
        for failure in ["none", "identifier", "team", "role"] {
            let sink = Sink(), diagnostics = D { sink.append($0) }
            let trace = ScreenRunnerSecurityTrace(executable: path, strict: failure == "role" ? -67050 : 0, identifier: "ai.sliccy.proof-helper")
            do {
                _ = try ScreenRunnerOwnedProcess.preflight(executable: path,
                    identifier: failure == "identifier" ? "invalid" : "ai.sliccy.proof-helper", team: failure == "team" ? "wrong" : "S8LB56P782",
                    calls: trace.calls, chromeEvidence: { _ in }, surfaceDiagnostics: diagnostics)
                #expect(failure == "none")
            } catch { #expect(failure != "none") }
            if failure == "none" { #expect(sink.rows.isEmpty) }
            else {
                #expect(sink.rows.count == 1)
                #expect(sink.rows.first?.predicate.rawValue == failure)
                #expect(sink.rows.first?.operation == (failure == "role" ? .staticValidity : .policy))
                #expect(sink.rows.first?.status == (failure == "role" ? -67050 : nil))
            }
            if failure == "identifier" || failure == "team" { #expect(trace.events.isEmpty) }
            if failure == "role" { #expect(trace.events.filter { $0.kind == "static-check" }.map(\.flags) == [16, 25]) }
        }
    }
    @Test func actualPreflightNamesInformationIdentifierAndPath() {
        let path = URL(fileURLWithPath: "/fixed/surface")
        for field in ["identifier", "path"] {
            let sink = Sink(), diagnostics = D { sink.append($0) }
            let trace = ScreenRunnerSecurityTrace(executable: path, failure: field == "path" ? "path" : nil,
                identifier: field == "identifier" ? "ai.sliccy.mac" : "ai.sliccy.proof-helper")
            #expect(throws: ScreenFailure.peerUntrusted) {
                try ScreenRunnerOwnedProcess.preflight(executable: path, identifier: "ai.sliccy.proof-helper", team: "S8LB56P782",
                    calls: trace.calls, chromeEvidence: { _ in }, surfaceDiagnostics: diagnostics)
            }
            #expect(sink.rows.count == 1)
            #expect(sink.rows.first?.predicate.rawValue == field && sink.rows.first?.operation == .signingInformation)
        }
    }
    @Test func observedReadFailureKeepsOriginalErrorAndFallbackCannotReplaceIt() {
        let sink = Sink(), diagnostics = D { sink.append($0) }
        #expect(throws: ScreenFailure.stalled) {
            try diagnostics.observe(.path, .executableRead) { throw ScreenFailure.stalled }
        }
        diagnostics.reject(.operation, .launch)
        #expect(sink.rows.count == 1)
        #expect(sink.rows.first?.predicate == .path && sink.rows.first?.operation == .executableRead)
    }
    @Test func actualJournalEncodesOnlyFixedSurfaceFields() throws {
        var descriptors: [Int32] = [-1, -1]
        #expect(pipe(&descriptors) == 0)
        defer { close(descriptors[0]); close(descriptors[1]) }
        #expect(fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0)
        let journal = try ScreenRunnerJournal(.selectedWindow, descriptor: descriptors[1], authorityFailed: {})
        let notice = D.Notice(predicate: .role, operation: .staticValidity, status: -67050, at: .now)
        #expect(journal.emit("surface-refusal", notice.fields, at: notice.at))
        var bytes = [UInt8](repeating: 0, count: 8192)
        let count = read(descriptors[0], &bytes, bytes.count)
        #expect(count > 0)
        guard count > 0 else { return }
        let data = Data(bytes.prefix(count)), row = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(row["stage"] as? String == "surface-refusal")
        #expect(row["predicate"] as? String == "role" && row["operation"] as? String == "static-validity")
        #expect(row["status"] as? Int == -67050)
        #expect(row["schema"] as? Int == 6 && data.count <= 4096)
        #expect(D.Notice(predicate: .hash, operation: .executableHash, status: nil, at: .now).fields["status"] is NSNull)
    }
}
#endif
