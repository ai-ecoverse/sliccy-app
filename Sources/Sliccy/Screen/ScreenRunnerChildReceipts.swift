#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Darwin
import Security

struct ScreenRunnerChildReceipts: Sendable {
    let record: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void
    let lost: @Sendable () -> Void
}

enum ScreenRunnerChildChecks {
    static func boundary(pid: pid_t, identity: ScreenRunnerProcessIdentity?, signal: Int32?, passed: Bool) -> ScreenRunnerSliceBinding.Evidence {
        var compared: [String: Any] = ["pid": pid, "signal": signal as Any? ?? NSNull()]
        if let identity {
            let s = identity.sample
            compared["incarnation"] = [s.pid, s.parent, s.uid, String(s.seconds), String(s.microseconds)] as [Any]
            compared["expected"] = identity.hash.base64EncodedString()
        }
        return .init(role: "ai.sliccy.slicc", site: signal == nil ? "child-initial" : "child-signal", at: .now,
            passed: passed, step: passed ? "child-complete" : "child-refused", selected: nil, statuses: [], compared: compared)
    }
    static func capture(pid: pid_t, hash: Data, receipts: ScreenRunnerChildReceipts) throws -> ScreenRunnerProcessIdentity {
        try capture(pid: pid, hash: hash, receipts: receipts, calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
                    read: ScreenRunnerProcessSample.read, parent: getpid(), uid: geteuid())
    }
    static func capture<S, G, R>(pid: pid_t, hash: Data, receipts: ScreenRunnerChildReceipts,
                                 calls: ScreenRunnerSecurityCalls<S, G, R>, read: (pid_t) throws -> ScreenRunnerProcessSample,
                                 parent: pid_t, uid: uid_t) throws -> ScreenRunnerProcessIdentity {
        let batch = ScreenRunnerChromeEvidenceBatch()
        var identity: ScreenRunnerProcessIdentity?
        defer {
            batch.collectSlice(boundary(pid: pid, identity: identity, signal: nil, passed: identity != nil))
            batch.deliver(to: { _, _ in }, sliceOutput: receipts.record, loss: receipts.lost)
        }
        let recorded = try ScreenRunnerProcessIdentity.capture(pid: pid, role: .cli, hash: hash, identifier: "ai.sliccy.slicc", team: "S8LB56P782",
            calls: calls, read: read, parent: parent, uid: uid, chromeEvidence: { _ in }, sliceEvidence: batch.collectSlice)
        identity = recorded
        return recorded
    }
    static func signalUnderLock(_ lock: ScreenRunnerOwnerLock, receipts: ScreenRunnerChildReceipts,
                                check: (ScreenRunnerChromeEvidenceBatch) -> Bool) -> Bool {
        lock.withEvidence(output: { _, _ in }, sliceOutput: receipts.record, loss: receipts.lost, operation: check)
    }
    static func signal(_ value: Int32, pid: pid_t, identity: ScreenRunnerProcessIdentity?, reaped: Bool,
                       batch: ScreenRunnerChromeEvidenceBatch) -> Bool {
        signal(value, pid: pid, identity: identity, reaped: reaped, batch: batch,
            calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
            read: { try ScreenRunnerProcessSample.read(pid) }, send: { kill($0, $1) })
    }
    static func signal<S, G, R>(_ value: Int32, pid: pid_t, identity: ScreenRunnerProcessIdentity?, reaped: Bool,
                                batch: ScreenRunnerChromeEvidenceBatch, calls: ScreenRunnerSecurityCalls<S, G, R>,
                                read: () throws -> ScreenRunnerProcessSample, send: (pid_t, Int32) -> Int32) -> Bool {
        var passed = false
        defer { batch.collectSlice(boundary(pid: pid, identity: identity, signal: value, passed: passed)) }
        guard let identity, identity.sample.pid == pid else { return false }
        passed = identity.signal(value, owned: !reaped, reaped: reaped, sample: read,
            role: { try ScreenRunnerProcessIdentity.verifyRole(pid: pid, identifier: "ai.sliccy.slicc", team: "S8LB56P782", hash: identity.hash,
                site: .signal, calls: calls, chromeEvidence: { _ in }, sliceEvidence: batch.collectSlice) }, send: send)
        return passed
    }
}
#endif
