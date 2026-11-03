#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerProcessIdentityTests {
    private let original = ScreenRunnerProcessSample(pid: 12, parent: 10, uid: 501, seconds: 100, microseconds: 20)
    @Test func childAdmissionRefusesWrongParentUIDAndMalformedStart() {
        #expect(throws: Never.self) { try original.requireChild(parent: 10, uid: 501) }
        #expect(throws: ScreenFailure.peerUntrusted) { try original.requireChild(parent: 11, uid: 501) }
        #expect(throws: ScreenFailure.peerUntrusted) { try original.requireChild(parent: 10, uid: 502) }
        for bad in [ScreenRunnerProcessSample(pid: 0, parent: 10, uid: 501, seconds: 100, microseconds: 20),
                    .init(pid: 12, parent: 10, uid: 501, seconds: 0, microseconds: 20),
                    .init(pid: 12, parent: 10, uid: 501, seconds: 100, microseconds: 1_000_000)] {
            #expect(throws: ScreenFailure.peerUntrusted) { try bad.requireChild(parent: 10, uid: 501) }
        }
    }
    @Test func signalsRequireBothIncarnationSamplesAndActualRoleCheck() {
        let record = ScreenRunnerProcessIdentity(sample: original, role: .chrome, hash: Data([1]))
        var stages: [String] = []
        let sent = record.signal(15, owned: true, reaped: false, sample: { stages.append("sample"); return original },
            role: { stages.append("role") }, send: { pid, value in
                stages.append("signal"); #expect(pid == 12 && value == 15); return 0
            })
        #expect(sent && stages == ["sample", "role", "sample", "signal"])
        for changedAt in [1, 2] {
            var reads = 0, signals = 0
            let result = record.signal(9, owned: true, reaped: false, sample: {
                reads += 1
                return reads == changedAt ? .init(pid: 12, parent: 10, uid: 501, seconds: 101, microseconds: 20) : original
            }, role: {}, send: { _, _ in signals += 1; return 0 })
            #expect(!result && signals == 0)
        }
    }
    @Test func reapedUnknownUnavailableOrWrongRoleNeverSignals() {
        let record = ScreenRunnerProcessIdentity(sample: original, role: .authorizationRequester, hash: Data([2]))
        for index in 0..<5 {
            var signals = 0
            let result = record.signal(9, owned: index != 0, reaped: index == 1, sample: {
                if index == 2 { throw ScreenFailure.peerLost }
                return original
            }, role: {
                if index == 3 { throw ScreenFailure.peerUntrusted }
            }, send: { _, _ in signals += 1; return -1 })
            #expect(!result && signals == (index == 4 ? 1 : 0))
        }
    }
}
#endif
