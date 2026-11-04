#if SLICCY_CAPTURE_RUNNER_PROOF
import Darwin
import Foundation
import ScreenSystem
import Testing
@testable import Sliccy

struct ScreenRunnerBSDTests {
    func read(_ pid: Int32, _ parent: Int32, _ uid: UInt32) -> sliccy_runner_bsd_read {
        .init(status: 0, count: 136, expected: 136,
              value: .init(pid: pid, parent: parent, effective_uid: uid, real_uid: uid, saved_uid: uid, seconds: 123, microseconds: 456))
    }
    func observation() -> sliccy_runner_bsd_observation {
        var result = sliccy_runner_bsd_observation()
        result.self_pid = 10; result.parent_pid = 11
        let a = read(10, 11, 501), b = read(11, 1, 501)
        result.controls.0 = .init(before: a, proc: a, after: a)
        result.controls.1 = .init(before: b, proc: b, after: b)
        var window = read(42, 1, 88); window.value.real_uid = 0; window.value.saved_uid = 0
        result.target = .init(before: window, proc: .init(status: EPERM, count: 0, expected: 136, value: .init()), after: window)
        return result
    }
    @Test func actualResolverAcceptsOnlyAgreedEPERMFallback() throws {
        let raw = observation(), value = try ScreenRunnerBSD.resolve(raw, pid: 42)
        #expect(value.usedSysctl && value.controlsAgreed)
        #expect(value.sample.effectiveUID == 88 && value.sample.realUID == 0 && value.sample.savedUID == 0)
        #expect(try ScreenRunnerBSD.bind(value, value, windowServer: true) == value.sample)
        var changed = raw; changed.controls.1.proc.value.saved_uid += 1
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerBSD.resolve(changed, pid: 42) }
        changed = raw; changed.target.proc.status = ESRCH
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerBSD.resolve(changed, pid: 42) }
        changed = raw; changed.target.after.value.seconds += 1
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerBSD.resolve(changed, pid: 42) }
        changed = raw; changed.controls.0.proc.status = EPERM
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerBSD.resolve(changed, pid: 42) }
    }
    @Test func actualBindingRejectsChangedCredentialsAndIncarnation() throws {
        let value = try ScreenRunnerBSD.resolve(observation(), pid: 42)
        var raw = observation(); raw.target.before.value.real_uid = 1; raw.target.after.value.real_uid = 1
        let changed = try ScreenRunnerBSD.resolve(raw, pid: 42)
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerBSD.bind(changed, changed, windowServer: true) }
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerBSD.bind(value, changed, windowServer: true) }
        let noControls = ScreenRunnerBSD.Resolved(sample: value.sample, usedSysctl: true, controlsAgreed: false)
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerBSD.bind(noControls, noControls, windowServer: true) }
    }
    @Test func windowServerTupleMustReachActualInventoryBoundary() throws {
        typealias F = ScreenRunnerInventoryBoundaryTests.Fixture
        var fixture = F(); fixture.add(id: 50, pid: 50, bundle: "com.apple.WindowServer", apple: true)
        let owner = fixture.owners[50]!
        _ = try fixture.read()
        for change in ["real", "saved", "binding", "effective", "parent"] {
            fixture.owners[50] = .init(pid: owner.pid, parent: change == "parent" ? 2 : owner.parent,
                uid: change == "effective" ? 89 : owner.uid, seconds: owner.seconds, microseconds: owner.microseconds,
                identifier: owner.identifier, path: owner.path, hash: owner.hash, appleAnchored: true, verified: true,
                sysctlBound: change != "binding", realUID: change == "real" ? 1 : 0, savedUID: change == "saved" ? 1 : 0)
            #expect(throws: ScreenRunnerInventoryIssue.ownerAttribution) { try fixture.read() }
        }
    }
}
#endif
