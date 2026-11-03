import Foundation
import Testing
@testable import Sliccy

struct ScreenProofTests {
    @Test func productionLaunchRemainsDisabled() {
        #expect(!ScreenLaunchPolicy.production.allowsIPC)
        #expect(ScreenLaunchPolicy.production.hashes.isEmpty)
        #expect(ScreenReleasePolicy.provenScopes.isEmpty)
        #expect(!ScreenReleasePolicy.identityProofApproved)
    }

    @Test func sharedStopObserverRunsAfterInvalidationAndBeforeStopWork() throws {
        let gate = ScreenOutputGate(), now = ContinuousClock.now
        let binding = ScreenBinding(link: try ScreenID.make(), session: try ScreenID.make(), source: try ScreenID.make(),
            grantEpoch: "1", sourceEpoch: "1", protectionEpoch: "1")
        try gate.renew(until: now.advanced(by: .seconds(10)), now: now)
        try gate.activate(binding, now: now)
        let relay = ScreenStopRelay(gate: gate, observed: { start, invalidated in
            #expect(invalidated >= start)
            #expect(!gate.allows(binding))
            #expect(throws: ScreenFailure.leaseExpired) { try gate.activate(binding) }
        }, stop: { _ in #expect(!gate.allows(binding)) })
        relay.invoke(.stopped)
        #expect(throws: ScreenFailure.leaseExpired) { try gate.nextFrame() }
    }

#if SLICCY_NATIVE_SCREEN_PROOF
    @Test func onlyFixedDiagnosticCasesCanBeSelected() throws {
        #expect(try ScreenProofCase.parse(["--screen-proof"]) == .base)
        #expect(try ScreenProofCase.parse(["--screen-proof", "--case", "parent-exec"]) == .parentExec)
        #expect(try ScreenProofCase.parse(["--screen-proof", "--case", "lifecycle"]) == .lifecycle)
        #expect(try ScreenProofCase.parse(["--screen-proof", "--case", "ancillary"]) == .ancillary)
        #expect(try ScreenProofCase.parse(["--screen-proof", "--case", "safety-handoff"]) == .safetyHandoff)
        #expect(try ScreenProofCase.parse(["--screen-proof", "--case", "frame-handoff"]) == .frameHandoff)
        for bad in [[String](), ["--screen-proof", "--case", "/bin/sh"],
                    ["--screen-proof", "--case", "base"], ["--screen-proof", "--pid", "1"],
                    ["--screen-proof", "--case", "parent-exec", "--path", "/tmp/helper"]] {
            #expect(throws: ScreenFailure.incompatible) { try ScreenProofCase.parse(bad) }
        }
    }
    @Test func generatedSourceIsFixedBoundedAndUsesMetadataStrippedJPEG() throws {
        let first = try ScreenProofSyntheticSource(), second = try ScreenProofSyntheticSource()
        #expect(first.jpeg == second.jpeg)
        #expect(first.jpeg.count <= 2048)
        #expect(try ScreenJPEG.withoutMetadata(first.jpeg) == first.jpeg)
        #expect(!ScreenReleasePolicy.identityProofApproved && ScreenReleasePolicy.provenScopes.isEmpty)
    }
    @Test func ancillaryObservationCannotPassFromLeaseExpiryPartialSendOrEarlyExit() {
        let start = ContinuousClock.now
        var observation = ScreenAncillaryObservation(started: start)
        observation.loss = (.peerLost, start.advanced(by: .milliseconds(25)))
        #expect(!observation.completed(at: start.advanced(by: .seconds(2)), childAlive: true))
        observation.fullWrite = true
        #expect(observation.completed(at: start.advanced(by: .seconds(2)), childAlive: true))
        #expect(!observation.completed(at: start.advanced(by: .seconds(1)), childAlive: true))
        #expect(!observation.completed(at: start.advanced(by: .seconds(2)), childAlive: false))
        observation.loss = (.leaseExpired, start.advanced(by: .milliseconds(25)))
        #expect(!observation.completed(at: start.advanced(by: .seconds(2)), childAlive: true))
        observation.loss = (.peerLost, start.advanced(by: .milliseconds(501)))
        #expect(!observation.completed(at: start.advanced(by: .seconds(2)), childAlive: true))
        observation.loss = (.peerLost, start.advanced(by: .milliseconds(-1)))
        #expect(!observation.completed(at: start.advanced(by: .seconds(2)), childAlive: true))
    }
    @Test func diagnosticJoinIsLoopbackOnlyAndRefusesDebugPorts() throws {
        let valid = "http://127.0.0.1:32456/join/test.secret"
        #expect(try ScreenProofSession.validateJoin(valid) == valid)
        for invalid in ["https://example.com/join/test.secret", "http://localhost:32456/join/test.secret",
                        "http://127.0.0.1:9222/join/test.secret", "http://127.0.0.1:9229/join/test.secret",
                        "http://127.0.0.1:32456/join/", "http://127.0.0.1:32456/join/test.secret?redirect=x",
                        "http://user@127.0.0.1:32456/join/test.secret", valid + "\n", valid + "\r", ""] {
            #expect(throws: ScreenFailure.incompatible) { try ScreenProofSession.validateJoin(invalid) }
        }
    }
    @Test func diagnosticPolicyDoesNotInheritUserEnvironmentOrChangeProductionAuthority() {
        let root = URL(fileURLWithPath: "/private/tmp/synthetic-proof-test")
        let policy = ScreenLaunchPolicy.noCaptureProof(root: root)
        #expect(policy.allowsIPC)
        #expect(policy.hashes.count == 1)
        #expect(policy.hashes.first?.count == 20)
        #expect(Set(policy.environment) == ["PATH=/usr/bin:/bin", "HOME=" + root.path,
            "TMPDIR=" + root.path + "/tmp/", "SLICC_USER_DATA_DIR=" + root.path + "/config",
            "SLICC_NO_TELEMETRY=1", "SLICC_NO_UPDATE_CHECK=1", "LANG=en_US.UTF-8"])
        #expect(!ScreenLaunchPolicy.production.allowsIPC)
    }
#endif
}
