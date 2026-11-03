#if SLICCY_HOSTED_PID_PROOF
import Foundation
import Darwin

enum ScreenHostedPIDHost {
    static let required = ["GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "ai-ecoverse/sliccy-app",
        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/proof/runner-capture-v1",
        "SLICCY_RUNNER_ENVIRONMENT": "github-hosted"]
    static func validate(arguments: [String], environment: [String: String], major: Int, arm: Bool) throws {
        guard arguments == ["--screen-runner-proof", "--case", "pid-reuse-hosted"], arm, major == 27,
              required.allSatisfy({ environment[$0.key] == $0.value }) else { throw ScreenFailure.incompatible }
    }
    static func require() throws {
#if arch(arm64)
        let arm = true
#else
        let arm = false
#endif
        try validate(arguments: Array(ProcessInfo.processInfo.arguments.dropFirst()), environment: ProcessInfo.processInfo.environment,
                     major: ProcessInfo.processInfo.operatingSystemVersion.majorVersion, arm: arm)
    }
}

final class ScreenHostedPIDSubject: @unchecked Sendable {
    typealias Emit = @Sendable (String, Int, pid_t?, Bool?) -> Void
    private let lock = NSLock(), ready = DispatchSemaphore(value: 0), reapSignal = DispatchSemaphore(value: 0)
    private let emit: Emit
    let attempt: Int
    private var child: ScreenChild?, transport: ScreenTransport?, pair: ScreenHandshake.Pair?, verifier: ScreenPeerVerifier?
    private var lost = false, reaped = false, published = false, stopping = false
    init(attempt: Int, emit: @escaping Emit) { self.attempt = attempt; self.emit = emit }
    private func state<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }
    var pid: pid_t? { state { child?.pid } }
    func launch(root: URL, join: String) throws {
        let handshake = try ScreenHandshake(), policy = ScreenLaunchPolicy.universalAppProof(root: root)
        let verifier = ScreenPeerVerifier(approvedHashes: policy.hashes)
        let owned = try ScreenChild(executable: Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
            join: join, bootstrap: handshake.bootstrapRecord(), policy: policy,
            reaped: { [weak self] _ in self?.didReap() }, lost: { [weak self] in self?.didLose() })
        lock.lock(); child = owned; published = true
        emit(attempt == 0 ? "pid-reuse-original-started" : "pid-reuse-attempt-started", attempt, owned.pid, nil)
        if lost { emit("pid-reuse-gate-invalidated", attempt, owned.pid, false) }
        if reaped { emit("pid-reuse-child-reaped", attempt, owned.pid, nil) }
        let stop = stopping; lock.unlock()
        if stop { owned.stop(); throw ScreenFailure.stopped }
        let pair = try handshake.authenticate(pid: owned.pid, until: owned.deadline, verifier: verifier,
                                               policy: policy, childAlive: { owned.isAlive })
        emit("lanes-authenticated", attempt, owned.pid, nil)
        let link = ScreenTransport(pair: pair, verifier: verifier, noCapture: true, currentProtection: { false }, event: { [weak self] event in
            guard let self else { return }
            if case .ready = event { self.emit("heartbeat-ready", self.attempt, self.pid, nil); self.ready.signal() }
        })
        let keep = state { () -> Bool in
            guard !lost, !stopping, !reaped else { return false }
            self.pair = pair; self.verifier = verifier; transport = link; return true
        }
        guard keep else { link.close(); throw ScreenFailure.peerLost }
        link.start()
        let duration = ContinuousClock.now.duration(to: owned.deadline).components
        let seconds = Double(duration.seconds) + Double(duration.attoseconds) / 1e18
        guard seconds > 0, ready.wait(timeout: .now() + seconds) == .success else { throw ScreenFailure.stalled }
        _ = try verify()
        emit(attempt == 0 ? "pid-reuse-original-live-positive" : "pid-reuse-candidate-live-positive", attempt, owned.pid, nil)
    }
    func verify() throws -> ScreenAuditIdentity {
        let value = state { (child, pair, verifier, stopping, lost) }
        guard let child = value.0, child.isAlive, let pair = value.1, let verifier = value.2, !value.3, !value.4 else { throw ScreenFailure.peerLost }
        return try verifier.verifyCLI(socket: pair.safety.fd, expectedPID: child.pid, expectedIdentity: pair.identity)
    }
    func cancel() {
        let owned = state { stopping = true; return child }; owned?.stop()
    }
    func stopAndReap() throws {
        cancel()
        let value = state { (child, transport) }; value.1?.close()
        if let child = value.0 {
            if !state({ reaped }), reapSignal.wait(timeout: .now() + 2) != .success {
                child.forceStop()
                guard reapSignal.wait(timeout: .now() + 1) == .success else { throw ScreenFailure.stalled }
            }
            guard state({ reaped }) else { throw ScreenFailure.stalled }
        }
    }
    private func didLose() {
        let link = state { transport }; link?.quiesceOutput()
        lock.lock(); lost = true
        if published { emit("pid-reuse-gate-invalidated", attempt, child?.pid, link?.gate.isInvalidated == true) }
        lock.unlock()
    }
    private func didReap() {
        lock.lock(); reaped = true
        if published { emit("pid-reuse-child-reaped", attempt, child?.pid, nil) }
        lock.unlock(); reapSignal.signal()
    }
}
#endif
