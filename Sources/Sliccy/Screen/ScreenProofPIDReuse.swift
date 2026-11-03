#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation
import Security
import Darwin

struct ScreenProofReuseBudget {
    static let maximumAttempts = 32
    static let duration: Duration = .seconds(15)
    let started: ContinuousClock.Instant
    private(set) var attempts = 0
    var deadline: ContinuousClock.Instant { started.advanced(by: Self.duration) }
    mutating func admit(now: ContinuousClock.Instant = .now) -> Int? {
        guard attempts < Self.maximumAttempts, now.duration(to: deadline) >= .seconds(3) else { return nil }
        attempts += 1
        return attempts
    }
}

/// Sequential owned children only. Exhaustion is an inconclusive result, never a
/// stale-token-only substitute for an observed reused PID/new incarnation.
final class ScreenProofPIDReuse: @unchecked Sendable {
    typealias Report = @Sendable (String, pid_t?, Int, String?, Double?) -> Void
    private let lock = NSLock()
    private var cancelled = false
    private var active: ScreenChild?
    private let report: Report
    private let root: URL
    private let join: String

    init(root: URL, join: String, report: @escaping Report) {
        self.root = root; self.join = join; self.report = report
    }
    func cancel() {
        lock.lock(); cancelled = true; let child = active; lock.unlock()
        child?.stop()
    }
    private var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    private func own(_ child: ScreenChild?) {
        lock.lock(); active = child; let stop = cancelled; lock.unlock()
        if stop { child?.stop() }
    }
    private final class Life: @unchecked Sendable {
        let ready = DispatchSemaphore(value: 0)
        let reap = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var transport: ScreenTransport?
        var didReap = false
        var lost = false
        var reaped: Bool { lock.lock(); defer { lock.unlock() }; return didReap }
        func install(_ value: ScreenTransport) throws {
            lock.lock(); defer { lock.unlock() }
            guard !lost, !didReap else { throw ScreenFailure.peerLost }
            transport = value
        }
        func invalidate() -> Bool {
            lock.lock(); lost = true; let value = transport; lock.unlock()
            value?.quiesceOutput()
            return value?.gate.isInvalidated == true
        }
        func markReaped() { lock.lock(); didReap = true; lock.unlock(); reap.signal() }
    }
    private struct Owned {
        let child: ScreenChild
        let pair: ScreenHandshake.Pair
        let transport: ScreenTransport
        let life: Life
        let verifier: ScreenPeerVerifier
        func verify() throws -> ScreenAuditIdentity {
            guard child.isAlive else { throw ScreenFailure.peerLost }
            return try verifier.verifyCLI(socket: pair.safety.fd, expectedPID: child.pid, expectedIdentity: pair.identity)
        }
    }
    private func launch(attempt: Int, deadline: ContinuousClock.Instant?) throws -> Owned {
        guard !isCancelled else { throw ScreenFailure.stopped }
        let handshake = try ScreenHandshake()
        let policy = ScreenLaunchPolicy.noCaptureProof(root: root)
        let verifier = ScreenPeerVerifier(approvedHashes: policy.hashes)
        let life = Life()
        // PID publication is local diagnostic metadata only, never authorization.
        let child = try ScreenChild(executable: Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
            join: join, bootstrap: handshake.bootstrapRecord(), policy: policy,
            reaped: { [report] _ in
                report("pid-reuse-child-reaped", nil, attempt, nil, nil)
                life.markReaped()
            }, lost: { [report] in
                let invalid = life.invalidate()
                report("pid-reuse-gate-invalidated", nil, attempt, invalid ? "invalidated" : "no-transport", nil)
            })
        own(child)
        report(attempt == 0 ? "pid-reuse-original-started" : "pid-reuse-attempt-started", child.pid, attempt, nil, nil)
        do {
            let until = min(child.deadline, deadline ?? child.deadline)
            let pair = try handshake.authenticate(pid: child.pid, until: until, verifier: verifier,
                policy: policy, childAlive: { child.isAlive })
            let transport = ScreenTransport(pair: pair, verifier: verifier, noCapture: true,
                currentProtection: { false }, event: { event in
                    if case .ready = event { life.ready.signal() }
                })
            try life.install(transport)
            transport.start()
            let remaining = ContinuousClock.now.duration(to: until).components
            let seconds = Double(remaining.seconds) + Double(remaining.attoseconds) / 1e18
            guard seconds > 0, life.ready.wait(timeout: .now() + seconds) == .success,
                  !isCancelled else { throw ScreenFailure.stalled }
            let owned = Owned(child: child, pair: pair, transport: transport, life: life, verifier: verifier)
            _ = try owned.verify()
            report(attempt == 0 ? "pid-reuse-original-live-positive" : "pid-reuse-candidate-live-positive", child.pid, attempt, nil, nil)
            return owned
        } catch {
            child.stop()
            if life.reap.wait(timeout: .now() + 2) != .success {
                child.forceStop()
                guard life.reap.wait(timeout: .now() + 1) == .success else { throw ScreenFailure.stalled }
            }
            own(nil)
            throw error
        }
    }
    private func stop(_ owned: Owned) throws {
        // Child.stop synchronously invalidates authority; its monitor owns reap.
        owned.child.stop()
        owned.transport.close()
        if !owned.life.reaped, owned.life.reap.wait(timeout: .now() + 2) != .success {
            owned.child.forceStop()
            guard owned.life.reap.wait(timeout: .now() + 1) == .success else { throw ScreenFailure.stalled }
        }
        guard owned.life.reaped else { throw ScreenFailure.stalled }
        own(nil)
    }
    private func awaitOriginalObservation() throws {
        let expected = Array("pid-original-observed\n".utf8)
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        var offset = 0
        while offset < expected.count, ContinuousClock.now < deadline {
            guard !isCancelled else { throw ScreenFailure.stopped }
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let status = poll(&descriptor, 1, 25)
            if status == 0 || (status < 0 && errno == EINTR) { continue }
            var byte: UInt8 = 0
            guard status > 0, read(STDIN_FILENO, &byte, 1) == 1, byte == expected[offset]
            else { throw ScreenFailure.incompatible }
            offset += 1
        }
        guard offset == expected.count else { throw ScreenFailure.stalled }
    }

    /// completion carries a fixed result, exit code, and actual cleanup status.
    func run(completion: @escaping @Sendable (String, Int32, Bool) -> Void) {
        DispatchQueue(label: "ai.sliccy.proof.pid-reuse").async { [self] in
            var owned: Owned?
            do {
                let original = try launch(attempt: 0, deadline: nil)
                owned = original
                let saved = try original.verify()
                try awaitOriginalObservation()
                _ = try original.verify()
                report("pid-reuse-original-observed", saved.pid, 0, nil, nil)
                try stop(original); owned = nil
                var budget = ScreenProofReuseBudget(started: .now)
                while !isCancelled, let attempt = budget.admit() {
                    let candidate = try launch(attempt: attempt, deadline: budget.deadline)
                    owned = candidate
                    let current = try candidate.verify()
                    if current.pid == saved.pid {
                        guard current.words[7] != saved.words[7], current != saved else { throw ScreenFailure.peerUntrusted }
                        report("pid-reuse-observed", current.pid, attempt, "new-incarnation", nil)
                        // A same-role live control precedes AND follows the old
                        // token lookup, preventing death/role mismatch confounds.
                        _ = try candidate.verify()
                        var oldRefused = false
                        do { _ = try ScreenPeerVerifier.verify(identity: saved, identifier: "ai.sliccy.slicc") }
                        catch { oldRefused = true }
                        guard oldRefused else { throw ScreenFailure.peerUntrusted }
                        report("pid-reuse-old-token-refused", current.pid, attempt, nil, nil)
                        _ = try candidate.verify()
                        report("pid-reuse-current-token-rechecked", current.pid, attempt, nil, nil)
                        // Fixed observation, not unbounded PID churn/polling.
                        let hold = DispatchSemaphore(value: 0)
                        _ = hold.wait(timeout: .now() + 2)
                        guard !isCancelled, candidate.child.isAlive else { throw ScreenFailure.peerLost }
                        _ = try candidate.verify()
                        report("pid-reuse-observation-ended", current.pid, attempt, "elapsed", nil)
                        try stop(candidate); owned = nil
                        completion("pid-reuse-confirmed", 0, true)
                        return
                    }
                    try stop(candidate); owned = nil
                }
                guard !isCancelled else { throw ScreenFailure.stopped }
                let elapsed = budget.started.duration(to: .now).components
                let milliseconds = Double(elapsed.seconds) * 1000 + Double(elapsed.attoseconds) / 1e15
                report("pid-reuse-budget-ended", nil, budget.attempts,
                    budget.attempts == ScreenProofReuseBudget.maximumAttempts ? "attempt-limit" : "time-limit", milliseconds)
                completion("pid-reuse-not-observed", 2, true)
            } catch {
                var clean = true
                if let owned { do { try stop(owned) } catch { clean = false } }
                lock.lock(); let remaining = active; lock.unlock()
                if remaining != nil { remaining?.forceStop(); clean = false }
                completion((error as? ScreenFailure ?? .incompatible).rawValue, 1, clean)
            }
        }
    }
}
#endif
