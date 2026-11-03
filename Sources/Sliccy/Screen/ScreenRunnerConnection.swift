#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

final class ScreenRunnerHealth: @unchecked Sendable {
    private let lock = NSLock()
    private var valid = false, ended = false
    private var sourceUntil: ContinuousClock.Instant?
    private var indicator: ScreenIndicatorHealth?
    private var owners: [ScreenRunnerOwnedProcess] = []
    func install(indicator: ScreenIndicatorHealth, owners: [ScreenRunnerOwnedProcess]) {
        lock.lock(); defer { lock.unlock() }
        guard !ended else { return }; self.indicator = indicator; self.owners = owners; sourceUntil = .now.advanced(by: .milliseconds(1500)); valid = true
    }
    func invalidate() { lock.lock(); valid = false; ended = true; lock.unlock() }
    func renewSource() {
        lock.lock(); defer { lock.unlock() }
        guard valid, !ended, sourceUntil.map({ .now < $0 }) == true else { valid = false; ended = true; return }
        sourceUntil = .now.advanced(by: .milliseconds(1500))
    }
    func check() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return valid && !ended && sourceUntil.map({ .now < $0 }) == true && indicator?.check() == true && owners.allSatisfy(\.isAlive)
    }
}

final class ScreenRunnerConnection: @unchecked Sendable {
    enum Event: Sendable { case started(pid_t), authenticated, lost, reaped(pid_t), transport(ScreenTransport.Event) }
    private let lock = NSLock()
    private var child: ScreenChild?, link: ScreenTransport?
    private var stopped = false, reaped = false
    private let didReap = DispatchSemaphore(value: 0)
    let health = ScreenRunnerHealth()
    private let event: @Sendable (Event) -> Void
    init(event: @escaping @Sendable (Event) -> Void) { self.event = event }
    var transport: ScreenTransport? { lock.lock(); defer { lock.unlock() }; return link }
    func open(root: URL, join: String) throws {
        lock.lock(); let allowed = !stopped; lock.unlock()
        guard allowed else { throw ScreenFailure.stopped }
        let policy = ScreenLaunchPolicy.universalAppProof(root: root), verifier = ScreenPeerVerifier(approvedHashes: policy.hashes)
        let handshake = try ScreenHandshake()
        let owned = try ScreenChild(executable: Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
            join: join, bootstrap: handshake.bootstrapRecord(), policy: policy,
            reaped: { [weak self] _ in self?.childReaped() }, lost: { [weak self] in self?.childLost() })
        lock.lock(); child = owned; let stop = stopped, alreadyReaped = reaped; lock.unlock()
        event(.started(owned.pid))
        if alreadyReaped { event(.reaped(owned.pid)) }
        if stop { owned.stop(); throw ScreenFailure.stopped }
        let pair = try handshake.authenticate(pid: owned.pid, until: owned.deadline, verifier: verifier, policy: policy, childAlive: { owned.isAlive })
        let transport = ScreenTransport(pair: pair, verifier: verifier, noCapture: false,
            currentProtection: { [health] in health.check() }, event: { [event] in event(.transport($0)) })
        lock.lock()
        let keep = !stopped && owned.isAlive
        if keep { link = transport }
        lock.unlock()
        guard keep else { transport.close(); throw ScreenFailure.peerLost }
        event(.authenticated); transport.start()
    }
    private func childLost() {
        health.invalidate(); transport?.quiesceOutput(); event(.lost)
    }
    private func childReaped() {
        lock.lock(); reaped = true; let pid = child?.pid; lock.unlock()
        didReap.signal(); if let pid { event(.reaped(pid)) }
    }
    func abortDiagnostic() {
        health.invalidate()
        lock.lock(); stopped = true; let transport = link, owned = child; lock.unlock()
        transport?.close(); owned?.stop()
    }
    @discardableResult func stopAndReap() throws -> pid_t? {
        health.invalidate()
        lock.lock(); stopped = true; let owned = child; let transport = link; let already = reaped; lock.unlock()
        transport?.close(); owned?.stop()
        if let owned, !already {
            if didReap.wait(timeout: .now() + 2) != .success {
                owned.forceStop(); guard didReap.wait(timeout: .now() + 1) == .success else { throw ScreenFailure.stalled }
            }
        }
        lock.lock(); let complete = reaped; lock.unlock()
        guard owned == nil || complete else { throw ScreenFailure.stalled }
        return owned?.pid
    }
}
#endif
