#if SLICCY_SNAPSHOT_PROOF
import AppKit
import Darwin
import Security

/// Stage uniqueness is per component, never a single global result flag.
struct ScreenSnapshotResults {
    enum Component: String, CaseIterable { case guest, endpoint }
    private var started = Set<Component>(), ended = Set<Component>()
    mutating func start(_ component: Component) throws {
        guard started.insert(component).inserted else { throw ScreenFailure.incompatible }
    }
    mutating func end(_ component: Component) throws {
        guard started.contains(component), ended.insert(component).inserted else { throw ScreenFailure.incompatible }
    }
    var complete: Bool { ended.count == Component.allCases.count }
}

@MainActor
final class ScreenSnapshotProofApp: NSObject, NSApplicationDelegate {
    private var session: ScreenSnapshotProofSession?
    static func run() {
        signal(SIGPIPE, SIG_IGN)
        let delegate = ScreenSnapshotProofApp(), app = NSApplication.shared
        app.delegate = delegate; app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let session = ScreenSnapshotProofSession { code in Task { @MainActor in Darwin.exit(code) } }
        self.session = session; session.start()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        session?.cancel(); return .terminateLater
    }
}

/// One owned subject, one fixed operation, no grant or capture route. Local exit0
/// says only that observations/cleanup completed, never that the proof passed.
final class ScreenSnapshotProofSession: @unchecked Sendable {
    private enum MarkerFailure: Error { case invalidOrExpired }
    private let stateLock = NSLock(), outputLock = NSLock()
    private let began = ContinuousClock.now
    private let complete: @Sendable (Int32) -> Void
    private var selected = ScreenSnapshotCase.mutation
    private var child: ScreenChild?, transport: ScreenTransport?
    private var subject: ScreenSnapshotSubject?
    private var cancelled = false, published = false, reaped = false, lost = false, associationLost = false
    private var outputFailed = false, outputBytes = 0
    private let reapSignal = DispatchSemaphore(value: 0), readySignal = DispatchSemaphore(value: 0)
    private var results = ScreenSnapshotResults()
    init(complete: @escaping @Sendable (Int32) -> Void) { self.complete = complete }
    private func state<T>(_ body: () -> T) -> T { stateLock.lock(); defer { stateLock.unlock() }; return body() }
    func cancel() { let owned = state { cancelled = true; return child }; owned?.stop() }
    func start() {
        DispatchQueue(label: "ai.sliccy.proof.snapshot").async { [self] in run() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35) { [weak self] in self?.cancel() }
    }
    private func run() {
        var reason = "inconclusive", code: Int32 = 2
        do {
            selected = try ScreenSnapshotCase.parse(Array(ProcessInfo.processInfo.arguments.dropFirst()))
            emit("snapshot-started", ["pid": getpid()])
            try ScreenPeerVerifier.verifySelf()
            let join = try ScreenProofSession.readJoin()
            reason = "layout-refused"
            let staged = try ScreenSnapshotSubject.prepare(selected); subject = staged
            var fields: [String: Any] = ["directory": staged.root.path, "originalSHA256": ScreenSnapshotRecipe.armSHA,
                                         "originalCDHash": String(ScreenSnapshotRecipe.armCD.prefix(40))]
            if selected == .replacement {
                fields["replacementSHA256"] = ScreenSnapshotRecipe.intelSHA
                fields["replacementCDHash"] = String(ScreenSnapshotRecipe.intelCD.prefix(40))
            }
            emit("snapshot-prepared", fields)
            let policy = ScreenLaunchPolicy.universalAppProof(root: staged.root)
            let verifier = ScreenPeerVerifier(approvedHashes: policy.hashes)
            let handshake = try ScreenHandshake()
            reason = "inconclusive"
            let owned = try ScreenChild.snapshot(subject: staged, join: join, bootstrap: handshake.bootstrapRecord(),
                                                 reaped: { [weak self] _ in self?.didReap() }, lost: { [weak self] in self?.didLose() })
            publish(owned)
            let pair = try handshake.authenticate(pid: owned.pid, until: owned.deadline, verifier: verifier,
                policy: policy, childAlive: { owned.isAlive })
            emit("lanes-authenticated")
            let link = ScreenTransport(pair: pair, verifier: verifier, noCapture: true, currentProtection: { false }, event: { [weak self] event in
                switch event {
                case .ready: self?.emit("heartbeat-ready"); self?.readySignal.signal()
                case .stopped:
                    guard let self else { return }
                    self.state { self.associationLost = true }
                default: break
                }
            })
            let keep = state { () -> Bool in guard !cancelled, !lost else { return false }; transport = link; return true }
            guard keep else { link.close(); throw ScreenFailure.peerLost }
            link.start()
            let remaining = max(0, Self.seconds(ContinuousClock.now.duration(to: owned.deadline)))
            guard readySignal.wait(timeout: .now() + remaining) == .success, owned.isAlive else { throw ScreenFailure.stalled }
            let baseline = try ScreenPeerVerifier.verify(identity: pair.identity, identifier: "ai.sliccy.slicc")
            let baselineHash = try hash(baseline)
            guard baselineHash == String(ScreenSnapshotRecipe.armCD.prefix(40)), owned.isAlive else { throw ScreenFailure.peerUntrusted }
            emit("baseline-live-positive", ["selectedCDHash": baselineHash])
            reason = "inconclusive"; try marker("snapshot-original-observed"); emit("original-observation-confirmed")
            guard owned.isAlive else { reason = "guest-exited"; throw ScreenFailure.peerLost }
            guard !state({ associationLost }) else { reason = "association-lost"; throw ScreenFailure.peerLost }
            let operation = selected == .mutation ? "mutation" : "replacement"
            emit("change-attempted", ["operation": operation]); reason = "layout-refused"
            let changed: Bool
            switch try staged.change() {
            case .completed:
                changed = true
                var details: [String: Any] = ["operation": operation]
                if selected == .mutation { details["offset"] = ScreenSnapshotRecipe.offset; details["before"] = 0; details["after"] = 1 }
                else { details["oldSnapshotRetained"] = true; details["pathNowReplacement"] = true }
                emit("change-completed", details)
            case .denied(let why): changed = false; emit("change-denied", ["operation": operation, "reason": why])
            }
            // Driver brackets each real call; timers/monitoring stay unchanged.
            reason = "inconclusive"
            try observe(.guest, pair: pair, verifier: verifier, owned: owned)
            try observe(.endpoint, pair: pair, verifier: verifier, owned: owned)
            guard results.complete else { throw ScreenFailure.incompatible }
            emit("result-ready"); try marker("snapshot-result-observed"); emit("result-observation-confirmed")
            reason = changed ? "observation-complete" : "change-denied"; code = changed ? 0 : 2
            if !owned.isAlive { reason = "guest-exited"; code = 2 }
        } catch is MarkerFailure { reason = "marker-timeout"; code = 2 }
        catch { if code == 0 { code = 2 } }
        if !cleanup() { reason = "cleanup-failed"; code = 1 }
        emit("terminal", ["reason": reason])
        outputLock.lock(); let failed = outputFailed; outputLock.unlock()
        complete(failed ? 2 : code)
    }
    private func observe(_ component: ScreenSnapshotResults.Component, pair: ScreenHandshake.Pair,
                         verifier: ScreenPeerVerifier, owned: ScreenChild) throws {
        try results.start(component)
        let observable = owned.isAlive && (component == .guest || !state({ associationLost }))
        emit("post-verifier-started", ["component": component.rawValue, "awaitingObservation": observable])
        // An unavailable component never consumes a marker. If it becomes lost
        // while the driver is sampling, consume only this requested marker and
        // report unavailable after rechecking; do not call a dead guest.
        if observable { try marker("snapshot-" + component.rawValue + "-observed") }
        let alive = owned.isAlive
        let available = observable && alive && (component == .guest || !state({ associationLost }))
        var fields: [String: Any] = ["component": component.rawValue, "called": available, "childAliveBefore": alive]
        if available {
            var guestInfo: [String: Any]?
            do {
                if component == .guest {
                    guestInfo = try ScreenPeerVerifier.verify(identity: pair.identity, identifier: "ai.sliccy.slicc")
                } else {
                    _ = try verifier.verifyCLI(socket: pair.safety.fd, expectedPID: owned.pid, expectedIdentity: pair.identity)
                }
                fields["outcome"] = "accepted"
            } catch { fields["outcome"] = "refused" }
            // Missing result metadata is a fixture failure, not a fabricated
            // verifier rejection after an actual successful invocation.
            if let guestInfo { fields["selectedCDHash"] = try hash(guestInfo) }
        } else { fields["outcome"] = "unavailable" }
        fields["childAliveAfter"] = owned.isAlive
        try results.end(component); emit("post-verifier-result", fields)
    }
    private func hash(_ info: [String: Any]) throws -> String {
        guard let value = info[kSecCodeInfoUnique as String] as? Data, value.count == 20 else { throw ScreenFailure.peerUntrusted }
        return value.map { String(format: "%02x", $0) }.joined()
    }
    private func publish(_ owned: ScreenChild) {
        stateLock.lock(); child = owned; published = true
        emit("child-started", ["pid": owned.pid])
        if lost { emit("child-gate-invalidated") }
        if reaped { emit("child-exit-reaped", ["pid": owned.pid]) }
        let stop = cancelled; stateLock.unlock()
        if stop { owned.stop() }
    }
    private func didLose() {
        let link = state { transport }; link?.quiesceOutput()
        stateLock.lock(); lost = true
        if published { emit("child-gate-invalidated") }
        stateLock.unlock()
    }
    private func didReap() {
        stateLock.lock(); reaped = true
        if published, let child { emit("child-exit-reaped", ["pid": child.pid]) }
        stateLock.unlock(); reapSignal.signal()
    }
    private func marker(_ text: String) throws {
        do { try readMarker(text) } catch { throw MarkerFailure.invalidOrExpired }
    }
    private func readMarker(_ text: String) throws {
        let expected = Array((text + "\n").utf8), deadline = ContinuousClock.now.advanced(by: .seconds(2))
        var index = 0
        while index < expected.count, ContinuousClock.now < deadline {
            guard !state({ cancelled }) else { throw ScreenFailure.stopped }
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let status = poll(&descriptor, 1, 25)
            if status == 0 || (status < 0 && errno == EINTR) { continue }
            var byte: UInt8 = 0
            guard status > 0, read(STDIN_FILENO, &byte, 1) == 1, byte == expected[index] else { throw ScreenFailure.incompatible }
            index += 1
        }
        guard index == expected.count else { throw ScreenFailure.stalled }
    }
    private func cleanup() -> Bool {
        let (owned, link) = state { (child, transport) }
        if let owned {
            owned.stop(); link?.close()
            if !state({ reaped }), reapSignal.wait(timeout: .now() + 2) != .success {
                owned.forceStop()
                guard reapSignal.wait(timeout: .now() + 1) == .success else { return false }
            }
            guard state({ reaped }) else { return false }
        }
        do { try subject?.cleanup(); return true } catch { return false }
    }
    private func emit(_ stage: String, _ fields: [String: Any] = [:]) {
        outputLock.lock(); defer { outputLock.unlock() }
        guard !outputFailed else { return }
        var row: [String: Any] = ["schema": 2, "case": selected.rawValue, "capture": false, "stage": stage,
                                  "elapsedMs": Self.seconds(began.duration(to: .now)) * 1000]
        fields.forEach { row[$0.key] = $0.value }
        do {
            var data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]); data.append(10)
            guard data.count <= 4096, data.count <= 65536 - outputBytes else { throw ScreenFailure.resourceLimit }
            outputBytes += data.count; try FileHandle.standardOutput.write(contentsOf: data)
        } catch { outputFailed = true }
    }
    private static func seconds(_ duration: Duration) -> Double {
        let value = duration.components; return Double(value.seconds) + Double(value.attoseconds) / 1e18
    }
}
#endif
