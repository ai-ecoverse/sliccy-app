#if SLICCY_NATIVE_SCREEN_PROOF
import AppKit
import Darwin
import Security
import ScreenSystem

enum ScreenUniversalCase: String, Sendable {
    case native = "universal-native", translated = "universal-translated"
    var architecture: String { self == .native ? "arm64" : "x86_64" }
    static func parse(_ arguments: [String]) throws -> Self {
        guard arguments.count == 3, arguments[0] == "--screen-proof", arguments[1] == "--case",
              let value = Self(rawValue: arguments[2]) else { throw ScreenFailure.incompatible }
        return value
    }
}

struct ScreenUniversalEvidence {
    var safety = false, frames = false, refusal = false, complete = false, lost = false
    mutating func observe(_ row: ScreenProofReport) {
        safety = safety || row.acceptedSafety; frames = frames || row.acceptedFrames
        refusal = refusal || (row.stage == "check" && row.outcome == "refused")
        complete = complete || row.stage == "complete"; lost = lost || row.lost
    }
    var nativePair: Bool { safety && frames && !refusal && !lost }
    var peerRefused: Bool { refusal && complete && !lost }
}

@MainActor
final class ScreenUniversalProofApp: NSObject, NSApplicationDelegate {
    private var session: ScreenUniversalProofSession?
    static func run() {
        signal(SIGPIPE, SIG_IGN)
        let delegate = ScreenUniversalProofApp(), app = NSApplication.shared
        app.delegate = delegate; app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let session = ScreenUniversalProofSession { code in Task { @MainActor in Darwin.exit(code) } }
        self.session = session; session.start()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        session?.cancel(); return .terminateLater
    }
}

/// No capture, grant or resource selection. Both app slices own the same exact
/// arm64 child. The external driver supplies all independent kernel/slice proof.
final class ScreenUniversalProofSession: @unchecked Sendable {
    private let stateLock = NSLock(), observerLock = NSLock(), outputLock = NSLock()
    private let began = ContinuousClock.now
    private let complete: @Sendable (Int32) -> Void
    private var selected = ScreenUniversalCase.native
    private var child: ScreenChild?
    private var transport: ScreenTransport?
    private var cancelled = false, published = false, reaped = false, lost = false
    private var gateReason = "no-transport"
    private var root: URL?
    private let reapSignal = DispatchSemaphore(value: 0), readySignal = DispatchSemaphore(value: 0)
    private let observerSignal = DispatchSemaphore(value: 0)
    private var observer = ScreenProofObserver(), evidence = ScreenUniversalEvidence()
    private var pending: [ScreenProofReport] = []
    private var forwarding = false, eof = false, outputFailed = false
    private var outputBytes = 0

    init(complete: @escaping @Sendable (Int32) -> Void) { self.complete = complete }
    private func state<T>(_ body: () throws -> T) rethrows -> T { stateLock.lock(); defer { stateLock.unlock() }; return try body() }
    private func observed<T>(_ body: () throws -> T) rethrows -> T { observerLock.lock(); defer { observerLock.unlock() }; return try body() }
    func cancel() {
        let child = state { cancelled = true; return self.child }
        child?.stop()
    }
    func start() {
        DispatchQueue(label: "ai.sliccy.proof.universal").async { [self] in run() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 35) { [weak self] in self?.cancel() }
    }
    private func run() {
        var reason = "native-timeout", code: Int32 = 2
        do {
            selected = try ScreenUniversalCase.parse(Array(ProcessInfo.processInfo.arguments.dropFirst()))
            var cpu: Int32 = 0, subtype: Int32 = 0
            guard sliccy_screen_proof_self_arch(&cpu, &subtype) == 0 else { throw ScreenFailure.incompatible }
            let architecture = cpu == 0x0100000c ? "arm64" : cpu == 0x01000007 ? "x86_64" : "unsupported"
            guard architecture != "unsupported" else { throw ScreenFailure.incompatible }
            emit("universal-started", fields: ["pid": getpid(), "reportedArchitecture": architecture])
            guard architecture == selected.architecture else { finish("architecture-mismatch", code: 1); return }
            do {
                let info = try ScreenPeerVerifier.verify(identity: ScreenAuditIdentity.current(), identifier: "ai.sliccy.mac")
                guard let hash = info[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else { throw ScreenFailure.peerUntrusted }
                emit("self-verification-accepted", fields: ["selectedCDHash": hash.map { String(format: "%02x", $0) }.joined()])
            } catch { emit("self-verification-refused"); finish("self-refused", code: 2); return }
            let join = try ScreenProofSession.readJoin()
            reason = "marker-timeout"; try marker("slice-app-observed")
            emit("app-observation-confirmed")
            let directory = try makeRoot()
            let policy = ScreenLaunchPolicy.universalAppProof(root: directory)
            let verifier = ScreenPeerVerifier(approvedHashes: policy.hashes)
            let handshake = try ScreenHandshake()
            reason = "native-timeout"
            let owned = try ScreenChild(executable: Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
                join: join, bootstrap: handshake.bootstrapRecord(), policy: policy,
                proofOutput: { [weak self] in self?.consume($0) },
                reaped: { [weak self] _ in self?.didReap() }, lost: { [weak self] in self?.didLose() })
            publish(owned)
            var paired = false
            do {
                let pair = try handshake.authenticate(pid: owned.pid, until: owned.deadline, verifier: verifier,
                    policy: policy, childAlive: { owned.isAlive })
                emit("lanes-authenticated")
                let link = ScreenTransport(pair: pair, verifier: verifier, noCapture: true, currentProtection: { false }, event: { [weak self] event in
                    if case .ready = event { self?.emit("heartbeat-ready"); self?.readySignal.signal() }
                })
                let keep = state { () -> Bool in
                    guard !cancelled, !lost else { return false }; transport = link; return true
                }
                guard keep else { link.close(); throw ScreenFailure.peerLost }
                link.start()
                let remaining = max(0, Self.seconds(ContinuousClock.now.duration(to: owned.deadline)))
                guard readySignal.wait(timeout: .now() + remaining) == .success, owned.isAlive else { throw ScreenFailure.stalled }
                paired = true
            } catch {
                if selected == .native { throw error }
                // EOF alone cannot prove translated-parent refusal. Inspect only
                // the released receiver's complete typed diagnostic below.
            }
            if selected == .native {
                guard paired, waitEvidence(until: owned.deadline, predicate: { $0.nativePair }) else { reason = "observer-inconclusive"; throw ScreenFailure.incompatible }
                emit("native-pair-observed"); reason = "native-observation-complete"; code = 0
            } else {
                guard !paired else { reason = "unexpected-acceptance"; code = 1; throw ScreenFailure.peerUntrusted }
                guard waitEvidence(until: .now.advanced(by: .seconds(1)), predicate: { $0.peerRefused }) else { reason = "observer-inconclusive"; throw ScreenFailure.incompatible }
                emit("cli-refusal-observed"); reason = "translated-refusal-observed"; code = 0
            }
            do { try marker("slice-result-observed") }
            catch { reason = "marker-timeout"; code = 2; throw error }
            emit("result-observation-confirmed")
            if selected == .native, !owned.isAlive { reason = "native-timeout"; code = 2 }
        } catch {
            if code == 0 { code = 2 }
        }
        if !cleanup() { reason = "cleanup-failed"; code = 1 }
        if code == 0 {
            let valid = waitEOF(until: .now.advanced(by: .seconds(1)))
            if !valid { reason = "observer-inconclusive"; code = 2 }
        }
        finish(reason, code: code)
    }
    private func makeRoot() throws -> URL {
        var template = Array("/private/tmp/sliccy-universal.XXXXXXXX".utf8CString)
        guard mkdtemp(&template) != nil else { throw ScreenFailure.audit }
        let value = URL(fileURLWithPath: String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
        root = value
        for name in ["tmp", "config"] { try FileManager.default.createDirectory(at: value.appending(path: name), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]) }
        return value
    }
    private func publish(_ owned: ScreenChild) {
        stateLock.lock()
        child = owned
        observerLock.lock()
        emit("child-started", fields: ["pid": owned.pid, "resource": "bundled-arm64-v1.59.0"])
        published = true; forwarding = true
        for row in pending { emit("cli-verification", fields: ["verification": row.metadata]) }
        pending.removeAll(); observerLock.unlock()
        if lost { emit("child-gate-invalidated", fields: ["reason": gateReason]) }
        if reaped { emit("child-exit-reaped", fields: ["pid": owned.pid]) }
        let stop = cancelled
        stateLock.unlock()
        if stop { owned.stop() }
    }
    private func didLose() {
        let current = state { transport }
        current?.quiesceOutput()
        stateLock.lock()
        lost = true; gateReason = current?.gate.isInvalidated == true ? "invalidated" : "no-transport"
        if published { emit("child-gate-invalidated", fields: ["reason": gateReason]) }
        stateLock.unlock()
    }
    private func didReap() {
        stateLock.lock(); reaped = true
        if published, let child { emit("child-exit-reaped", fields: ["pid": child.pid]) }
        stateLock.unlock(); reapSignal.signal()
    }
    private func consume(_ data: Data?) {
        observerLock.lock(); defer { observerLock.unlock(); observerSignal.signal() }
        do {
            if let data {
                if !observer.invalid {
                    for row in try observer.feed(data) {
                        evidence.observe(row)
                        if forwarding { emit("cli-verification", fields: ["verification": row.metadata]) }
                        else { pending.append(row) }
                    }
                }
            } else { eof = true; _ = observer.finish() }
        } catch { evidence.lost = true }
    }
    private func waitEvidence(until deadline: ContinuousClock.Instant, predicate: (ScreenUniversalEvidence) -> Bool) -> Bool {
        while ContinuousClock.now < deadline {
            if observed({ !observer.invalid && predicate(evidence) }) { return true }
            if state({ cancelled }) || observed({ observer.invalid || eof }) { return false }
            _ = observerSignal.wait(timeout: .now() + max(0, Self.seconds(ContinuousClock.now.duration(to: deadline))))
        }
        return observed { !observer.invalid && predicate(evidence) }
    }
    private func waitEOF(until deadline: ContinuousClock.Instant) -> Bool {
        while !observed({ eof }), ContinuousClock.now < deadline {
            _ = observerSignal.wait(timeout: .now() + max(0, Self.seconds(ContinuousClock.now.duration(to: deadline))))
        }
        return observed { eof && !observer.invalid && observer.complete }
    }
    private func marker(_ text: String) throws {
        let expected = Array((text + "\n").utf8), until = ContinuousClock.now.advanced(by: .seconds(2))
        var index = 0
        while index < expected.count, ContinuousClock.now < until {
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
        guard let owned else { return true }
        owned.stop(); link?.close()
        if !state({ reaped }), reapSignal.wait(timeout: .now() + 2) != .success {
            owned.forceStop()
            guard reapSignal.wait(timeout: .now() + 1) == .success else { return false }
        }
        return state { reaped }
    }
    private func finish(_ reason: String, code: Int32) {
        if let root, state({ child == nil || reaped }) { try? FileManager.default.removeItem(at: root) }
        emit("terminal", fields: ["reason": reason])
        outputLock.lock(); let failed = outputFailed; outputLock.unlock()
        complete(failed ? 2 : code)
    }
    private func emit(_ stage: String, fields: [String: Any] = [:]) {
        outputLock.lock(); defer { outputLock.unlock() }
        guard !outputFailed else { return }
        var row: [String: Any] = ["schema": 2, "case": selected.rawValue, "capture": false, "stage": stage,
                                  "elapsedMs": Self.seconds(began.duration(to: .now)) * 1000]
        for (key, value) in fields { row[key] = value }
        do {
            var data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]); data.append(10)
            guard data.count <= 4096, data.count <= 65536 - outputBytes else { throw ScreenFailure.resourceLimit }
            outputBytes += data.count
            try FileHandle.standardOutput.write(contentsOf: data)
        } catch { outputFailed = true }
    }
    private static func seconds(_ duration: Duration) -> Double {
        let value = duration.components
        return Double(value.seconds) + Double(value.attoseconds) / 1e18
    }
}
#endif
