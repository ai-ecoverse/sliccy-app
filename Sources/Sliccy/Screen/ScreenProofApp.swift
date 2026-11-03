#if SLICCY_NATIVE_SCREEN_PROOF
import AppKit
import Darwin
import Security
import ScreenSystem

/// Diagnostic-only app entry: no workspace, user defaults, capture or grant caller.
@MainActor
final class ScreenProofApp: NSObject, NSApplicationDelegate {
    private var session: ScreenProofSession?
    private var indicator: ScreenIndicator?
    private var relay: ScreenStopRelay?

    static func run() {
        signal(SIGPIPE, SIG_IGN)
        let delegate = ScreenProofApp()
        let app = NSApplication.shared
        app.delegate = delegate
        app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let session = ScreenProofSession(show: { [weak self] relay in
            Task { @MainActor in
                guard let self else { return }
                do {
                    self.relay = relay
                    self.indicator = try ScreenIndicator(recipient: "Local synthetic peer", scope: "None", relay: relay, diagnostic: true)
                    if let health = self.indicator?.health { self.session?.indicatorReady(health) }
                } catch { relay.invoke(.indicator) }
            }
        }, completed: { [weak self] code in
            Task { @MainActor in
                self?.indicator?.dismiss()
                Darwin.exit(code)
            }
        })
        self.session = session
        session.start()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        if let relay { relay.invoke(.stopped) }
        else { session?.close(.stopped) }
        return .terminateLater
    }
}

/// All rows are fixed stage/reason names and elapsed times, never peer data.
final class ScreenProofSession: @unchecked Sendable {
    private let lock = NSLock()
    private let outputLock = NSLock()
    private let startTime = ContinuousClock.now
    private let queue = DispatchQueue(label: "ai.sliccy.mac.proof", qos: .userInitiated)
    private let show: @Sendable (ScreenStopRelay) -> Void
    private let completed: @Sendable (Int32) -> Void
    private var child: ScreenChild?
    private var transport: ScreenTransport?
    private var root: URL?
    private var ready = false
    private var stopping = false
    private var closing = false
    private var finished = false
    private var reaped = false
    private var result: ScreenFailure?
    private var stopAt: ContinuousClock.Instant?
    private var proofCase = ScreenProofCase.base
    private var linked = false
    private var caseStarted = false
    private var lifecycleStop = false
    private var authenticatedIdentity: ScreenAuditIdentity?
    private var gateInvalidatedBeforeReap = false
    private var ancillaryObservation: ScreenAncillaryObservation?
    private var ancillaryCompleted = false
    private var observer = ScreenProofObserver()
    private var observerEnded = false
    private var observerFailureReported = false
    private var observerBaseline = false
    private var observerRefusal = false
    private var observerComplete = false
    private var helper: ScreenProofHelper?
    private var helperEnded = false
    private var helperGood = false
    private var helperWritten = false
    private var handoffAt: ContinuousClock.Instant?
    private var handoffDeadline: ContinuousClock.Instant?
    private var handoffLoss: ContinuousClock.Instant?
    private var handoffCompleted = false
    private var syntheticSource: ScreenProofSyntheticSource?
    private var indicatorHealth: ScreenIndicatorHealth?
    private var generatedGranted = false

    init(show: @escaping @Sendable (ScreenStopRelay) -> Void, completed: @escaping @Sendable (Int32) -> Void) {
        self.show = show; self.completed = completed
    }
    func start() {
        queue.async { [self] in
            do { try connect() }
            catch { close(error as? ScreenFailure ?? .incompatible) }
        }
        queue.asyncAfter(deadline: .now() + 40) { [self] in close(.stalled) }
    }

    private func connect() throws {
        let selected = try ScreenProofCase.parse(Array(ProcessInfo.processInfo.arguments.dropFirst()))
        locked { proofCase = selected }
        if selected == .frameHandoff {
            let source = try ScreenProofSyntheticSource()
            locked { syntheticSource = source }
            report("generated-source-verified")
        }
        let join = try Self.readJoin()
        var template = Array("/private/tmp/sliccy-proof.XXXXXXXX".utf8CString)
        guard mkdtemp(&template) != nil else { throw ScreenFailure.audit }
        let root = URL(fileURLWithPath: String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
        locked { self.root = root }
        for name in ["tmp", "config"] {
            try FileManager.default.createDirectory(at: root.appending(path: name), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        let policy = ScreenLaunchPolicy.noCaptureProof(root: root)
        let verifier = ScreenPeerVerifier(approvedHashes: policy.hashes)
        let handshake = try ScreenHandshake()
        let proofOutput: (@Sendable (Data?) -> Void)?
        if selected.isHandoff { proofOutput = { [weak self] data in self?.consumeObserver(data) } }
        else { proofOutput = nil }
        let child = try ScreenChild(executable: Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
            join: join, bootstrap: handshake.bootstrapRecord(), policy: policy, proofOutput: proofOutput,
            reaped: { [weak self] status in self?.childReaped(status) },
            lost: { [weak self] in self?.childLost() })
        guard locked({ () -> Bool in
            guard !closing else { return false }
            self.child = child; return true
        }) else { child.stop(); return }
        report("child-started", pid: selected == .base ? nil : child.pid)
        let pair = try handshake.authenticate(pid: child.pid, until: child.deadline, verifier: verifier,
            policy: policy, childAlive: { child.isAlive })
        report("lanes-authenticated")
        locked { authenticatedIdentity = pair.identity }
        let transport = ScreenTransport(pair: pair, verifier: verifier, noCapture: selected != .frameHandoff, currentProtection: { [weak self] in self?.generatedSourceReady == true },
            event: { [weak self] in self?.event($0) })
        guard locked({ () -> Bool in
            guard !closing else { return false }
            self.transport = transport; return true
        }) else { transport.close(); return }
        let relay = ScreenStopRelay(gate: transport.gate, observed: { [weak self] start, invalidated in
            guard let self else { return }
            let first = self.locked { () -> Bool in
                guard !self.stopping, !self.closing else { return false }
                self.stopping = true; self.stopAt = start; return true
            }
            if first { self.report("local-gate-invalidated", at: invalidated, duration: start.duration(to: invalidated)) }
        }, stop: { [weak transport] reason in transport?.stop(reason) })
        transport.start()
        show(relay)
        queue.asyncAfter(deadline: .now() + 30) { [weak self] in
            guard let self, self.locked({ self.proofCase == .base && !self.closing && !self.stopping }) else { return }
            self.report("automatic-stop")
            relay.invoke(.stopped)
        }
    }

    private func event(_ event: ScreenTransport.Event) {
        switch event {
        case .ready:
            locked { ready = true }; report("heartbeat-ready"); runCaseIfReady()
        case .proofControlSent(let at):
            report(controlStage("sent"), at: at)
        case .proofControlEchoed(let at):
            report(controlStage("echoed"), at: at)
            let transport = locked { self.transport }
            if locked({ proofCase == .frameHandoff }), let source = locked({ syntheticSource }) {
                transport?.proofGeneratedFrameAfterFreshControl(source) { [self] frames, record, deadline in
                    guard let child = locked({ self.child }), child.isAlive else { throw ScreenFailure.peerLost }
                    try transferSafety(safety: frames, cli: child.pid, record: record, deadline: deadline)
                }
                return
            }
            transport?.proofAfterFreshControl { [self] safety, frames, record, deadline in
                guard let child = locked({ self.child }), child.isAlive else { throw ScreenFailure.peerLost }
                if locked({ proofCase == .ancillary }) {
                    try injectAncillary(safety: safety, record: record, deadline: deadline)
                    return
                }
                if locked({ proofCase.isHandoff }) {
                    try transferSafety(safety: safety, cli: child.pid, record: record, deadline: deadline)
                    return
                }
                let helper = Bundle.main.bundleURL.appending(path: "Contents/Helpers/ScreenProofExecHelper")
                try Self.verifyExecHelper(helper)
                guard ContinuousClock.now < deadline else { throw ScreenFailure.stalled }
                report("parent-exec-requested", pid: getpid())
                let elapsed = startTime.duration(to: .now).components
                let nanos = UInt64(elapsed.seconds) * 1_000_000_000 + UInt64(elapsed.attoseconds / 1_000_000_000)
                let result = record.withUnsafeBytes {
                    sliccy_screen_proof_exec(helper.path, child.pid, safety, frames, $0.baseAddress, record.count, nanos)
                }
                report("parent-exec-failed")
                _ = result
                throw ScreenFailure.peerLost // A successful same-PID exec never returns.
            }
        case .link:
            locked { linked = true }; report("synthetic-link-observed"); runCaseIfReady()
        case .granted:
            guard locked({ proofCase == .frameHandoff && !generatedGranted }), let source = locked({ syntheticSource }),
                  let transport = locked({ transport }) else { close(.protection); return }
            locked { generatedGranted = true }; report("synthetic-granted")
            do {
                try transport.proofSubmitGeneratedBaseline(source)
                report("synthetic-baseline-submitted")
                queue.async { [self] in
                    do {
                        try Self.readBaselineMarker()
                        report("synthetic-baseline-confirmed")
                        try startHandoffHelper()
                    } catch { close(.incompatible) }
                }
            } catch { close(.protection) }
        case .revokeQueued(let at):
            report("revoke-queued", at: at)
        case .revocationConfirmed:
            report("native-ack", duration: locked { stopAt?.duration(to: .now) })
            close(locked { ready && stopping ? nil : .incompatible })
        case .stopped(let reason):
            let handoff = locked { () -> Bool in
                guard proofCase.isHandoff, handoffAt != nil, !closing, !stopping else { return false }
                if reason == .peerLost && handoffLoss == nil { handoffLoss = .now }
                return true
            }
            if handoff { report("handoff-association-lost", reason: reason.rawValue); return }
            let observed = locked { () -> Bool in
                guard proofCase == .ancillary, ancillaryObservation != nil, !closing, !stopping else { return false }
                if ancillaryObservation?.loss == nil { ancillaryObservation?.loss = (reason, .now) }
                return true
            }
            if observed {
                report("ancillary-association-lost", reason: reason.rawValue)
                return // Retain the child/Pion link until the fixed observation ends.
            }
            // stop() reports its local action before the matching peer ack.
            if !locked({ stopping }) || reason != .stopped { close(reason) }
        }
    }
    private func runCaseIfReady() {
        let selected: ScreenProofCase? = locked {
            guard ready, linked, !caseStarted, !closing, proofCase != .base else { return nil }
            if proofCase.isHandoff && !observerBaseline { return nil }
            if proofCase == .frameHandoff && indicatorHealth?.check() != true { return nil }
            caseStarted = true
            return proofCase
        }
        guard let selected else { return }
        queue.async { [self] in
            guard let transport = locked({ transport }) else { close(.peerLost); return }
            switch selected {
            case .base: return
            case .parentExec, .ancillary:
                transport.proofBeginExecControl()
            case .safetyHandoff:
                do { try startHandoffHelper() } catch { close(.peerUntrusted) }
            case .frameHandoff:
                do { try transport.proofGrantGeneratedSource(); report("synthetic-grant-requested") }
                catch { close(.protection) }
            case .lifecycle:
                guard let identity = locked({ authenticatedIdentity }),
                      (try? ScreenPeerVerifier.verify(identity: identity, identifier: "ai.sliccy.slicc")) != nil
                else { close(.peerUntrusted); return }
                report("lifecycle-live-token-accepted")
                let child = locked { () -> ScreenChild? in lifecycleStop = true; return self.child }
                report("lifecycle-stop-requested")
                child?.stop()
            }
        }
    }
    func indicatorReady(_ health: ScreenIndicatorHealth) {
        locked { indicatorHealth = health }; runCaseIfReady()
    }
    private var generatedSourceReady: Bool {
        locked { proofCase == .frameHandoff && syntheticSource != nil && indicatorHealth?.check() == true }
    }
    private func startHandoffHelper() throws {
        let url = Bundle.main.bundleURL.appending(path: "Contents/Helpers/ScreenProofHandoffHelper")
        try Self.verifyExecHelper(url)
        let helper = try ScreenProofHelper(executable: url.path, event: { [weak self] in self?.helperEvent($0) })
        let keep = locked { () -> Bool in
            guard !closing, self.helper == nil else { return false }; self.helper = helper; return true
        }
        report("handoff-helper-started", pid: helper.pid)
        if keep { try helper.start() } else { helper.stop() }
    }
    private static func readBaselineMarker() throws {
        let expected = Array("frame-baseline\n".utf8)
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        var offset = 0
        while offset < expected.count, ContinuousClock.now < deadline {
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let status = poll(&descriptor, 1, 25)
            if status == 0 || (status < 0 && errno == EINTR) { continue }
            var byte: UInt8 = 0
            guard status > 0, read(STDIN_FILENO, &byte, 1) == 1, byte == expected[offset] else { throw ScreenFailure.incompatible }
            offset += 1
        }
        guard offset == expected.count else { throw ScreenFailure.stalled }
    }
    private func controlStage(_ suffix: String) -> String {
        locked { (proofCase == .ancillary ? "ancillary" : proofCase.isHandoff ? "handoff" : "exec") + "-control-" + suffix }
    }
    private func consumeObserver(_ data: Data?) {
        if data != nil, locked({ observer.invalid }) { return }
        do {
            let rows = try locked { () throws -> [ScreenProofReport] in
                if let data { return try observer.feed(data) }
                observerEnded = true
                guard observer.finish() else { throw ScreenFailure.incompatible }
                return []
            }
            for row in rows {
                locked {
                    observerBaseline = observerBaseline || (proofCase == .frameHandoff ? row.acceptedFrames : row.acceptedSafety)
                    observerRefusal = observerRefusal || ((proofCase == .frameHandoff ? row.refusedFrames : row.refusedSafety) && handoffAt != nil)
                    if row.stage == "complete" { observerComplete = !row.lost }
                }
                report("cli-verification", observerRow: row)
            }
            runCaseIfReady()
            if data == nil, locked({ reaped }) { finish(locked { result }) }
        } catch {
            let first = locked { () -> Bool in
                result = .incompatible
                guard !observerFailureReported else { return false }
                observerFailureReported = true; return true
            }
            if first { report("cli-verification-inconclusive") }
            // connect() publishes the owned child before this queue advances.
            // A malformed startup row cannot exit the app before ownership exists.
            queue.async { [self] in
                close(.incompatible)
                if locked({ reaped }) { finish(.incompatible) }
            }
        }
    }
    private func helperEvent(_ value: ScreenProofHelper.Event) {
        switch value {
        case .stage(let stage):
            report("handoff-helper-" + stage)
            if stage == "ready" { locked { transport }?.proofBeginExecControl(keepHeartbeats: locked { proofCase == .frameHandoff }) }
            if stage == "written" {
                locked { helperWritten = handoffDeadline.map { ContinuousClock.now < $0 } == true }
            }
        case .finished(let success):
            locked { helperEnded = true; helperGood = success }
            report("handoff-helper-reaped", reason: success ? "complete" : "failed")
            if !success { close(.peerLost) }
            if locked({ reaped }) { finish(locked { result }) }
        }
    }
    private func transferSafety(safety: Int32, cli: pid_t, record: Data, deadline: ContinuousClock.Instant) throws {
        let now = ContinuousClock.now
        let helper = locked { () -> ScreenProofHelper? in
            guard !closing, !stopping, observerBaseline, !observer.invalid, handoffAt == nil,
                  now < deadline, let helper else { return nil }
            handoffAt = now; handoffDeadline = deadline
            return helper
        }
        guard let helper else { throw ScreenFailure.incompatible }
        report("handoff-send-started", at: now)
        try helper.transfer(safety: safety, cli: cli, record: record)
        report("handoff-record-transferred")
        queue.asyncAfter(deadline: .now() + 2.5) { [self] in
            let alive = locked { child }?.isAlive == true
            let passed = locked { () -> Bool in
                guard !closing, !stopping, alive, helperEnded, helperGood, helperWritten,
                      observerBaseline, observerRefusal, observerComplete, !observer.invalid,
                      let start = handoffAt, let loss = handoffLoss,
                      loss >= start, start.duration(to: loss) <= .milliseconds(500) else { return false }
                handoffCompleted = true; return true
            }
            report("handoff-observation-ended", reason: passed ? "elapsed" : "inconclusive")
            close(passed ? nil : .incompatible)
        }
    }
    private func injectAncillary(safety: Int32, record: Data, deadline: ContinuousClock.Instant) throws {
        let began = ContinuousClock.now
        guard began < deadline, locked({ () -> Bool in
            guard !closing, !stopping, ancillaryObservation == nil else { return false }
            ancillaryObservation = ScreenAncillaryObservation(started: began)
            return true
        }) else { throw ScreenFailure.stalled }
        report("ancillary-send-started", at: began)
        let result = record.withUnsafeBytes { sliccy_screen_proof_ancillary(safety, $0.baseAddress, record.count) }
        locked { ancillaryObservation?.fullWrite = result == 0 }
        report(result == 0 ? "ancillary-record-sent" : "ancillary-send-refused")
        // Do not close locally in response to EOF: the external driver needs
        // the still-live CLI/Pion link to observe its independent refusal state.
        // A passing refusal is within 500ms, leaving at least two seconds for
        // the driver to inspect the still-owned live receiver after refusal.
        queue.asyncAfter(deadline: .now() + 2.5) { [self] in
            let alive = locked { child }?.isAlive == true
            let observed = locked { () -> Bool in
                guard !closing, !stopping else { return false }
                ancillaryCompleted = ancillaryObservation?.completed(at: .now, childAlive: alive) == true
                return ancillaryCompleted
            }
            report("ancillary-observation-ended", reason: observed ? "elapsed" : "failed")
            close(observed ? nil : .incompatible)
        }
    }
    func close(_ failure: ScreenFailure?) {
        let owned: (ScreenTransport?, ScreenChild?)? = locked {
            guard !closing else { return nil }
            closing = true; result = failure
            return (transport, child)
        }
        guard let owned else { return }
        if let helper = locked({ helperEnded ? nil : helper }) { helper.stop() }
        owned.0?.close()
        if let child = owned.1 {
            child.stop()
            queue.asyncAfter(deadline: .now() + 2) { [self] in
                // A missing reap is a failure, never a successful shutdown claim.
                if !locked({ finished }) {
                    locked { result = .stalled }
                    child.forceStop()
                    queue.asyncAfter(deadline: .now() + 1) { [self] in finish(.stalled) }
                }
            }
        } else { finish(failure) }
    }
    private func childLost() {
        let activeTransport = locked { transport }
        activeTransport?.quiesceOutput()
        let invalid = activeTransport?.gate.isInvalidated == true
        let extended = locked { () -> Bool in
            gateInvalidatedBeforeReap = invalid && !reaped
            return proofCase != .base
        }
        if extended { report("child-gate-invalidated", reason: invalid ? "invalidated" : "no-transport") }
        report("child-authority-invalidated")
        // The exit monitor reaps next. Keep ownership until that callback.
        let active = locked { () -> Bool in
            // The child can exit during its initializer, before ownership is
            // published here. Its reap callback (or the initializer's error)
            // completes that case; do not exit the app before reaping it.
            if child == nil { result = .peerLost; return false }
            return !closing
        }
        if active { close(locked { lifecycleStop && gateInvalidatedBeforeReap ? nil : .peerLost }) }
    }
    private func childReaped(_ status: Int32) {
        report("child-exit-reaped")
        var failure = locked { () -> ScreenFailure? in
            reaped = true
            if !closing { closing = true; result = .peerLost }
            return result
        }
        if locked({ proofCase == .lifecycle && lifecycleStop }) {
            if let identity = locked({ authenticatedIdentity }), locked({ gateInvalidatedBeforeReap }) {
                do {
                    _ = try ScreenPeerVerifier.verify(identity: identity, identifier: "ai.sliccy.slicc")
                    report("stale-token-accepted")
                    failure = .peerUntrusted
                } catch {
                    report("stale-token-refused")
                }
            } else { failure = .peerUntrusted }
        }
        finish(failure)
    }
    private func finish(_ failure: ScreenFailure?) {
        if locked({ proofCase.isHandoff && failure != .stalled &&
            ((!observerEnded && child != nil) || (helper != nil && !helperEnded)) }) { return }
        let failure = failure ?? locked {
            (proofCase == .ancillary && !ancillaryCompleted) ||
            (proofCase.isHandoff && (!handoffCompleted || observer.invalid)) ? .incompatible : nil
        }
        let outcome: (Bool, URL?) = locked {
            guard !finished else { return (false, nil) }
            finished = true
            return (true, child == nil || reaped ? root : nil)
        }
        guard outcome.0 else { return }
        // root may be nil when stdin validation fails.
        if let cleanup = outcome.1 { try? FileManager.default.removeItem(at: cleanup) }
        let success = locked {
            switch proofCase {
            case .lifecycle: "lifecycle-only-complete"
            case .ancillary: "ancillary-observation-complete"
            case .safetyHandoff, .frameHandoff: "handoff-observation-complete"
            default: "ipc-only-complete"
            }
        }
        report("terminal", reason: failure?.rawValue ?? success)
        completed(failure == nil ? 0 : 1)
    }
    private func report(_ stage: String, at: ContinuousClock.Instant = .now, duration: Duration? = nil, reason: String? = nil, pid: pid_t? = nil, observerRow: ScreenProofReport? = nil) {
        func milliseconds(_ duration: Duration) -> Double {
            let value = duration.components
            return Double(value.seconds) * 1000 + Double(value.attoseconds) / 1e15
        }
        var row: [String: Any] = ["schema": 1, "stage": stage, "elapsedMs": milliseconds(startTime.duration(to: at)), "capture": false]
        let selected = locked { proofCase }
        if selected != .base { row["schema"] = 2; row["case"] = selected.rawValue }
        if let observerRow { row["verification"] = observerRow.metadata }
        if let pid { row["pid"] = pid }
        if let duration { row["durationMs"] = milliseconds(duration) }
        if let reason { row["reason"] = reason }
        outputLock.lock(); defer { outputLock.unlock() }
        if var data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]) {
            data.append(10); try? FileHandle.standardOutput.write(contentsOf: data)
        }
    }
    private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }

    private static func verifyExecHelper(_ url: URL) throws {
        try ScreenPeerVerifier.verifySelf()
        var code: SecStaticCode?, requirement: SecRequirement?
        let rule = "anchor apple generic and identifier \"ai.sliccy.proof-helper\" and certificate leaf[subject.OU] = \"S8LB56P782\""
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString(rule as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
        else { throw ScreenFailure.peerUntrusted }
    }

    static func validateJoin(_ raw: String) throws -> String {
        guard raw.utf8.count <= 4096, !raw.contains("\n"), !raw.contains("\r"),
              let url = URLComponents(string: raw), url.scheme == "http", url.host == "127.0.0.1",
              let port = url.port, port >= 1024, port <= 65535, !(9222...9229).contains(port),
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.hasPrefix("/join/"), !url.path.dropFirst(6).isEmpty else { throw ScreenFailure.incompatible }
        return raw
    }
    private static func readJoin() throws -> String {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        var data = Data()
        while ContinuousClock.now < deadline, data.count <= 4096 {
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let ready = poll(&descriptor, 1, 25)
            if ready < 0, errno == EINTR { continue }
            if ready == 0 { continue }
            guard ready > 0 else { throw ScreenFailure.incompatible }
            var byte: UInt8 = 0
            guard read(STDIN_FILENO, &byte, 1) == 1 else { throw ScreenFailure.incompatible }
            if byte == 10 {
                guard let raw = String(data: data, encoding: .utf8) else { throw ScreenFailure.incompatible }
                return try validateJoin(raw)
            }
            data.append(byte)
        }
        throw ScreenFailure.incompatible
    }
}
#endif
