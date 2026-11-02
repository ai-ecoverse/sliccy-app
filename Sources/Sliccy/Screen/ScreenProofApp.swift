#if SLICCY_NATIVE_SCREEN_PROOF
import AppKit
import Darwin

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
        guard ProcessInfo.processInfo.arguments.count == 2 else { throw ScreenFailure.incompatible }
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
        let child = try ScreenChild(executable: Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
            join: join, bootstrap: handshake.bootstrapRecord(), policy: policy,
            reaped: { [weak self] status in self?.childReaped(status) },
            lost: { [weak self] in self?.childLost() })
        guard locked({ () -> Bool in
            guard !closing else { return false }
            self.child = child; return true
        }) else { child.stop(); return }
        report("child-started")
        let pair = try handshake.authenticate(pid: child.pid, until: child.deadline, verifier: verifier,
            policy: policy, childAlive: { child.isAlive })
        report("lanes-authenticated")
        let transport = ScreenTransport(pair: pair, verifier: verifier, noCapture: true, currentProtection: { false },
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
            guard let self, !self.locked({ self.closing || self.stopping }) else { return }
            self.report("automatic-stop")
            relay.invoke(.stopped)
        }
    }

    private func event(_ event: ScreenTransport.Event) {
        switch event {
        case .ready:
            locked { ready = true }; report("heartbeat-ready")
        case .link:
            report("synthetic-link-observed")
        case .granted:
            close(.protection) // No diagnostic code may request a grant.
        case .revokeQueued(let at):
            report("revoke-queued", at: at)
        case .revocationConfirmed:
            report("native-ack", duration: locked { stopAt?.duration(to: .now) })
            close(locked { ready && stopping ? nil : .incompatible })
        case .stopped(let reason):
            // stop() reports its local action before the matching peer ack.
            if !locked({ stopping }) || reason != .stopped { close(reason) }
        }
    }
    func close(_ failure: ScreenFailure?) {
        let owned: (ScreenTransport?, ScreenChild?)? = locked {
            guard !closing else { return nil }
            closing = true; result = failure
            return (transport, child)
        }
        guard let owned else { return }
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
        report("child-authority-invalidated")
        // The exit monitor reaps next. Keep ownership until that callback.
        let active = locked { () -> Bool in
            // The child can exit during its initializer, before ownership is
            // published here. Its reap callback (or the initializer's error)
            // completes that case; do not exit the app before reaping it.
            if child == nil { result = .peerLost; return false }
            return !closing
        }
        if active { close(.peerLost) }
    }
    private func childReaped(_ status: Int32) {
        report("child-exit-reaped")
        let failure = locked { () -> ScreenFailure? in
            reaped = true
            if !closing { closing = true; result = .peerLost }
            return result
        }
        finish(failure)
    }
    private func finish(_ failure: ScreenFailure?) {
        let outcome: (Bool, URL?) = locked {
            guard !finished else { return (false, nil) }
            finished = true
            return (true, child == nil || reaped ? root : nil)
        }
        guard outcome.0 else { return }
        // root may be nil when stdin validation fails.
        if let cleanup = outcome.1 { try? FileManager.default.removeItem(at: cleanup) }
        report("terminal", reason: failure?.rawValue ?? "ipc-only-complete")
        completed(failure == nil ? 0 : 1)
    }
    private func report(_ stage: String, at: ContinuousClock.Instant = .now, duration: Duration? = nil, reason: String? = nil) {
        func milliseconds(_ duration: Duration) -> Double {
            let value = duration.components
            return Double(value.seconds) * 1000 + Double(value.attoseconds) / 1e15
        }
        var row: [String: Any] = ["schema": 1, "stage": stage, "elapsedMs": milliseconds(startTime.duration(to: at)), "capture": false]
        if let duration { row["durationMs"] = milliseconds(duration) }
        if let reason { row["reason"] = reason }
        outputLock.lock(); defer { outputLock.unlock() }
        if var data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]) {
            data.append(10); try? FileHandle.standardOutput.write(contentsOf: data)
        }
    }
    private func locked<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }

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
