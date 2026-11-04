#if SLICCY_CAPTURE_RUNNER_PROOF
import AppKit
import Carbon
import Darwin

@MainActor
final class ScreenRunnerProofApp: NSObject, NSApplicationDelegate {
    private var session: ScreenRunnerSession?
    static func run() {
        guard (try? ScreenRunnerHost.require()) != nil else { exit(2) }
        signal(SIGPIPE, SIG_IGN); umask(0o077)
        let delegate = ScreenRunnerProofApp(), app = NSApplication.shared
        app.delegate = delegate; app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        do {
            let session = try ScreenRunnerSession(); self.session = session
            Task { await session.run() }
        } catch { exit(2) }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        session?.cancel(); return .terminateLater
    }
}

@MainActor
final class ScreenRunnerSession {
    private let selected: ScreenRunnerCase
    private let journal: ScreenRunnerJournal
    private let diagnosticAbort: ScreenRunnerDiagnosticAbort
    private let causes: ScreenRunnerCauseLedger
    private var connection: ScreenRunnerConnection?
    private var indicator: ScreenIndicator?
    private var relay: ScreenStopRelay?
    private var capture: ScreenCapture?
    private var captureLimit: ScreenRunnerCaptureLimit?
    private var sourceMonitor: Task<Void, Never>?
    private var owned: [(String, ScreenRunnerOwnedProcess)] = []
    private var primaries: [ScreenRunnerOwnedProcess] = []
    private var ready = false, linked = false, granted = false, captureStarted = false
    private var ownAck = false, reset = false, stopping = false, cleaning = false, cancelled = false
    private var failure: ScreenFailure?
    private var stopAt: ContinuousClock.Instant?
    private var root: URL?, rootFD: Int32 = -1, rootStat = stat()
    private var reverseComplete = false, reverseSeen = false, inventoryUnavailable = false
    private var audit: ScreenAudit?
    init() throws {
        selected = try ScreenRunnerHost.require()
        let abort = ScreenRunnerDiagnosticAbort(); diagnosticAbort = abort
        let output = try ScreenRunnerJournal(selected, authorityFailed: { abort.fail() })
        journal = output
        causes = ScreenRunnerCauseLedger { notice in
            output.emit("first-cause", ["kind": notice.kind.rawValue, "reason": notice.reason.value,
                "phase": notice.phase.rawValue, "origin": notice.origin.rawValue], at: notice.at)
        }
    }
    func cancel(origin: ScreenStopRelay.Origin = .cancelled) {
        let at = ContinuousClock.now
        cancelled = true
        if let relay { relay.invoke(.stopped, origin: origin) }
        else {
            connection?.health.invalidate(); connection?.transport?.stop(.stopped)
            causes.record(.stop, reason: .screen(.stopped), origin: origin, at: at)
        }
        connection?.health.invalidate()
    }
    func run() async {
        var outcome = "failed", reason = "fixed-failure", exitCode: Int32 = 1
        let watchdog = Task { try? await Task.sleep(for: .seconds(40)); if !Task.isCancelled { cancel(origin: .watchdog) } }
        defer { watchdog.cancel() }
        do {
            try ScreenPeerVerifier.verifySelf()
            let screen = CGPreflightScreenCaptureAccess(), listen = CGPreflightListenEventAccess(), post = CGPreflightPostEventAccess()
            journal.emit("runner-preflight", ["screenCapture": screen, "listenEvent": listen, "postEvent": post, "hosted": true, "osMajor": 27, "architecture": "arm64"])
            try check()
            guard screen, selected != .hotkeyStop || (listen && post), NSScreen.main != nil else { reason = "permission-unavailable"; exitCode = 2; throw ScreenFailure.permission }
            causes.advance(.preparing)
            let join = try await Task.detached { try ScreenProofSession.readJoin() }.value
            let home = try prepareHome()
            audit = try ScreenAudit(base: home.appending(path: "Library/Application Support"))
            let surface = try ScreenRunnerOwnedProcess.surface(home: home, ended: surfaceEnded("allowed"))
            owned.append(("allowed", surface)); primaries.append(surface)
            try reportOwned(surface.recordedIdentity)
            journal.emit("surface-process", ["label": "allowed", "pid": surface.pid, "bundleIdentifier": "ai.sliccy.proof-helper"])
            var browsers: [ScreenRunnerOwnedProcess] = []
            if selected.needsBrowser {
                for window in ScreenRunnerBrowserWindow.allCases {
                    let label = "chrome-" + window.profile
                    let child = try ScreenRunnerOwnedProcess.chrome(window: window, join: join, home: home, evidence: { [journal] phase, evidence in
                        var fields = evidence.fields; fields["label"] = label; fields["phase"] = phase
                        journal.emit("chrome-identity", fields, at: evidence.observedAt)
                    }, evidenceLost: { [journal] in journal.rejectEvidence() }, ended: surfaceEnded(label))
                    owned.append((label, child))
                    try reportOwned(child.recordedIdentity)
                    journal.emit("surface-launcher-started", ["label": label, "pid": child.pid])
                    if window == .a1 || window == .b1 {
                        browsers.append(child); primaries.append(child)
                        journal.emit("surface-process", ["label": label, "pid": child.pid, "bundleIdentifier": "com.google.Chrome"])
                    }
                }
            }
            var authorization: ScreenRunnerOwnedProcess?
            if selected == .authorizationExclusion {
                guard try await !ScreenRunnerInventory.authorizationWindowExists() else { reason = "authorization-preexisting"; exitCode = 2; throw ScreenFailure.protection }
                let requester = try ScreenRunnerOwnedProcess.authorization(home: home, ended: surfaceEnded("authorization-requester"))
                owned.append(("authorization-requester", requester)); authorization = requester
                try reportOwned(requester.recordedIdentity)
                journal.emit("surface-launcher-started", ["label": "authorization-requester", "pid": requester.pid])
            }
            let causes = self.causes
            let connection = ScreenRunnerConnection { [weak self, causes] event in
                if case .transport(.revokeQueued(_, let began, _)) = event { causes.noteStop(at: began) }
                if case .lost = event { causes.record(.childLoss, reason: .screen(.peerLost), origin: .nativeChild) }
                Task { @MainActor in self?.consume(event) }
            }
            self.connection = connection
            diagnosticAbort.register { connection.abortDiagnostic() }
            try check()
            try await Task.detached { try connection.open(root: home, join: join) }.value
            guard let transport = connection.transport else { throw ScreenFailure.peerLost }
            let journal = self.journal
            let relay = ScreenStopRelay(gate: transport.gate, entered: { origin, at in
                if origin == .button || origin == .hotkey { journal.emit("stop-handler-entered", ["trigger": origin == .button ? "button" : "hotkey"], at: at) }
            }, observed: { start, invalidated in
                journal.gateInvalidated(start: start, end: invalidated)
            }, cause: { reason, origin, at in
                causes.record(.stop, reason: .screen(reason), origin: origin, at: at)
            }, stop: { reason in transport.stop(reason) })
            self.relay = relay
            indicator = try ScreenIndicator(recipient: "Synthetic runner peer", scope: "Owned synthetic surface", relay: relay)
            guard let indicator else { throw ScreenFailure.indicator }
            try indicator.proofPlace()
            causes.advance(.inventory)
            var inventory: ScreenRunnerInventory?
            var inventoryIssue: ScreenRunnerInventoryIssue = .unknown
            let inventoryDeadline = ContinuousClock.now.advanced(by: .seconds(5))
            while inventory == nil, ContinuousClock.now < inventoryDeadline {
                try check()
                do { inventory = try await ScreenRunnerInventory.read(surface: surface, browsers: browsers, selected: selected, authorization: authorization) }
                catch { inventoryIssue = error as? ScreenRunnerInventoryIssue ?? .unknown }
                if inventory == nil { try await Task.sleep(for: .milliseconds(50)) }
            }
            guard let inventory else {
                reportInventoryUnavailable(inventoryIssue)
                reason = "surface-unavailable"; exitCode = 2; throw ScreenFailure.protection
            }
            if selected.needsBrowser { journal.emit("surface-process", ["label": "app", "pid": getpid(), "bundleIdentifier": "ai.sliccy.mac"]) }
            if let authorizationWindow = inventory.windows.first(where: { $0.label == "authorization" }), let owner = authorizationWindow.value.owningApplication {
                journal.emit("surface-process", ["label": "authorization", "pid": owner.processID, "bundleIdentifier": owner.bundleIdentifier])
            }
            report(inventory)
            journal.emit("surfaces-ready", ["counts": ["processes": Set(inventory.windows.compactMap { $0.value.owningApplication?.processID }).count, "windows": inventory.windows.count]])
            try await marker("runner-surfaces-observed", timeout: .seconds(5))
            causes.advance(.consent)
            try audit?.record(.consent, reason: "active", scope: selected.scope, session: nil)
            let refreshed: ScreenRunnerInventory
            do { refreshed = try await ScreenRunnerInventory.read(surface: surface, browsers: browsers, selected: selected, authorization: authorization) }
            catch { reportInventoryUnavailable(error as? ScreenRunnerInventoryIssue ?? .unknown); throw error }
            guard inventory.fingerprint == refreshed.fingerprint else { throw ScreenFailure.sourceChanged }
            journal.emit("surfaces-confirmed")
            let source = try ScreenRunnerCaptureSource.make(inventory: refreshed, selected: selected) { refusal in
                var fields: [String: Any] = ["label": refusal.label.rawValue, "type": refusal.type, "pid": refusal.pid, "predicateEvidence": refusal.predicateEvidence]
                if let id = refusal.windowID { fields["windowID"] = id }
                journal.emit("protected-selection-refused", fields)
            }
            journal.emit("source-validated", ["scope": selected.scope, "allowedWindowCount": 1, "protectedWindowCount": refreshed.windows.count - 1, "emptyExceptions": true])
            connection.health.install(indicator: indicator.health, owners: primaries)
            let frozenInventory = refreshed.fingerprint
            sourceMonitor = Task { [weak self] in
                while !Task.isCancelled {
                    do {
                        try await Task.sleep(for: .milliseconds(250))
                        guard let self, !self.cleaning, !self.stopping, !Task.isCancelled else { return }
                        let next = try await ScreenRunnerInventory.read(surface: surface, browsers: browsers, selected: self.selected, authorization: authorization)
                        guard !Task.isCancelled, !self.cleaning, !self.stopping else { return }
                        guard next.fingerprint == frozenInventory else { throw ScreenFailure.sourceChanged }
                        connection.health.renewSource()
                    } catch {
                        guard let self, !Task.isCancelled, !self.cleaning, !self.stopping else { return }
                        self.failure = .sourceChanged; self.relay?.invoke(.sourceChanged, origin: .sourceMonitor)
                        self.reportInventoryUnavailable(error as? ScreenRunnerInventoryIssue ?? .sourceChanged); return
                    }
                }
            }
            try await until(.seconds(3)) { self.ready && self.linked }
            causes.advance(.granting)
            try audit?.record(.grantIntent, reason: "active", scope: selected.scope, session: nil)
            journal.emit("grant-requested"); try transport.proofGrantCaptured(scope: selected.scope)
            try await until(.milliseconds(1500)) { self.granted }
            guard let binding = currentBinding else { throw ScreenFailure.incompatible }
            try audit?.record(.grant, reason: "active", scope: selected.scope, session: binding.session)
            let capture = ScreenCapture(gate: transport.gate, binding: binding, protection: { connection.health.check() },
                output: { image in try transport.proofSubmitCaptured(image) }, failure: { [weak self] reason in
                    Task { @MainActor in if let self, !self.stopping && !self.cleaning { self.failure = reason; self.relay?.invoke(reason, origin: .captureFailure) } }
                })
            self.capture = capture
            diagnosticAbort.register { capture.stop(.stalled) }
            try check()
            let limit = ScreenRunnerCaptureLimit { [transport, capture, causes] in
                let at = ContinuousClock.now
                transport.stop(.stalled); capture.stop(.stalled)
                causes.record(.stop, reason: .screen(.stalled), origin: .captureLimit, at: at)
            }
            captureLimit = limit; limit.arm()
            causes.advance(.capturing)
            try await capture.startProof(source: source); captureStarted = true; journal.emit("capture-started")
            let captureDeadline = ContinuousClock.now.advanced(by: .seconds(10))
            try await marker("runner-baseline", timeout: .seconds(5)); try check(); journal.emit("baseline-confirmed")
            if selected == .reciprocalRevoke {
                try await until(.milliseconds(1500)) { self.stopping }
            } else {
                let trigger = selected == .hotkeyStop ? "hotkey" : "button"
                stopAt = .now; journal.emit("stop-requested", ["trigger": trigger], at: stopAt!)
                if selected == .hotkeyStop { try Self.injectFixedShortcut() } else { try indicator.proofPressStop() }
            }
            try await until(.milliseconds(1500)) { self.stopping }
            try await marker("runner-receiver-reset", timeout: .milliseconds(1500)); reset = true; journal.emit("receiver-reset-confirmed")
            try await until(.milliseconds(1500)) { self.selected == .reciprocalRevoke ? self.reverseComplete : self.ownAck && (!self.reverseSeen || self.reverseComplete) }
            guard ContinuousClock.now < captureDeadline, reset, !journal.failed else { throw ScreenFailure.stalled }
            capture.stop(.stopped)
            guard await capture.proofAwaitStopped() else { throw ScreenFailure.sourceChanged }
            try check()
            journal.emit("capture-stopped")
            try audit?.record(.stop, reason: "stopped", scope: selected.scope, session: binding.session)
            outcome = "complete"; reason = "complete"; exitCode = 0
        } catch {
            causes.record(.failure, reason: .error(error), origin: .fixture)
            if inventoryUnavailable { reason = "surface-unavailable"; exitCode = 2 }
            if exitCode == 2 { outcome = "failed-to-demonstrate" }
            if cancelled { outcome = "failed"; reason = "interrupted"; exitCode = 1 }
        }
        causes.advance(.cleanup)
        cleaning = true; sourceMonitor?.cancel(); captureLimit?.cancel(); connection?.health.invalidate(); capture?.stop(.stopped)
        indicator?.dismiss()
        var cleaned = true
        if let transport = connection?.transport {
            let starts = [stopAt, causes.firstStopAt].compactMap { $0 }
            let deadline = starts.min()?.advanced(by: .milliseconds(1500)) ?? .now
            let snapshot = await Task.detached { transport.proofFinalClose(until: deadline) }.value
            reportReverse(snapshot.notices)
            journal.emit("reverse-ledger-closed", ["requests": snapshot.requests, "written": snapshot.written,
                "pending": snapshot.pending, "pendingAtCutoff": snapshot.cutoff.pending,
                "readInFlightAtCutoff": snapshot.cutoff.readInFlight,
                "transportWasOpen": snapshot.cutoff.transportWasOpen, "invalid": snapshot.invalid,
                "workersSettled": snapshot.workersSettled, "complete": snapshot.succeeded], at: snapshot.cutoff.at)
            if outcome == "complete" && (!snapshot.succeeded || failure != nil || (selected == .reciprocalRevoke && snapshot.requests == 0)) {
                causes.record(.failure, reason: .screen(.incompatible), origin: .remote)
                outcome = "failed"; reason = "reverse-incomplete"; exitCode = 1
            }
        } else if outcome == "complete" {
            outcome = "failed"; reason = "reverse-incomplete"; exitCode = 1
        }
        if let connection {
            do {
                if let pid = try await Task.detached(operation: { try connection.stopAndReap() }).value { reportNativeReap(pid) }
            } catch { cleaned = false; causes.record(.failure, reason: .error(error), origin: .nativeChild) }
        }
        drainReverse()
        for (_, process) in owned { process.stop() }
        let cleanupRemaining = max(0, 45 - ScreenRunnerJournal.ms(journal.began.duration(to: .now)) / 1000)
        let cleanupDeadline = DispatchTime.now() + cleanupRemaining
        for (label, process) in owned {
            do { try await Task.detached { try process.stopAndReap(until: min(cleanupDeadline, .now() + 3)) }.value } catch { cleaned = false; causes.record(.failure, reason: .error(error), origin: .launcher) }
            if process.hasReaped { reportReap(pid: process.pid, label: label) }
        }
        if !removeHome() { cleaned = false; causes.record(.failure, reason: .screen(.audit), origin: .fixture) }
        if !cleaned || journal.began.duration(to: .now) > .seconds(45) || journal.failed { outcome = "failed"; reason = "cleanup-failed"; exitCode = 1 }
        if journal.failed { outcome = "failed-to-demonstrate"; reason = "diagnostic-loss"; exitCode = 2 }
        if outcome != "complete" { causes.record(.failure, reason: journal.failed ? .screen(.resourceLimit) : .screen(.stalled), origin: journal.failed ? .diagnostic : .fixture) }
        causes.advance(.finished)
        let delivered = journal.emit("terminal", ["outcome": outcome, "reason": reason])
        Darwin.exit(delivered && !journal.failed ? exitCode : 2)
    }
    private func reportInventoryUnavailable(_ issue: ScreenRunnerInventoryIssue) {
        guard !inventoryUnavailable else { return }
        inventoryUnavailable = true
        causes.record(.inventory, reason: .inventory(issue), origin: .inventory)
        journal.emit("surface-unavailable", ["label": "inventory", "reason": "unresolved-owner"])
    }
    private func reportOwned(_ identity: ScreenRunnerProcessIdentity?) throws {
        guard let identity else { throw ScreenFailure.peerUntrusted }
        reportOwnedIdentity(identity)
    }
    private func reportOwnedIdentity(_ identity: ScreenRunnerProcessIdentity) {
        let sample = identity.sample
        journal.emit("owned-process-recorded", ["role": identity.role.rawValue, "pid": sample.pid, "parent": sample.parent,
            "uid": sample.uid, "startSeconds": String(sample.seconds), "startMicroseconds": sample.microseconds,
            "cdHash": identity.hash.map { String(format: "%02x", $0) }.joined()])
    }
    private var reportedReaps = Set<pid_t>()
    private var nativeStarted: pid_t?, nativeReaped: pid_t?, nativeReapReported = false
    private func reportNativeReap(_ pid: pid_t) {
        nativeReaped = pid
        if nativeStarted == pid, !nativeReapReported {
            nativeReapReported = true; journal.emit("child-exit-reaped", ["pid": pid])
        }
    }
    private func reportReap(pid: pid_t, label: String) {
        if reportedReaps.insert(pid).inserted { journal.emit("surface-child-reaped", ["pid": pid, "label": label]) }
    }
    private var currentBinding: ScreenBinding?
    private func consume(_ event: ScreenRunnerConnection.Event) {
        switch event {
        case .owned(let identity): reportOwnedIdentity(identity)
        case .started(let pid):
            nativeStarted = pid; journal.emit("child-started", ["pid": pid])
            if let reaped = nativeReaped { reportNativeReap(reaped) }
        case .authenticated: journal.emit("lanes-authenticated")
        case .lost: if !cleaning { failure = .peerLost }; drainReverse()
        case .reaped(let pid): reportNativeReap(pid)
        case .transport(let value):
            switch value {
            case .ready: ready = true; journal.emit("heartbeat-ready")
            case .link: linked = true; journal.emit("synthetic-link-observed")
            case .granted(let binding): granted = true; currentBinding = binding; journal.emit("native-granted")
            case .revocationConfirmed(let at, let began, let ordinal):
                ownAck = true
                journal.emit("native-ack", ["durationMs": ScreenRunnerJournal.ms(began.duration(to: at)), "revokeOrdinal": ordinal], at: at)
            case .revokeQueued(let queuedAt, let began, let ordinal):
                journal.emit("revoke-queued", ["revokeOrdinal": ordinal, "stopBeganElapsedMs": ScreenRunnerJournal.ms(journal.began.duration(to: began))], at: queuedAt)
            case .stopped(let reason):
                if reason != .stopped && !cleaning { causes.record(.failure, reason: .screen(reason), origin: .nativeChild) }
                causes.advance(cleaning ? .cleanup : .stopping)
                if !stopping { stopping = true; captureLimit?.cancel(); capture?.stop(.stopped) }
                if reason != .stopped && !cleaning { failure = reason }
            case .proofSourceAdmitted(let seq, let mono, let at): journal.emit("source-admitted", ["frameSeq": seq, "capturedMonoMs": mono], at: at)
            case .proofNativeAdmitted(let seq, let at): journal.emit("native-admitted", ["frameSeq": seq], at: at)
            case .proofControlSent, .proofControlEchoed: break
            }
            drainReverse()
        }
    }
    private func drainReverse() {
        guard let value = connection?.transport?.proofDrainReverseReplies() else { return }
        if value.invalid { failure = .incompatible }
        reportReverse(value.notices)
        reverseComplete = value.complete
    }
    private func reportReverse(_ notices: [ScreenProofReverseReplies.Notice]) {
        for notice in notices {
            reverseSeen = true
            if notice.stage == .received, selected == .reciprocalRevoke, stopAt == nil {
                stopAt = notice.at; journal.emit("stop-requested", ["trigger": "remote"], at: notice.at)
            }
            if notice.stage == .received {
                causes.noteStop(at: notice.at)
                causes.record(.stop, reason: .screen(.stopped), origin: .remote, at: notice.at)
                guard let invalidation = notice.invalidation else { failure = .incompatible; continue }
                journal.gateInvalidated(start: invalidation.0, end: invalidation.1)
            }
            let stage = notice.stage == .received ? "reverse-revoke-received" : notice.stage == .enqueued ? "reverse-reply-enqueued" : "reverse-reply-written"
            journal.emit(stage, ["revokeOrdinal": notice.ordinal], at: notice.at)
        }
    }
    private func surfaceEnded(_ label: String) -> @Sendable (pid_t, Bool) -> Void {
        let causes = self.causes
        return { [weak self, causes] pid, reaped in
            causes.record(.launcherReap, reason: reaped ? .reaped : .unreaped, origin: .launcher)
            Task { @MainActor in
            guard let self else { return }
            if reaped { self.reportReap(pid: pid, label: label) }
            if !self.cleaning, self.captureStarted, self.primaries.contains(where: { $0.pid == pid }) { self.failure = .sourceChanged; self.relay?.invoke(.sourceChanged, origin: .launcher) }
        } }
    }
    private func check() throws {
        drainReverse()
        guard !cancelled, !journal.failed else { throw ScreenFailure.stopped }
        if let failure { throw failure }
    }
    private func until(_ duration: Duration, condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: duration)
        while !condition(), ContinuousClock.now < deadline { try check(); try await Task.sleep(for: .milliseconds(5)) }
        try check(); guard condition() else { throw ScreenFailure.stalled }
    }
    private func marker(_ marker: String, timeout: Duration) async throws {
        try await Task.detached {
            let deadline = ContinuousClock.now.advanced(by: timeout), expected = Array((marker + "\n").utf8)
            var index = 0
            while index < expected.count, ContinuousClock.now < deadline {
                var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
                let ready = poll(&descriptor, 1, 25)
                if ready == 0 || (ready < 0 && errno == EINTR) { continue }
                var byte: UInt8 = 0
                guard ready > 0, read(STDIN_FILENO, &byte, 1) == 1, byte == expected[index] else { throw ScreenFailure.incompatible }
                index += 1
            }
            guard index == expected.count else { throw ScreenFailure.stalled }
        }.value
    }
    private func report(_ inventory: ScreenRunnerInventory) {
        for window in inventory.windows {
            let frame = window.value.frame
            journal.emit("surface-window", ["label": window.label, "profile": window.profile, "pid": window.value.owningApplication!.processID,
                "windowID": window.value.windowID, "layer": window.value.windowLayer,
                "rect": ["x": frame.minX, "y": frame.minY, "width": frame.width, "height": frame.height]])
        }
    }
    private static func injectFixedShortcut() throws {
        guard try ScreenRunnerHost.require() == .hotkeyStop, CGPreflightListenEventAccess(), CGPreflightPostEventAccess(),
              let source = CGEventSource(stateID: .hidSystemState) else { throw ScreenFailure.permission }
        let modifiers: [(CGKeyCode, CGEventFlags)] = [(59, .maskControl), (58, .maskAlternate), (55, .maskCommand)]
        var flags = CGEventFlags(), events: [CGEvent] = []
        for (key, flag) in modifiers {
            flags.insert(flag); guard let event = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: true) else { throw ScreenFailure.shortcut }
            event.flags = flags; events.append(event)
        }
        for down in [true, false] {
            guard let event = CGEvent(keyboardEventSource: source, virtualKey: 53, keyDown: down) else { throw ScreenFailure.shortcut }
            event.flags = flags; events.append(event)
        }
        for (key, flag) in modifiers.reversed() {
            flags.remove(flag); guard let event = CGEvent(keyboardEventSource: source, virtualKey: key, keyDown: false) else { throw ScreenFailure.shortcut }
            event.flags = flags; events.append(event)
        }
        for event in events { event.post(tap: .cghidEventTap) }
    }
    private func prepareHome() throws -> URL {
        var name = Array("/private/tmp/sliccy-runner.XXXXXXXX".utf8CString)
        guard mkdtemp(&name) != nil else { throw ScreenFailure.audit }
        let root = URL(fileURLWithPath: String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)); self.root = root
        rootFD = open(root.path, O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard rootFD >= 0, fstat(rootFD, &rootStat) == 0 else { throw ScreenFailure.audit }
        for name in ["tmp", "config"] { guard mkdirat(rootFD, name, 0o700) == 0 else { throw ScreenFailure.audit } }
        return root
    }
    private func removeHome() -> Bool {
        guard let root else { return true }
        do {
            guard rootFD >= 0 else { return false }
            try ScreenRunnerCleanup.removeContents(directory: rootFD, expected: rootStat)
            var current = stat()
            guard lstat(root.path, &current) == 0, current.st_ino == rootStat.st_ino, current.st_dev == rootStat.st_dev, rmdir(root.path) == 0 else { return false }
            close(rootFD); rootFD = -1; return true
        } catch { return false }
    }
}
#endif
