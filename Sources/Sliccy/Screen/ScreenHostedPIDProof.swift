#if SLICCY_HOSTED_PID_PROOF
import AppKit
import Darwin
import Security

@MainActor
final class ScreenHostedPIDProofApp: NSObject, NSApplicationDelegate {
    private var session: ScreenHostedPIDProofSession?
    static func run() {
        guard (try? ScreenHostedPIDHost.require()) != nil else { exit(2) }
        signal(SIGPIPE, SIG_IGN)
        let delegate = ScreenHostedPIDProofApp(), app = NSApplication.shared
        app.delegate = delegate; app.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { app.run() }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let value = ScreenHostedPIDProofSession { code in Task { @MainActor in Darwin.exit(code) } }
        session = value; value.start()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        session?.cancel(); return .terminateLater
    }
}

final class ScreenHostedPIDProofSession: @unchecked Sendable {
    private let lock = NSLock(), outputLock = NSLock()
    private let began = ContinuousClock.now
    private let complete: @Sendable (Int32) -> Void
    private var cancelled = false, outputFailed = false, outputBytes = 0
    private var active: ScreenHostedPIDSubject?
    private var outstandingCycler: pid_t?
    private var cyclerSpawned: UInt64 = 0, cyclerReaped: UInt64 = 0
    private var root: URL?, rootFD: Int32 = -1, rootMetadata = stat()
    init(complete: @escaping @Sendable (Int32) -> Void) { self.complete = complete }
    private func state<T>(_ body: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return body() }
    private var isCancelled: Bool {
        outputLock.lock(); let failed = outputFailed; outputLock.unlock()
        return failed || state { cancelled }
    }
    func cancel() { let owned = state { cancelled = true; return active }; owned?.cancel() }
    func start() {
        DispatchQueue(label: "ai.sliccy.proof.hosted-pid").async { [self] in run() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 645) { [weak self] in self?.cancel() }
    }
    private func run() {
        var reason = "fixed-failure", code: Int32 = 1
        do {
            try ScreenHostedPIDHost.require()
            try ScreenPeerVerifier.verifySelf()
            emit("runner-preflight", ["hosted": true, "osMajor": 27, "architecture": "arm64", "pid": getpid()])
            let join = try ScreenProofSession.readJoin()
            let home = try prepareHome()
            let original = try launch(attempt: 0, home: home, join: join)
            let saved = try original.verify()
            try marker("pid-original-observed")
            _ = try original.verify()
            emit("pid-reuse-original-observed", ["attempt": 0, "pid": saved.pid])
            try original.stopAndReap(); state { active = nil }
            guard saved.pid > 2 else { reason = "unsupported-target"; throw ScreenFailure.incompatible }
            if let deadline = try cycle(original: saved.pid) {
                guard !isCancelled, ContinuousClock.now < deadline else { throw ScreenFailure.stalled }
                let candidate = try launch(attempt: 1, home: home, join: join)
                let current = try candidate.verify()
                if current.pid == saved.pid {
                    let prefix = saved.words.prefix(7).elementsEqual(current.words.prefix(7))
                    let version = saved.words[7] != current.words[7]
                    emit("token-incarnation-compared", ["attempt": 1, "pid": current.pid, "prefixEqual": prefix, "versionDifferent": version])
                    guard ScreenHostedPIDBudget.sameCredentialPrefixAndNewVersion(saved: saved, current: current) else { throw ScreenFailure.peerUntrusted }
                    emit("pid-reuse-observed", ["attempt": 1, "pid": current.pid])
                    try marker("pid-replacement-observed")
                    _ = try candidate.verify()
                    emit("pid-reuse-current-token-positive", ["attempt": 1, "pid": current.pid])
                    var refused = false
                    do { _ = try ScreenPeerVerifier.verify(identity: saved, identifier: "ai.sliccy.slicc") } catch { refused = true }
                    guard refused else { throw ScreenFailure.peerUntrusted }
                    emit("pid-reuse-old-token-refused", ["attempt": 1, "pid": current.pid])
                    _ = try candidate.verify()
                    emit("pid-reuse-current-token-rechecked", ["attempt": 1, "pid": current.pid])
                    try marker("pid-result-observed")
                    _ = try candidate.verify()
                    emit("pid-reuse-observation-ended", ["attempt": 1, "pid": current.pid])
                    reason = "pid-reuse-confirmed"; code = 0
                } else {
                    emit("pid-reuse-near-target-missed", ["attempt": 1, "pid": current.pid])
                    reason = "pid-reuse-not-observed"; code = 2
                }
                try candidate.stopAndReap(); state { active = nil }
            } else { reason = "pid-reuse-not-observed"; code = 2 }
        } catch { if isCancelled { reason = "interrupted" }; code = 1 }
        if !cleanup() { reason = "cleanup-failed"; code = 1 }
        if began.duration(to: .now) > .seconds(650) { reason = "time-budget-exceeded"; code = 1 }
        emit("terminal", ["reason": reason, "outcome": code == 0 ? "complete" : code == 2 ? "failed-to-demonstrate" : "failed"])
        outputLock.lock(); let failed = outputFailed; outputLock.unlock()
        complete(failed ? 1 : code)
    }
    private func launch(attempt: Int, home: URL, join: String) throws -> ScreenHostedPIDSubject {
        guard !isCancelled else { throw ScreenFailure.stopped }
        let value = ScreenHostedPIDSubject(attempt: attempt) { [weak self] stage, attempt, pid, invalidated in
            var fields: [String: Any] = ["attempt": attempt]
            if let pid { fields["pid"] = pid }
            if let invalidated { fields["invalidated"] = invalidated }
            self?.emit(stage, fields)
        }
        let keep = state { () -> Bool in guard !cancelled else { return false }; active = value; return true }
        guard keep else { throw ScreenFailure.stopped }
        try value.launch(root: home, join: join)
        return value
    }
    private func cycle(original: pid_t) throws -> ContinuousClock.Instant? {
        let initial = try ScreenHostedPIDSpawn.CPU.read()
        var budget = ScreenHostedPIDBudget(original: original, started: .now, selfCPU: initial.process, childrenCPU: initial.children)
        emit("cycler-started", ["maximumSeconds": 600])
        var lastProgress = budget.started, maximumDebt = Duration.zero
        var operation = "cpu-accounting-failed"
        func fields(_ sample: ScreenHostedPIDSpawn.CPU, _ now: ContinuousClock.Instant) -> [String: Any] {
            let cpu = budget.cpu(selfCPU: sample.process, childrenCPU: sample.children), wall = budget.started.duration(to: now)
            maximumDebt = max(maximumDebt, budget.maximumTransientDebt, cpu - wall, .zero)
            return ["count": budget.reaped, "spawned": budget.spawned, "reaped": budget.reaped,
                    "cpuMs": Self.ms(cpu), "wallMs": Self.ms(wall), "maximumDebtMs": Self.ms(maximumDebt)]
        }
        do {
        while true {
            guard !isCancelled else { operation = "interrupted"; throw ScreenFailure.stopped }
            operation = "cpu-accounting-failed"
            let sample = try ScreenHostedPIDSpawn.CPU.read(), now = ContinuousClock.now
            let decision = budget.decision(now: now, selfCPU: sample.process, childrenCPU: sample.children)
            switch decision {
            case .stop(let reason):
                var row = fields(sample, now); row["reason"] = reason.rawValue; emit("cycler-ended", row)
                if reason == .timeLimit { return nil }
                throw ScreenFailure.incompatible
            case .attemptCLI:
                var row = fields(sample, now); row["reason"] = "near-target"; emit("cycler-ended", row)
                return budget.deadline
            case .pace(let duration):
                _ = poll(nil, 0, Int32(max(1, min(25, Self.ms(duration).rounded(.up)))))
            case .spawnCycler:
                guard !isCancelled else { throw ScreenFailure.stopped }
                guard ContinuousClock.now < budget.deadline else {
                    let final = try ScreenHostedPIDSpawn.CPU.read(), at = ContinuousClock.now
                    var row = fields(final, at)
                    let debt = budget.cpu(selfCPU: final.process, childrenCPU: final.children) > budget.started.duration(to: at)
                    row["reason"] = debt ? "cpu-debt-at-deadline" : "time-limit"; emit("cycler-ended", row)
                    if debt { throw ScreenFailure.incompatible }; return nil
                }
                operation = "spawn-failed"
                let pid = try ScreenHostedPIDSpawn.spawn(); outstandingCycler = pid; cyclerSpawned += 1
                operation = "lifecycle-failed"; try budget.didSpawnCycler()
                operation = "reap-failed"
                let result = try ScreenHostedPIDSpawn.reap(pid, deadline: budget.deadline, cancelled: { self.isCancelled }, cleanupDeadline: began.advanced(by: .seconds(650)))
                outstandingCycler = nil; cyclerReaped += 1
                operation = "lifecycle-failed"; try budget.didReapCycler(pid: pid)
                if result.interrupted, !isCancelled, ContinuousClock.now >= budget.deadline {
                    let final = try ScreenHostedPIDSpawn.CPU.read(), at = ContinuousClock.now
                    var row = fields(final, at)
                    let debt = budget.cpu(selfCPU: final.process, childrenCPU: final.children) > budget.started.duration(to: at)
                    row["reason"] = debt ? "cpu-debt-at-deadline" : "time-limit"; emit("cycler-ended", row)
                    if debt { throw ScreenFailure.incompatible }; return nil
                }
                guard result.status == 0, !result.interrupted else { throw ScreenFailure.stopped }
            }
            if lastProgress.duration(to: .now) >= .seconds(10) {
                operation = "cpu-accounting-failed"
                let sample = try ScreenHostedPIDSpawn.CPU.read(), now = ContinuousClock.now
                emit("cycler-progress", fields(sample, now)); lastProgress = now
            }
        }
        } catch {
            emit("cycler-failed", ["reason": operation, "spawned": cyclerSpawned, "reaped": cyclerReaped])
            throw error
        }
    }
    private func marker(_ value: String) throws {
        let expected = Array((value + "\n").utf8), deadline = ContinuousClock.now.advanced(by: .seconds(2))
        var index = 0
        while index < expected.count, ContinuousClock.now < deadline {
            guard !isCancelled else { throw ScreenFailure.stopped }
            var descriptor = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
            let result = poll(&descriptor, 1, 25)
            if result == 0 || (result < 0 && errno == EINTR) { continue }
            var byte: UInt8 = 0
            guard result > 0, read(STDIN_FILENO, &byte, 1) == 1, byte == expected[index] else { throw ScreenFailure.incompatible }
            index += 1
        }
        guard index == expected.count else { throw ScreenFailure.stalled }
    }
    private func prepareHome() throws -> URL {
        var template = Array("/private/tmp/sliccy-hosted-pid.XXXXXXXX".utf8CString)
        guard mkdtemp(&template) != nil else { throw ScreenFailure.audit }
        let home = URL(fileURLWithPath: String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)); root = home
        rootFD = open(home.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard rootFD >= 0, fstat(rootFD, &rootMetadata) == 0 else { throw ScreenFailure.audit }
        for name in ["tmp", "config"] {
            guard mkdirat(rootFD, name, 0o700) == 0 else { throw ScreenFailure.audit }
        }
        return home
    }
    private func cleanup() -> Bool {
        do {
            if let pid = outstandingCycler {
                _ = try ScreenHostedPIDSpawn.reap(pid, deadline: .now, cancelled: { true }, cleanupDeadline: began.advanced(by: .seconds(650))); outstandingCycler = nil; cyclerReaped += 1
            }
            let owned = state { active }; try owned?.stopAndReap(); state { active = nil }
            if let root {
                guard rootFD >= 0 else { return false }
                try ScreenSnapshotCleanup.removeContents(directory: rootFD, expected: rootMetadata)
                var current = stat()
                guard lstat(root.path, &current) == 0, current.st_dev == rootMetadata.st_dev,
                      current.st_ino == rootMetadata.st_ino, rmdir(root.path) == 0 else { return false }
                close(rootFD); rootFD = -1
            }
            guard cyclerSpawned == cyclerReaped else { return false }
            emit("owned-cleanup-complete", ["spawned": cyclerSpawned, "reaped": cyclerReaped]); return true
        } catch { return false }
    }
    private func emit(_ stage: String, _ fields: [String: Any] = [:]) {
        outputLock.lock(); defer { outputLock.unlock() }
        guard !outputFailed else { return }
        var row: [String: Any] = ["schema": 3, "case": "pid-reuse-hosted", "capture": false,
                                  "stage": stage, "elapsedMs": Self.ms(began.duration(to: .now))]
        fields.forEach { row[$0.key] = $0.value }
        do {
            var data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]); data.append(10)
            guard data.count <= 4096, data.count <= 65536 - outputBytes else { throw ScreenFailure.resourceLimit }
            outputBytes += data.count; try FileHandle.standardOutput.write(contentsOf: data)
        } catch { outputFailed = true }
    }
    private static func ms(_ value: Duration) -> Double {
        let parts = value.components; return Double(parts.seconds) * 1000 + Double(parts.attoseconds) / 1e15
    }
}
#endif
