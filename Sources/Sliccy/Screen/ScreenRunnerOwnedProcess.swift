#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Darwin
import Security
import CryptoKit

final class ScreenRunnerOwnedProcess: @unchecked Sendable {
    let pid: pid_t
    let executable: URL
    let identifier: String
    private let lock = ScreenRunnerOwnerLock()
    private var reaped = false, invalid = false, ownsPID = true
    private var input: Int32 = -1
    private var monitor: DispatchSourceProcess?
    private let exited = DispatchSemaphore(value: 0)
    private let ended: @Sendable (pid_t, Bool) -> Void
    private let staticHash: Data
    private let team: String?
    private let chromeEvidence: @Sendable (String, ScreenRunnerChromePolicy.Evidence) -> Void
    private let evidenceLost: @Sendable () -> Void
    private var identity: ScreenRunnerProcessIdentity?
    private var signalRefused = false
    var isAlive: Bool { lock.lock(); defer { lock.unlock() }; return !invalid && !reaped }

    static func surface(home: URL, ended: @escaping @Sendable (pid_t, Bool) -> Void) throws -> ScreenRunnerOwnedProcess {
        _ = try ScreenRunnerHost.require()
        let app = Bundle.main.bundleURL.appending(path: "Contents/Helpers/ScreenProofSurface.app")
        let executable = app.appending(path: "Contents/MacOS/ScreenProofSurface")
        guard SHA256.hash(data: try Data(contentsOf: executable)).map({ String(format: "%02x", $0) }).joined() ==
              "baff7b8b21264018138c9f7e2e7f6b8052bdcaf6e10b8ffa06dde854ac2b20c9" else { throw ScreenFailure.peerUntrusted }
        return try ScreenRunnerOwnedProcess(executable: app.appending(path: "Contents/MacOS/ScreenProofSurface"),
            identifier: "ai.sliccy.proof-helper", team: "S8LB56P782", arguments: [], home: home, ended: ended)
    }
    static func chrome(window: ScreenRunnerBrowserWindow, join: String, home: URL,
                       evidence: @escaping @Sendable (String, ScreenRunnerChromePolicy.Evidence) -> Void,
                       evidenceLost: @escaping @Sendable () -> Void,
                       ended: @escaping @Sendable (pid_t, Bool) -> Void) throws -> ScreenRunnerOwnedProcess {
        _ = try ScreenRunnerHost.require()
        let page = try window.page(join: join), rect = window.rect
        return try ScreenRunnerOwnedProcess(executable: URL(fileURLWithPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            identifier: "com.google.Chrome", team: ScreenRunnerChromePolicy.team,
            arguments: ["--user-data-dir=" + home.appending(path: "config/chrome-" + window.profile).path,
                        "--no-first-run", "--no-default-browser-check", "--use-mock-keychain", "--disable-background-networking",
                        "--disable-component-update", "--disable-sync", "--disable-default-apps",
                        "--window-position=\(Int(rect.minX)),\(Int(rect.minY))", "--window-size=288,224", "--app=" + page.absoluteString],
            home: home, chromeEvidence: evidence, evidenceLost: evidenceLost, ended: ended)
    }
    static func authorization(home: URL, ended: @escaping @Sendable (pid_t, Bool) -> Void) throws -> ScreenRunnerOwnedProcess {
        guard try ScreenRunnerHost.require() == .authorizationExclusion else { throw ScreenFailure.protection }
        return try ScreenRunnerOwnedProcess(executable: URL(fileURLWithPath: "/usr/bin/osascript"),
            identifier: "com.apple.osascript", team: nil,
            arguments: ["-e", "do shell script \"/usr/bin/true\" with administrator privileges"], home: home, ended: ended)
    }
    private init(executable: URL, identifier: String, team: String?, arguments: [String], home: URL,
                 chromeEvidence: @escaping @Sendable (String, ScreenRunnerChromePolicy.Evidence) -> Void = { _, _ in },
                 evidenceLost: @escaping @Sendable () -> Void = {},
                 ended: @escaping @Sendable (pid_t, Bool) -> Void) throws {
        self.executable = executable; self.identifier = identifier; self.ended = ended; self.team = team; self.chromeEvidence = chromeEvidence; self.evidenceLost = evidenceLost
        staticHash = try Self.preflight(executable: executable, identifier: identifier, team: team,
            calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
            chromeEvidence: { chromeEvidence("preflight", $0) })
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw ScreenFailure.peerLost }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw ScreenFailure.peerLost }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED)) == 0 else { throw ScreenFailure.peerLost }
        var pipeFD: [Int32] = [-1, -1]
        guard pipe(&pipeFD) == 0 else { throw ScreenFailure.peerLost }
        var retainInput = false
        defer { close(pipeFD[0]); if !retainInput { close(pipeFD[1]) } }
        guard fcntl(pipeFD[0], F_SETFD, FD_CLOEXEC) == 0, fcntl(pipeFD[1], F_SETFD, FD_CLOEXEC) == 0,
              posix_spawn_file_actions_adddup2(&actions, pipeFD[0], STDIN_FILENO) == 0 else { throw ScreenFailure.peerLost }
        for fd in 1...2 {
            guard posix_spawn_file_actions_addopen(&actions, Int32(fd), "/dev/null", O_WRONLY, 0) == 0 else { throw ScreenFailure.peerLost }
        }
        let processHome = home.appending(path: identifier == "ai.sliccy.proof-helper" ? "config/surface-home" : "config/browser-home")
        try FileManager.default.createDirectory(at: processHome, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let argv = ([executable.path] + arguments).map { strdup($0) } + [nil]
        let environment = (["PATH=/usr/bin:/bin", "HOME=" + processHome.path, "TMPDIR=" + home.appending(path: "tmp").path + "/", "LANG=C"] + ScreenRunnerHost.assertions.sorted { $0.key < $1.key }.map { $0.key + "=" + $0.value }).map { strdup($0) } + [nil]
        defer { for p in argv + environment { free(p) } }
        var child: pid_t = 0
        let result = argv.withUnsafeBufferPointer { a in environment.withUnsafeBufferPointer { e in
            posix_spawn(&child, executable.path, &actions, &attributes, a.baseAddress!, e.baseAddress!)
        } }
        guard result == 0, child > 0 else { throw ScreenFailure.peerLost }
        pid = child; input = pipeFD[1]; retainInput = true
        let monitor = DispatchSource.makeProcessSource(identifier: child, eventMask: [.exit, .exec], queue: DispatchQueue(label: "ai.sliccy.runner.surface-life"))
        self.monitor = monitor
        let registered = DispatchSemaphore(value: 0)
        monitor.setRegistrationHandler { registered.signal() }
        monitor.setEventHandler { [weak self, weak monitor] in
            guard let self else { return }
            let result: Bool? = self.lock.withEvidence(output: self.chromeEvidence, loss: self.evidenceLost) { batch in
                if monitor?.data.contains(.exec) == true { self.invalid = true; _ = self.signalLocked(SIGKILL, evidence: batch) }
                if monitor?.data.contains(.exit) == true, !self.reaped {
                    self.invalid = true
                    var status: Int32 = 0, result: pid_t
                    repeat { result = waitpid(self.pid, &status, 0) } while result < 0 && errno == EINTR
                    self.reaped = result == self.pid; self.ownsPID = false
                    return self.reaped
                }
                return nil
            }
            if let reaped = result {
                monitor?.cancel()
                if reaped { self.exited.signal() }
                self.ended(self.pid, reaped)
            }
        }
        monitor.resume()
        guard registered.wait(timeout: .now() + 1) == .success else { stop(); throw ScreenFailure.stalled }
        let role: ScreenRunnerProcessIdentity.Role = identifier == "ai.sliccy.proof-helper" ? .surface : identifier == "com.google.Chrome" ? .chrome : .authorizationRequester
        do {
            let recorded = try ScreenRunnerProcessIdentity.capture(pid: pid, role: role, hash: staticHash, identifier: identifier, team: team, chromeEvidence: { chromeEvidence("initial-live", $0) })
            let resumed = lock.withEvidence(output: chromeEvidence, loss: evidenceLost) { batch in
                identity = recorded; return signalLocked(SIGCONT, evidence: batch)
            }
            guard resumed else { throw ScreenFailure.peerUntrusted }
        } catch { stop(); throw error }
    }
    private static func rule<Static, Guest, Rule>(identifier: String, team: String?, calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>) throws -> Rule {
        if identifier == ScreenRunnerChromePolicy.identifier { return try calls.makeRule(ScreenRunnerChromePolicy.requirementText) }
        var text = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"\(identifier)\""
        if identifier == "com.apple.osascript" { text = "anchor apple and identifier \"com.apple.osascript\"" }
        if let team { text += " and certificate leaf[subject.OU] = \"\(team)\"" }
        return try calls.makeRule(text)
    }
    static func preflight<Static, Guest, Rule>(executable: URL, identifier: String, team: String?,
                                              calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                              chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void) throws -> Data {
        let code = try calls.staticCode(executable), rule = try rule(identifier: identifier, team: team, calls: calls)
        try ScreenRunnerChromePolicy.verify(code, identifier: identifier, site: .preflight, ordinary: rule, calls: calls, record: chromeEvidence)
        guard let hash = try calls.information(code).hash else { throw ScreenFailure.peerUntrusted }
        return hash
    }
    static func verifyLiveCopy<Static, Guest, Rule>(pid: pid_t, executable: URL, identifier: String, team: String?, hash: Data,
                                                   calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                                   chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void) throws {
        let guest = try calls.guest(pid)
        guard try calls.checkGuest(guest, [], rule(identifier: identifier, team: team, calls: calls)) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        let staticCode = try calls.copyStatic(guest)
        try ScreenRunnerChromePolicy.verify(staticCode, identifier: identifier, site: .liveCopy,
            ordinary: try rule(identifier: identifier, team: team, calls: calls), calls: calls, record: chromeEvidence)
        let info = try calls.information(staticCode)
        guard info.hash == hash, info.path?.standardizedFileURL == executable.standardizedFileURL else { throw ScreenFailure.peerUntrusted }
    }
    static func verifySignalRole<Static, Guest, Rule>(pid: pid_t, identifier: String, team: String?, hash: Data,
                                                     calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                                     chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void) throws {
        try ScreenRunnerProcessIdentity.verifyRole(pid: pid, identifier: identifier, team: team, hash: hash, site: .signal, calls: calls, chromeEvidence: chromeEvidence)
    }
    func verifyLive() throws {
        try lock.withEvidence(output: chromeEvidence, loss: evidenceLost) { batch in
            guard ownsPID, !invalid, !reaped, let identity else { throw ScreenFailure.peerLost }
            try identity.verify(identifier: identifier, team: team, chromeEvidence: { batch.collect("live", $0) })
            try Self.verifyLiveCopy(pid: pid, executable: executable, identifier: identifier, team: team, hash: staticHash,
                calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
                chromeEvidence: { batch.collect("live-copy", $0) })
        }
    }

    func inventoryIdentity() throws -> ScreenRunnerInventoryBoundary.Identity {
        guard let original = recordedIdentity else { throw ScreenFailure.peerUntrusted }
        let before = try ScreenRunnerProcessSample.read(pid)
        try verifyLive()
        let path = try ScreenRunnerKernelSample.path(pid), hash = try ScreenRunnerKernelSample.hash(pid)
        guard before == original.sample, try ScreenRunnerProcessSample.read(pid) == before,
              path == executable.path, hash == original.hash else { throw ScreenFailure.peerUntrusted }
        return .init(pid: pid, parent: before.parent, uid: before.uid, seconds: before.seconds, microseconds: before.microseconds,
                     identifier: identifier, path: path, hash: hash, appleAnchored: false, verified: true, privilegedBracket: false)
    }

    func stop() {
        lock.withEvidence(output: chromeEvidence, loss: evidenceLost) { batch in
            invalid = true
            if input >= 0 { close(input); input = -1 }
            _ = signalLocked(SIGTERM, evidence: batch)
        }
    }
    func stopAndReap(until: DispatchTime) throws {
        stop()
        if !hasReaped, exited.wait(timeout: min(until, .now() + 1)) != .success {
            lock.withEvidence(output: chromeEvidence, loss: evidenceLost) { batch in _ = signalLocked(SIGKILL, evidence: batch) }
            if !hasReaped, exited.wait(timeout: until) != .success { throw ScreenFailure.stalled }
        }
        guard hasReaped else { throw ScreenFailure.stalled }
        lock.lock(); let refused = signalRefused; lock.unlock()
        guard !refused else { throw ScreenFailure.peerUntrusted }
    }
    deinit {
        monitor?.cancel()
        if input >= 0 { close(input) }
        var status: Int32 = 0
        if waitpid(pid, &status, WNOHANG) == 0 {
            let signalled = lock.withEvidence(output: chromeEvidence, loss: evidenceLost) { batch in signalLocked(SIGKILL, evidence: batch) }
            if signalled { _ = waitpid(pid, &status, WNOHANG) }
        }
    }
    private func signalLocked(_ value: Int32, evidence: ScreenRunnerChromeEvidenceBatch) -> Bool {
        guard ownsPID, !reaped else { return false }
        guard let identity else { signalRefused = true; return false }
        let accepted = identity.signal(value, owned: ownsPID, reaped: reaped,
            sample: { try ScreenRunnerProcessSample.read(pid) },
            role: { try Self.verifySignalRole(pid: pid, identifier: identifier, team: team, hash: staticHash,
                calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native, chromeEvidence: { evidence.collect("signal", $0) }) },
            send: { kill($0, $1) })
        if !accepted { signalRefused = true }
        return accepted
    }
    var recordedIdentity: ScreenRunnerProcessIdentity? { lock.lock(); defer { lock.unlock() }; return identity }
    var hasReaped: Bool { lock.lock(); defer { lock.unlock() }; return reaped }
}
#endif
