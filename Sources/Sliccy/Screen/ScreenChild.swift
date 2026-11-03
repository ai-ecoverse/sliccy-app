import Foundation
import Darwin
import ScreenSystem

/// Owns the exact suspended child, installs exit/exec monitoring before resuming,
/// and retains PID ownership until invalidation. A separate follow link offers no
/// credentials, shell, browsers or filesystem resources.
final class ScreenChild: @unchecked Sendable {
    let pid: pid_t
    let deadline: ContinuousClock.Instant
    private let lock = NSLock()
    private var live = true
    private var hasReaped = false
    private var monitor: DispatchSourceProcess?
    private let lost: @Sendable () -> Void
    private let reaped: @Sendable (Int32) -> Void
    var isAlive: Bool { lock.lock(); defer { lock.unlock() }; return live }

    init(executable: String, join: String, bootstrap: Data, policy: ScreenLaunchPolicy = .production,
         proofOutput: (@Sendable (Data?) -> Void)? = nil,
         reaped: @escaping @Sendable (Int32) -> Void = { _ in },
         lost: @escaping @Sendable () -> Void) throws {
        guard policy.allowsIPC else { throw ScreenFailure.peerUntrusted }
        try ScreenPeerVerifier.verifySelf()
        guard executable == Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
              !join.contains("\n"), !join.contains("\r"), join.utf8.count <= 4096 else { throw ScreenFailure.incompatible }
        self.lost = lost
        self.reaped = reaped
        var arguments = [executable, "-", "follow", "--json", "--native-screen"]
#if SLICCY_NATIVE_SCREEN_PROOF
        if proofOutput != nil { arguments.append("--native-screen-proof") }
#else
        guard proofOutput == nil else { throw ScreenFailure.incompatible }
#endif
        // No inherited DYLD/loader variables or user CLI settings.
        let environment = policy.environment
        let argv = arguments.map { strdup($0) } + [nil]
        let env = environment.map { strdup($0) } + [nil]
        defer { for pointer in argv + env { free(pointer) } }
        var child: pid_t = 0, input: Int32 = -1, output: Int32 = -1, boot: Int32 = -1
        deadline = .now.advanced(by: .seconds(3))
        let result = argv.withUnsafeBufferPointer { args in env.withUnsafeBufferPointer { values in
            sliccy_screen_spawn(executable, args.baseAddress, values.baseAddress, &child, &input, &output, &boot)
        } }
        guard result == 0 else { throw ScreenFailure.peerLost }
        pid = child
        let monitor = DispatchSource.makeProcessSource(identifier: child, eventMask: [.exit, .exec],
            queue: DispatchQueue(label: "ai.sliccy.screen.child", qos: .userInteractive))
        self.monitor = monitor
        let registered = DispatchSemaphore(value: 0)
        monitor.setRegistrationHandler { registered.signal() }
        monitor.setEventHandler { [weak self, weak monitor] in
            guard let self else { return }
            self.invalidate()
            if monitor?.data.contains(.exit) == true {
                var status: Int32 = 0
                var result: pid_t
                self.lock.lock()
                repeat { result = waitpid(self.pid, &status, 0) } while result < 0 && errno == EINTR
                self.hasReaped = true
                self.lock.unlock()
                if result == self.pid { self.reaped(status) }
                monitor?.cancel()
            } else { _ = kill(self.pid, SIGKILL) }
        }
        monitor.resume()
        // Ordinary launches discard stdout. Diagnostic bytes go only to the
        // bounded typed filter; they are never logged or directly forwarded.
        let readFD = output
        DispatchQueue(label: "ai.sliccy.screen.child-output").async {
            defer { Darwin.close(readFD) }
            var bytes = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = Darwin.read(readFD, &bytes, bytes.count)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { break }
#if SLICCY_NATIVE_SCREEN_PROOF
                proofOutput?(Data(bytes.prefix(count)))
#endif
            }
#if SLICCY_NATIVE_SCREEN_PROOF
            proofOutput?(nil)
#endif
        }
        do {
            defer { Darwin.close(input); Darwin.close(boot) }
            guard registered.wait(timeout: .now() + 1) == .success, ContinuousClock.now < deadline else { throw ScreenFailure.stalled }
            guard kill(child, SIGCONT) == 0 else { throw ScreenFailure.peerLost }
            try Self.writePipe(bootstrap, fd: boot, until: deadline)
            try Self.writePipe(Data((join + "\n").utf8), fd: input, until: deadline)
        } catch { invalidate(); _ = kill(child, SIGKILL); throw error }
    }
    private func invalidate() {
        lock.lock(); let notify = live; live = false; lock.unlock()
        if notify { lost() } // Gate invalidation happens before reaping/possible PID reuse.
    }
    func stop() {
        lock.lock()
        if !hasReaped { _ = kill(pid, SIGTERM) }
        lock.unlock()
        invalidate()
    }
    /// Ownership and reaping share this lock, so escalation cannot target a reused PID.
    func forceStop() {
        lock.lock()
        if !hasReaped { _ = kill(pid, SIGKILL) }
        lock.unlock()
        invalidate()
    }
    deinit {
        monitor?.cancel()
        var status: Int32 = 0
        // No event handler can retain self during deinit. WNOHANG establishes
        // that this PID is still our unreaped child before sending a signal.
        if waitpid(pid, &status, WNOHANG) == 0 {
            _ = kill(pid, SIGKILL)
            while waitpid(pid, &status, 0) < 0 && errno == EINTR {}
        }
    }
    private static func writePipe(_ data: Data, fd: Int32, until: ContinuousClock.Instant) throws {
        let one: Int32 = 1
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              fcntl(fd, F_SETNOSIGPIPE, one) == 0 else { throw ScreenFailure.peerLost }
        var offset = 0
        while offset < data.count {
            guard ContinuousClock.now < until else { throw ScreenFailure.stalled }
            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let result = poll(&descriptor, 1, 25)
            if result == 0 || (result < 0 && errno == EINTR) { continue }
            guard result > 0 else { throw ScreenFailure.peerLost }
            let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count > 0 else { throw ScreenFailure.peerLost }
            offset += count
        }
    }
}
