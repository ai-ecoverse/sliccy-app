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
    private var monitor: DispatchSourceProcess?
    private let lost: @Sendable () -> Void
    var isAlive: Bool { lock.lock(); defer { lock.unlock() }; return live }

    init(executable: String, join: String, bootstrap: Data, lost: @escaping @Sendable () -> Void) throws {
        guard ScreenReleasePolicy.identityProofApproved, !ScreenReleasePolicy.cliCodeDirectoryHashes.isEmpty else { throw ScreenFailure.peerUntrusted }
        try ScreenPeerVerifier.verifySelf()
        guard executable == Bundle.main.bundleURL.appending(path: "Contents/Resources/slicc").path,
              !join.contains("\n"), !join.contains("\r"), join.utf8.count <= 4096 else { throw ScreenFailure.incompatible }
        self.lost = lost
        let arguments = [executable, "-", "follow", "--json", "--native-screen"]
        // No inherited DYLD/loader variables or user CLI settings.
        let environment = ["PATH=/usr/bin:/bin", "HOME=" + FileManager.default.homeDirectoryForCurrentUser.path,
                           "TMPDIR=" + NSTemporaryDirectory(), "LANG=en_US.UTF-8"]
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
                _ = waitpid(self.pid, &status, 0)
                monitor?.cancel()
            } else { _ = kill(self.pid, SIGKILL) }
        }
        monitor.resume()
        // Read stdout continuously, without retaining or logging even one line.
        let readFD = output
        DispatchQueue(label: "ai.sliccy.screen.child-output").async {
            defer { Darwin.close(readFD) }
            var bytes = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = Darwin.read(readFD, &bytes, bytes.count)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { break }
            }
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
        if live { _ = kill(pid, SIGTERM) }
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
