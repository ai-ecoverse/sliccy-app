#if SLICCY_HOSTED_PID_PROOF
import Darwin
import Foundation

enum ScreenHostedPIDSpawn {
    struct CPU {
        let process: Duration, children: Duration
        static func read() throws -> Self {
            func value(_ who: Int32) throws -> Duration {
                var usage = rusage()
                guard getrusage(who, &usage) == 0 else { throw ScreenFailure.incompatible }
                func time(_ v: timeval) throws -> Duration {
                    guard v.tv_sec >= 0, v.tv_usec >= 0, v.tv_usec < 1_000_000 else { throw ScreenFailure.incompatible }
                    return .seconds(v.tv_sec) + .microseconds(v.tv_usec)
                }
                return try time(usage.ru_utime) + time(usage.ru_stime)
            }
            return try Self(process: value(RUSAGE_SELF), children: value(RUSAGE_CHILDREN))
        }
    }
    static func spawn() throws -> pid_t {
        try ScreenHostedPIDHost.require()
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw ScreenFailure.peerLost }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw ScreenFailure.peerLost }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else { throw ScreenFailure.peerLost }
        for fd in 0...2 {
            guard posix_spawn_file_actions_addopen(&actions, Int32(fd), "/dev/null", fd == 0 ? O_RDONLY : O_WRONLY, 0) == 0 else { throw ScreenFailure.peerLost }
        }
        let args = [strdup("/usr/bin/true"), nil]
        let environment = [strdup("PATH=/usr/bin:/bin"), strdup("LANG=C"), nil]
        defer { for pointer in args + environment { free(pointer) } }
        var child: pid_t = 0
        let result = args.withUnsafeBufferPointer { arguments in environment.withUnsafeBufferPointer { env in
            posix_spawn(&child, "/usr/bin/true", &actions, &attributes, arguments.baseAddress!, env.baseAddress!)
        } }
        guard result == 0, child > 0 else { throw ScreenFailure.peerLost }
        return child
    }
    enum WaitResult { case running, reaped(Int32), interrupted, unowned }
    struct WaitCalls {
        var now: () -> ContinuousClock.Instant
        var wait: (pid_t) -> WaitResult
        var send: (pid_t, Int32) -> Bool
        var pause: () -> Void
        static var native: Self {
            Self(now: { .now }, wait: { pid in
                var status: Int32 = 0
                let result = waitpid(pid, &status, WNOHANG)
                if result == pid { return .reaped(status) }
                if result == 0 { return .running }
                return errno == EINTR ? .interrupted : .unowned
            }, send: { pid, signal in kill(pid, signal) == 0 || errno == ESRCH }, pause: { _ = poll(nil, 0, 1) })
        }
    }
    static func reap(_ child: pid_t, deadline: ContinuousClock.Instant, cancelled: () -> Bool,
                     cleanupDeadline: ContinuousClock.Instant? = nil, calls: WaitCalls = .native) throws -> (status: Int32, interrupted: Bool) {
        guard child > 0 else { throw ScreenFailure.peerLost }
        var termAt: ContinuousClock.Instant?, killed = false
        while true {
            switch calls.wait(child) {
            case .reaped(let status): return (status, termAt != nil)
            case .interrupted: continue
            case .unowned: throw ScreenFailure.peerLost
            case .running: break
            }
            let now = calls.now()
            if let cleanupDeadline, now >= cleanupDeadline {
                _ = calls.send(child, SIGKILL)
                throw ScreenFailure.stalled
            }
            if termAt == nil, now >= deadline || cancelled() {
                guard calls.send(child, SIGTERM) else { throw ScreenFailure.peerLost }
                termAt = now
            }
            if let termAt, !killed, termAt.duration(to: now) >= .seconds(1) {
                guard calls.send(child, SIGKILL) else { throw ScreenFailure.peerLost }
                killed = true
            }
            if let termAt, termAt.duration(to: now) >= .seconds(3) { throw ScreenFailure.stalled }
            calls.pause()
        }
    }
}
#endif
