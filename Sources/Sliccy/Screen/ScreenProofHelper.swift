#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation
import Darwin
import ScreenSystem

/// Owns one fixed CI-signed helper until actual waitpid and bounded stdout EOF.
final class ScreenProofHelper: @unchecked Sendable {
    enum Event: Sendable { case stage(String); case finished(Bool) }
    let pid: pid_t
    private let channel: ScreenSocket
    private let lock = NSLock()
    private var reaped = false
    private var outputEnded = false
    private var good = true
    private var sent = false
    private var notified = false
    private var monitor: DispatchSourceProcess?
    private let event: @Sendable (Event) -> Void

    init(executable: String, event: @escaping @Sendable (Event) -> Void) throws {
        self.event = event
        var child: pid_t = 0, channelFD: Int32 = -1, output: Int32 = -1
        guard sliccy_screen_proof_helper_spawn(executable, &child, &channelFD, &output) == 0 else { throw ScreenFailure.peerLost }
        pid = child
        do { channel = try ScreenSocket(channelFD) }
        catch { close(output); kill(child, SIGKILL); while waitpid(child, nil, 0) < 0 && errno == EINTR {}; throw error }
        let monitor = DispatchSource.makeProcessSource(identifier: child, eventMask: [.exit, .exec], queue: DispatchQueue(label: "ai.sliccy.proof.helper-life"))
        self.monitor = monitor
        let registration = DispatchSemaphore(value: 0)
        monitor.setRegistrationHandler { registration.signal() }
        monitor.setEventHandler { [weak self, weak monitor] in
            guard let self else { return }
            if monitor?.data.contains(.exec) == true { self.stop() }
            if monitor?.data.contains(.exit) == true {
                self.lock.lock()
                var status: Int32 = 0, result: pid_t
                repeat { result = waitpid(self.pid, &status, 0) } while result < 0 && errno == EINTR
                self.reaped = true; self.good = self.good && result == self.pid && status == 0
                self.lock.unlock()
                monitor?.cancel(); self.finishIfReady()
            }
        }
        monitor.resume()
        let readFD = output
        DispatchQueue(label: "ai.sliccy.proof.helper-output").async { [self] in
            defer { close(readFD) }
            let stages = ["ready", "received", "write-started", "written", "held", "complete"]
            var index = 0, total = 0, line = Data(), valid = true
            var bytes = [UInt8](repeating: 0, count: 512)
            while true {
                let count = read(readFD, &bytes, bytes.count)
                if count < 0 && errno == EINTR { continue }
                if count <= 0 { if count < 0 { valid = false }; break }
                total += count
                if total > 4096 { valid = false }
                if !valid { continue } // Drain without retaining uncontrolled output.
                for byte in bytes.prefix(count) {
                    if byte == 10 {
                        do {
                            let object = try ScreenJSON.object(line, limit: 128)
                            try ScreenJSON.keys(object, exact: ["stage"])
                            guard index < stages.count, object["stage"] as? String == stages[index] else { throw ScreenFailure.incompatible }
                            let stage = stages[index]; index += 1; event(.stage(stage))
                        } catch { valid = false }
                        line.removeAll()
                    } else if line.count < 128 { line.append(byte) } else { valid = false }
                    if !valid { break }
                }
            }
            lock.lock(); outputEnded = true; good = good && valid && line.isEmpty && index == stages.count; lock.unlock()
            finishIfReady()
        }
        guard registration.wait(timeout: .now() + 1) == .success else {
            lock.lock()
            if !reaped {
                _ = kill(pid, SIGKILL)
                while waitpid(pid, nil, 0) < 0 && errno == EINTR {}
                reaped = true
            }
            lock.unlock()
            throw ScreenFailure.peerLost
        }
    }
    func start() throws {
        lock.lock(); defer { lock.unlock() }
        guard !reaped, kill(pid, SIGCONT) == 0 else { throw ScreenFailure.peerLost }
    }
    func transfer(safety: Int32, cli: pid_t, record: Data) throws {
        lock.lock(); defer { lock.unlock() }
        guard !sent, !reaped else { throw ScreenFailure.incompatible }
        sent = true
        guard record.withUnsafeBytes({ sliccy_screen_proof_handoff(channel.fd, safety, cli, $0.baseAddress, record.count) }) == 0 else { throw ScreenFailure.peerLost }
    }
    func stop() {
        lock.lock(); good = false; if !reaped { _ = kill(pid, SIGTERM) }; lock.unlock()
        channel.stop()
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) { [self] in
            lock.lock(); if !reaped { _ = kill(pid, SIGKILL) }; lock.unlock()
        }
    }
    private func finishIfReady() {
        lock.lock()
        let notify = reaped && outputEnded && !notified
        if notify { notified = true }
        let success = good
        lock.unlock()
        if notify { event(.finished(success)) }
    }
}
#endif
