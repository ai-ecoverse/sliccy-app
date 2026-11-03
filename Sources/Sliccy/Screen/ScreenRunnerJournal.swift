#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Darwin

final class ScreenRunnerDiagnosticAbort: @unchecked Sendable {
    private let lock = NSLock()
    private var failed = false
    private var actions: [@Sendable () -> Void] = []
    func register(_ action: @escaping @Sendable () -> Void) {
        lock.lock()
        if failed { lock.unlock(); action(); return }
        if actions.count == 2 {
            failed = true; let pending = actions; actions.removeAll(); lock.unlock()
            for stop in pending { stop() }; action(); return
        }
        actions.append(action); lock.unlock()
    }
    func fail() {
        lock.lock()
        guard !failed else { lock.unlock(); return }
        failed = true; let pending = actions; actions.removeAll(); lock.unlock()
        for stop in pending { stop() }
    }
}

final class ScreenRunnerJournal: @unchecked Sendable {
    let began = ContinuousClock.now
    private let lock = NSLock()
    private let selected: ScreenRunnerCase
    private let output: Int32
    private let authorityFailed: @Sendable () -> Void
    private var bytes = 0, gateReported = false
    private var writeFailed = false
    var failed: Bool { lock.lock(); defer { lock.unlock() }; return writeFailed }

    init(_ selected: ScreenRunnerCase, descriptor: Int32 = STDOUT_FILENO,
         authorityFailed: @escaping @Sendable () -> Void) throws {
        self.selected = selected; self.authorityFailed = authorityFailed
        var value = stat()
        guard fstat(descriptor, &value) == 0, value.st_mode & S_IFMT == S_IFIFO else { throw ScreenFailure.incompatible }
        let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 3)
        guard duplicate >= 0 else { throw ScreenFailure.resourceLimit }
        let flags = fcntl(duplicate, F_GETFL)
        guard flags >= 0, flags & O_ACCMODE != O_RDONLY,
              fcntl(duplicate, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(duplicate, F_GETFL) & O_NONBLOCK != 0 else {
            close(duplicate); throw ScreenFailure.incompatible
        }
        output = duplicate
    }
    deinit { close(output) }

    @discardableResult
    func emit(_ stage: String, _ fields: [String: Any] = [:], at: ContinuousClock.Instant = .now) -> Bool {
        lock.lock()
        guard !writeFailed else { lock.unlock(); return false }
        var row: [String: Any] = ["schema": 3, "case": selected.rawValue, "capture": true, "stage": stage,
            "elapsedMs": Self.ms(began.duration(to: .now)), "eventElapsedMs": Self.ms(began.duration(to: at))]
        fields.forEach { row[$0.key] = $0.value }
        do {
            var data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]); data.append(10)
            guard data.count <= 4096, bytes + data.count <= 524288 else { throw ScreenFailure.resourceLimit }
            let count = data.withUnsafeBytes { Darwin.write(output, $0.baseAddress, $0.count) }
            guard count == data.count else { throw ScreenFailure.stalled }
            bytes += data.count
            lock.unlock(); return true
        } catch {
            writeFailed = true; lock.unlock()
            authorityFailed(); return false
        }
    }
    func gateInvalidated(start: ContinuousClock.Instant, end: ContinuousClock.Instant) {
        lock.lock(); let first = !gateReported; gateReported = true; lock.unlock()
        if first { emit("local-gate-invalidated", ["durationMs": Self.ms(start.duration(to: end))], at: end) }
    }
    static func ms(_ duration: Duration) -> Double {
        let value = duration.components; return Double(value.seconds) * 1000 + Double(value.attoseconds) / 1e15
    }
}
#endif
