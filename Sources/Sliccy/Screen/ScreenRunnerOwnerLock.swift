#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

final class ScreenRunnerChromeEvidenceBatch: @unchecked Sendable {
    struct Row: Sendable {
        let phase: String
        let value: ScreenRunnerChromePolicy.Evidence
    }
    private let mutex = NSLock()
    private var rows: [Row] = []
    private var sliceRows: [ScreenRunnerSliceBinding.Evidence] = []
    private var lost = false
    func collect(_ phase: String, _ value: ScreenRunnerChromePolicy.Evidence) {
        mutex.lock(); defer { mutex.unlock() }
        guard rows.count < 4 else { lost = true; return }
        rows.append(.init(phase: phase, value: value))
    }
    func collectSlice(_ value: ScreenRunnerSliceBinding.Evidence) {
        mutex.lock(); defer { mutex.unlock() }
        guard sliceRows.count < 4 else { lost = true; return }
        sliceRows.append(value)
    }
    func deliver(to output: @Sendable (String, ScreenRunnerChromePolicy.Evidence) -> Void,
                 sliceOutput: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in },
                 loss: @Sendable () -> Void) {
        mutex.lock(); let snapshot = rows, slices = sliceRows, failed = lost; rows.removeAll(); sliceRows.removeAll(); mutex.unlock()
        if failed { loss(); return }
        for row in snapshot { output(row.phase, row.value) }
        for row in slices { sliceOutput(row) }
    }
}

final class ScreenRunnerOwnerLock: @unchecked Sendable {
    private let mutex = NSLock()
    func lock() { mutex.lock() }
    func unlock() { mutex.unlock() }
    func withEvidence<T>(output: @Sendable (String, ScreenRunnerChromePolicy.Evidence) -> Void,
                         sliceOutput: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in },
                         loss: @Sendable () -> Void,
                         operation: (ScreenRunnerChromeEvidenceBatch) throws -> T) rethrows -> T {
        let batch = ScreenRunnerChromeEvidenceBatch()
        mutex.lock()
        defer {
            mutex.unlock()
            batch.deliver(to: output, sliceOutput: sliceOutput, loss: loss)
        }
        return try operation(batch)
    }
    #if DEBUG
    func testLiveness(until: Date) -> Bool {
        guard mutex.lock(before: until) else { return false }
        mutex.unlock(); return true
    }
    #endif
}
#endif
