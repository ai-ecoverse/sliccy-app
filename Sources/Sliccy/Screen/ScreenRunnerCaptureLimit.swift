#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

final class ScreenRunnerCaptureLimit: @unchecked Sendable {
    private let lock = NSLock()
    private var armed = false, ended = false
    private var work: DispatchWorkItem?
    private let expired: @Sendable () -> Void
    init(expired: @escaping @Sendable () -> Void) { self.expired = expired }
    func arm() {
        lock.lock(); defer { lock.unlock() }
        guard !armed, !ended else { return }
        armed = true
        let item = DispatchWorkItem { [weak self] in self?.expire() }
        work = item
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 10, execute: item)
    }
    func cancel() {
        lock.lock(); ended = true; let item = work; work = nil; lock.unlock()
        item?.cancel()
    }
    func expire() {
        lock.lock()
        let run = armed && !ended
        if run { ended = true; work = nil }
        lock.unlock()
        if run { expired() }
    }
    deinit { work?.cancel() }
}
#endif
