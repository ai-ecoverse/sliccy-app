#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

final class ScreenRunnerLaunchCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, ScreenRunnerLaunchBarrier.Failure>?
    private var continuation: CheckedContinuation<Void, any Error>?
    func wait() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { install($0) }
        } onCancel: { self.finish(.failure(.cancelled)) }
    }
    private func install(_ value: CheckedContinuation<Void, any Error>) {
        lock.lock()
        if let result { lock.unlock(); value.resume(with: result.mapError { $0 as any Error }); return }
        continuation = value; lock.unlock()
    }
    func finish(_ value: Result<Void, ScreenRunnerLaunchBarrier.Failure>) {
        lock.lock()
        guard result == nil else { lock.unlock(); return }
        result = value; let pending = continuation; continuation = nil
        lock.unlock(); pending?.resume(with: value.mapError { $0 as any Error })
    }
}
#endif
