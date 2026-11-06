#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

/// Uses actual Foundation semantic equality dispatch; PID is a separate check.
enum ScreenRunnerLaunchInstance {
    struct Facts: Sendable {
        let pid: pid_t
        let bundle: String?
        let finished: Bool, terminated: Bool
    }
    static func matches(original: NSObject, current: NSObject?, originalFacts: Facts, currentFacts: Facts?,
                        expectedPID: pid_t, expectedBundle: String) -> Bool {
        guard let current, let currentFacts, current.isEqual(original) else { return false }
        guard expectedPID > 0, expectedBundle == "com.google.Chrome",
              originalFacts.pid == expectedPID, currentFacts.pid == expectedPID,
              originalFacts.bundle == expectedBundle, currentFacts.bundle == expectedBundle,
              originalFacts.finished, currentFacts.finished, !originalFacts.terminated, !currentFacts.terminated else { return false }
        return true
    }
}
#endif
