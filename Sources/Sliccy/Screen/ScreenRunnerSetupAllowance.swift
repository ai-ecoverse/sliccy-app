#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

enum ScreenRunnerSetupAllowance {
    static let watchdogSeconds: Int64 = 120
    static let finalSeconds: Int64 = 150
    static func cleanupRemaining(elapsed: Double) -> Double { max(0, Double(finalSeconds) - elapsed) }
}

enum ScreenRunnerClockAnchor {
    static let marker = "runner-clock-anchor"
    static var fields: [String: Any] { ["marker": marker] }
}
#endif
