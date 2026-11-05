import Foundation
import Darwin

enum ScreenFailure: Error { case incompatible, resourceLimit, stalled }
enum ScreenRunnerCase: String { case selectedWindow = "selected-window" }

@main struct ClockFixture {
    static func main() throws {
        let output = try ScreenRunnerJournal(.selectedWindow, authorityFailed: { exit(2) })
        output.emit("clock-anchor", ["marker": "runner-clock-anchor"], at: .now)
        if output.failed { exit(3) }
    }
}
