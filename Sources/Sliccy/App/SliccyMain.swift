import AppKit
import SwiftUI

@main
enum SliccyMain {
    @MainActor static func main() {
#if SLICCY_CAPTURE_RUNNER_PROOF
        ScreenRunnerProofApp.run()
#elseif SLICCY_HOSTED_PID_PROOF
        ScreenHostedPIDProofApp.run()
#elseif SLICCY_SNAPSHOT_PROOF
        guard (try? ScreenSnapshotCase.parse(Array(ProcessInfo.processInfo.arguments.dropFirst()))) != nil else { exit(2) }
        ScreenSnapshotProofApp.run()
#elseif SLICCY_UNIVERSAL_SLICE_PROOF
        // This separately signed fixture has no workspace or other proof entry.
        guard (try? ScreenUniversalCase.parse(Array(ProcessInfo.processInfo.arguments.dropFirst()))) != nil else { exit(2) }
        ScreenUniversalProofApp.run()
#else
        if ProcessInfo.processInfo.arguments.dropFirst().first == "--screen-proof" {
#if SLICCY_NATIVE_SCREEN_PROOF
            ScreenProofApp.run()
#else
            try? FileHandle.standardError.write(contentsOf: Data("This app does not include connection diagnostics.\n".utf8))
            exit(2)
#endif
            return
        }
        SliccyApp.main()
#endif
    }
}
