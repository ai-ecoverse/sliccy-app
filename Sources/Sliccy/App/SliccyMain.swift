import AppKit
import SwiftUI

@main
enum SliccyMain {
    @MainActor static func main() {
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
    }
}
