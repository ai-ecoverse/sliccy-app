import AppKit
import SwiftUI

@main
enum SliccyMain {
    @MainActor static func main() {
#if SLICCY_NATIVE_SCREEN_PROOF
        if ProcessInfo.processInfo.arguments.dropFirst().first == "--screen-proof" {
            ScreenProofApp.run()
            return
        }
#endif
        SliccyApp.main()
    }
}
