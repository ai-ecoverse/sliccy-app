#if SLICCY_CAPTURE_RUNNER_PROOF
import AppKit
@preconcurrency import ScreenCaptureKit

@MainActor
final class ScreenRunnerCaptureSource {
    let filter: SCContentFilter
    let scope: String
    let width: Int
    let height: Int
    private let inventory: ScreenRunnerInventory
    private init(inventory: ScreenRunnerInventory, filter: SCContentFilter, selected: ScreenRunnerCase) throws {
        self.inventory = inventory; self.filter = filter; scope = selected.scope
        let rect = scope == "window" ? inventory.allowed.frame : inventory.display.frame
        guard rect.width.rounded() == rect.width, rect.height.rounded() == rect.height else { throw ScreenFailure.protection }
        width = Int(rect.width); height = Int(rect.height)
        _ = try ScreenFilterBuilder.configuration(width: width, height: height)
    }
    static func make(inventory: ScreenRunnerInventory, selected: ScreenRunnerCase,
                     refused: (ScreenProofProtectedProbe.Refusal) -> Void) throws -> ScreenRunnerCaptureSource {
        guard try ScreenRunnerHost.require() == selected,
              CGPreflightScreenCaptureAccess() else { throw ScreenFailure.protection }
        return try ScreenRunnerCaptureSource(inventory: inventory, filter: inventory.filter(selected: selected, refused: refused), selected: selected)
    }
}
#endif
