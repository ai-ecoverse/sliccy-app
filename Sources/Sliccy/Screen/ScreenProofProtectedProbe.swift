#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation
import ScreenCaptureKit

/// This observes the real builder boundary; it cannot change eligibility or
/// construct a stream. A post-construction failure is not a policy refusal.
enum ScreenProofFilterConstruction {
    @TaskLocal static var observer: (@Sendable () -> Void)?
    static func reached() { observer?() }
}

enum ScreenProofProtectedProbe {
    enum Label: String, Sendable, CaseIterable {
        case app
        case chromeA = "chrome-a", chromeB = "chrome-b"
        case authorization
        case systemSettings = "system-settings"
        case tcc, password
    }
    struct Target {
        let label: Label
        let application: SCRunningApplication
        let windows: [SCWindow]
    }
    struct Refusal: Sendable {
        let label: Label
        let type: String
        let pid: pid_t
        let windowID: UInt32?
        // A nonzero-layer window has an independent exclusion rule. Its
        // rejection cannot prove the protected-owner predicate by itself.
        let predicateEvidence: Bool
    }
    enum Failure: Error, Equatable {
        case unresolvedOwner
        case constructionReached
        case wrongRefusal
        case unexpectedlyAccepted
    }
    private final class Witness: @unchecked Sendable {
        private let lock = NSLock()
        private var constructed = false
        func record() { lock.lock(); constructed = true; lock.unlock() }
        var reached: Bool { lock.lock(); defer { lock.unlock() }; return constructed }
    }

    /// Reject success and every error that is not a pre-construction protection
    /// refusal. This prevents an SCK/postcondition error from becoming a pass.
    static func requireRefusal<T>(_ build: () throws -> T) throws {
        let witness = Witness()
        var refusal: (any Error)?
        do {
            _ = try ScreenProofFilterConstruction.$observer.withValue({ witness.record() }, operation: build)
        } catch { refusal = error }
        guard !witness.reached else { throw Failure.constructionReached }
        guard let refusal else { throw Failure.unexpectedlyAccepted }
        guard refusal as? ScreenFailure == .protection else { throw Failure.wrongRefusal }
    }

    /// Caller must first obtain independent process/window attribution. These
    /// structural checks prevent missing/mismatched objects counting as refusal;
    /// they are not a replacement for the external driver's ownership evidence.
    static func check(display: SCDisplay, targets: [Target], protected: ScreenProtectedSet,
                      refused: (Refusal) -> Void) throws {
        guard !targets.isEmpty, targets.count <= 16 else { throw Failure.unresolvedOwner }
        var labels = Set<Label>()
        var observedWindows = Set<UInt32>()
        for target in targets {
            let app = target.application
            guard labels.insert(target.label).inserted, app.processID > 0,
                  !app.bundleIdentifier.isEmpty, !target.windows.isEmpty,
                  target.windows.count <= 64 else { throw Failure.unresolvedOwner }
            for window in target.windows {
                guard let owner = window.owningApplication, window.windowID > 0,
                      owner.processID == app.processID, owner.bundleIdentifier == app.bundleIdentifier,
                      observedWindows.insert(window.windowID).inserted else { throw Failure.unresolvedOwner }
            }
            // No pre-check with protected.excludes: that would test an imitation
            // of the predicate instead of requiring the actual builder refusal.
            try requireRefusal {
                try ScreenFilterBuilder.display(display, selected: [app], exceptingWindows: [], protected: protected)
            }
            refused(.init(label: target.label, type: "display", pid: app.processID, windowID: nil, predicateEvidence: true))
            for window in target.windows {
                try requireRefusal { try ScreenFilterBuilder.window(window, protected: protected) }
                refused(.init(label: target.label, type: "window", pid: app.processID,
                              windowID: window.windowID, predicateEvidence: window.windowLayer == 0))
            }
        }
    }
}
#endif
