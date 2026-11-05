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
#if SLICCY_CAPTURE_RUNNER_PROOF
        case chromeA1 = "chrome-a-1", chromeA2 = "chrome-a-2", chromeB1 = "chrome-b-1", chromeB2 = "chrome-b-2"
        case windowManager = "window-manager", dock, finder, windowServer = "window-server"
#endif
        case authorization
        case systemSettings = "system-settings"
        case tcc, password
    }
    struct Target {
        let label: Label
        let application: SCRunningApplication
        let windows: [SCWindow]
#if SLICCY_CAPTURE_RUNNER_PROOF
        var inventoryIdentity: ScreenRunnerInventoryBoundary.Identity? = nil
        var windowServerWitness: ScreenRunnerInventoryBoundary.WindowServerEmptyBundleWitness? = nil
#endif
    }
    struct Refusal: Sendable {
        let label: Label
        let type: String
        let pid: pid_t
        let windowID: UInt32?
        // A nonzero-layer window has an independent exclusion rule. Its
        // rejection cannot prove the protected-owner predicate by itself.
        let predicateEvidence: Bool
#if SLICCY_CAPTURE_RUNNER_PROOF
        var structural: ScreenRunnerStructuralRefusal? = nil
#endif
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

#if SLICCY_CAPTURE_RUNNER_PROOF
    static func requireStructuralRefusals(witness: ScreenRunnerInventoryBoundary.WindowServerEmptyBundleWitness,
        identity: ScreenRunnerInventoryBoundary.Identity, label: Label, pid: pid_t, bundle: String,
        windows: [ScreenRunnerInventoryBoundary.SCKRecord], display: () throws -> Void,
        window: (UInt32) throws -> Void, refused: (Refusal) -> Void) throws {
        guard label == .windowServer, witness.matches(identity: identity, pid: pid, bundle: bundle, windows: windows) else {
            throw Failure.unresolvedOwner
        }
        try requireRefusal(display)
        refused(.init(label: label, type: "display", pid: pid, windowID: nil, predicateEvidence: false,
            structural: .init(witness: witness, windowID: nil)))
        for value in windows.sorted(by: { $0.id < $1.id }) {
            try requireRefusal { try window(value.id) }
            refused(.init(label: label, type: "window", pid: pid, windowID: value.id, predicateEvidence: false,
                structural: .init(witness: witness, windowID: value.id)))
        }
    }
#endif

    /// Caller must first obtain independent process/window attribution. These
    /// structural checks prevent missing/mismatched objects counting as refusal;
    /// they are not a replacement for the external driver's ownership evidence.
    static func check(display: SCDisplay, targets: [Target], protected: ScreenProtectedSet,
                      refused: (Refusal) -> Void) throws {
        guard !targets.isEmpty, targets.count <= 16 else { throw Failure.unresolvedOwner }
        var owners = Set<pid_t>()
#if !SLICCY_CAPTURE_RUNNER_PROOF
        var labels = Set<Label>()
#endif
        var observedWindows = Set<UInt32>()
        for target in targets {
            let app = target.application
#if !SLICCY_CAPTURE_RUNNER_PROOF
            guard labels.insert(target.label).inserted else { throw Failure.unresolvedOwner }
#endif
#if SLICCY_CAPTURE_RUNNER_PROOF
            let structural = app.bundleIdentifier.isEmpty && target.windowServerWitness != nil
            guard structural || (target.windowServerWitness == nil && !app.bundleIdentifier.isEmpty) else { throw Failure.unresolvedOwner }
#else
            guard !app.bundleIdentifier.isEmpty else { throw Failure.unresolvedOwner }
#endif
            guard owners.insert(app.processID).inserted, app.processID > 0,
                  !target.windows.isEmpty,
                  target.windows.count <= 64 else { throw Failure.unresolvedOwner }
            for window in target.windows {
                guard let owner = window.owningApplication, window.windowID > 0,
                      owner.processID == app.processID, owner.bundleIdentifier == app.bundleIdentifier,
                      observedWindows.insert(window.windowID).inserted else { throw Failure.unresolvedOwner }
            }
#if SLICCY_CAPTURE_RUNNER_PROOF
            if structural {
                guard let witness = target.windowServerWitness, let identity = target.inventoryIdentity else { throw Failure.unresolvedOwner }
                let records = target.windows.map { value in
                    ScreenRunnerInventoryBoundary.SCKRecord(id: value.windowID, pid: app.processID,
                        bundle: value.owningApplication!.bundleIdentifier, rect: value.frame, layer: value.windowLayer)
                }
                try requireStructuralRefusals(witness: witness, identity: identity, label: target.label,
                    pid: app.processID, bundle: app.bundleIdentifier, windows: records, display: {
                        _ = try ScreenFilterBuilder.display(display, selected: [app], exceptingWindows: [], protected: protected)
                    }, window: { id in
                        guard let actual = target.windows.first(where: { $0.windowID == id }) else { throw Failure.unresolvedOwner }
                        _ = try ScreenFilterBuilder.window(actual, protected: protected)
                    }, refused: refused)
                continue
            }
#endif
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
