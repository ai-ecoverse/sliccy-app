import Foundation
import ScreenCaptureKit

struct ScreenProtectedSet: Sendable {
    // Bundle IDs supplement verified process identities; they never prove an app eligible.
    static let fixedBundles: Set<String> = [
        "ai.sliccy.mac", "com.apple.SecurityAgent", "com.apple.securityagent",
        "com.apple.AuthorizationHost", "com.apple.authorizationhost",
        "com.apple.UserNotificationCenter", "com.apple.CoreServicesUIAgent",
        "com.apple.tccd", "com.apple.loginwindow"
    ]
    var hostBundleIDs: Set<String> = []
    var hostPIDs: Set<Int32> = []
    var allowSystemSettings = false
    var excludedBundleIDs: Set<String> {
        Self.fixedBundles.union(hostBundleIDs).union(allowSystemSettings ? [] : ["com.apple.systempreferences"])
    }
    func excludes(bundle: String, pid: Int32) -> Bool {
        hostPIDs.contains(pid) || excludedBundleIDs.contains(where: { bundle == $0 || bundle.hasPrefix($0 + ".") })
    }
}

/// The actual SCK construction boundary, used by the picker and native fixture harness.
/// Structural correctness here is not proof of compositor/service-surface safety.
enum ScreenFilterBuilder {
    struct Exception: Decodable { var owner: String; var window: String }
    struct Vector: Decodable { var name: String; var included: [String]; var exceptingWindows: [Exception]; var allowed: Bool }
    struct Fixture: Decodable { var v: Int; var vectors: [Vector]; var nativeBuilderMustConsume: Bool }

    static func display(_ display: SCDisplay, selected: [SCRunningApplication],
                        exceptingWindows: [SCWindow] = [], protected: ScreenProtectedSet) throws -> SCContentFilter {
        // Never turn an exclusion into an exception: SCK can re-include its owner.
        guard exceptingWindows.isEmpty else { throw ScreenFailure.protection }
        guard !selected.isEmpty, selected.allSatisfy({ !$0.bundleIdentifier.isEmpty && !protected.excludes(bundle: $0.bundleIdentifier, pid: $0.processID) }) else { throw ScreenFailure.protection }
#if SLICCY_NATIVE_SCREEN_PROOF
        ScreenProofFilterConstruction.reached()
#endif
        let filter = SCContentFilter(display: display, including: selected, exceptingWindows: [])
        filter.includeMenuBar = false
        guard Set(filter.includedApplications.map(\.processID)) == Set(selected.map(\.processID)) else { throw ScreenFailure.protection }
        return filter
    }

    static func window(_ window: SCWindow, protected: ScreenProtectedSet) throws -> SCContentFilter {
        guard let app = window.owningApplication, !app.bundleIdentifier.isEmpty,
              !protected.excludes(bundle: app.bundleIdentifier, pid: app.processID), window.windowLayer == 0 else { throw ScreenFailure.protection }
#if SLICCY_NATIVE_SCREEN_PROOF
        ScreenProofFilterConstruction.reached()
#endif
        return SCContentFilter(desktopIndependentWindow: window)
    }

    /// Map synthetic fixture labels to genuine SC objects supplied by the native harness.
    static func consume(_ vector: Vector, display: SCDisplay,
                        applications: [String: SCRunningApplication], windows: [String: SCWindow],
                        protected: ScreenProtectedSet) throws -> SCContentFilter {
        // Reject before lookup/construction, even if an exception cannot be resolved.
        guard vector.exceptingWindows.isEmpty else { throw ScreenFailure.protection }
        let selected = try vector.included.map { label in
            guard let app = applications[label] else { throw ScreenFailure.protection }
            return app
        }
        return try self.display(display, selected: selected, protected: protected)
    }

    static func configuration(width: Int, height: Int, fps: Int = 5) throws -> SCStreamConfiguration {
        guard width > 0, height > 0, max(width, height) <= 2560,
              width <= 4_000_000 / height, (1...10).contains(fps) else { throw ScreenFailure.resourceLimit }
        let configuration = SCStreamConfiguration()
        configuration.width = width; configuration.height = height
        configuration.minimumFrameInterval = CMTime(value: 1, timescale: CMTimeScale(fps))
        configuration.queueDepth = 3
        configuration.pixelFormat = kCVPixelFormatType_32BGRA
        configuration.showsCursor = false
        configuration.capturesAudio = false
        configuration.captureMicrophone = false
        configuration.includeChildWindows = false
        configuration.captureDynamicRange = .SDR
        return configuration
    }
}
