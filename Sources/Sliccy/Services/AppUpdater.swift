import Combine
import Sparkle
import SwiftUI

@MainActor
final class AppUpdater: ObservableObject {
    @Published private(set) var canCheck = false
    @Published var automaticChecks = false {
        didSet { controller?.updater.automaticallyChecksForUpdates = automaticChecks }
    }
    let available: Bool
    /// Runs right before Sparkle quits Sliccy to relaunch an installed update.
    var willRelaunch: (() -> Void)? {
        get { relaunchDelegate.willRelaunch }
        set { relaunchDelegate.willRelaunch = newValue }
    }
    private var controller: SPUStandardUpdaterController?
    private let relaunchDelegate = RelaunchDelegate()

    init() {
        #if SLICCY_NATIVE_SCREEN_PROOF
        available = false
        #else
        available = Bundle.main.object(forInfoDictionaryKey: "SliccyEnableUpdater") as? Bool == true &&
            !ProcessInfo.processInfo.arguments.contains("--preview")
        #endif
        guard available else { return }
        let controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: relaunchDelegate, userDriverDelegate: nil)
        self.controller = controller
        automaticChecks = controller.updater.automaticallyChecksForUpdates
        controller.updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
        controller.updater.publisher(for: \.automaticallyChecksForUpdates)
            .removeDuplicates().assign(to: &$automaticChecks)
    }

    func check() { controller?.checkForUpdates(nil) }
}

/// Lets an update relaunch keep live links, as the CLI's own update does: see `UpdateResume`.
@MainActor
final class RelaunchDelegate: NSObject, SPUUpdaterDelegate {
    var willRelaunch: (() -> Void)?
    nonisolated func updaterWillRelaunchApplication(_ updater: SPUUpdater) {
        MainActor.assumeIsolated { willRelaunch?() }
    }
}

struct UpdateSettingsView: View {
    @ObservedObject var updater: AppUpdater
    var body: some View {
        Section("Software updates") {
            LabeledContent("Version", value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Development")
            Toggle("Automatically check for updates", isOn: $updater.automaticChecks)
                .disabled(!updater.available)
            Button("Check for Updates…", action: updater.check).disabled(!updater.canCheck)
            Text(updater.available ? "Updates are downloaded from GitHub and verified before installation. Sliccy asks before installing an update." : "Automatic updates are available in the signed GitHub release. Local development builds stay separate.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}
