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
    private var controller: SPUStandardUpdaterController?

    init() {
        #if SLICCY_NATIVE_SCREEN_PROOF
        available = false
        #else
        available = Bundle.main.object(forInfoDictionaryKey: "SliccyEnableUpdater") as? Bool == true &&
            !ProcessInfo.processInfo.arguments.contains("--preview")
        #endif
        guard available else { return }
        let controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        self.controller = controller
        automaticChecks = controller.updater.automaticallyChecksForUpdates
        controller.updater.publisher(for: \.canCheckForUpdates).assign(to: &$canCheck)
        controller.updater.publisher(for: \.automaticallyChecksForUpdates)
            .removeDuplicates().assign(to: &$automaticChecks)
    }

    func check() { controller?.checkForUpdates(nil) }
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
