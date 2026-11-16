import AppKit
import Observation

@MainActor protocol DefaultBrowserSystem {
    func handler(for scheme: String) -> URL?
    func claim(_ scheme: String, app: URL) async throws
}

@MainActor struct WorkspaceBrowserSystem: DefaultBrowserSystem {
    func handler(for scheme: String) -> URL? {
        NSWorkspace.shared.urlForApplication(toOpen: URL(string: "\(scheme)://example.com")!)
    }
    func claim(_ scheme: String, app: URL) async throws {
        try await NSWorkspace.shared.setDefaultApplication(at: app, toOpenURLsWithScheme: scheme)
    }
}

@MainActor @Observable final class DefaultBrowserRegistration {
    static let schemes = ["http", "https"]
    private(set) var isDefault = false
    private(set) var requesting = false
    private(set) var message: String?
    private let system: any DefaultBrowserSystem
    private let app: URL
    let canRegister: Bool

    init(app: URL = Bundle.main.bundleURL, system: any DefaultBrowserSystem = WorkspaceBrowserSystem(), canRegister: Bool? = nil) {
        self.app = app
        self.system = system
        self.canRegister = canRegister ?? (app.pathExtension == "app" && Bundle.main.object(forInfoDictionaryKey: "SliccyHandlesWebLinks") as? Bool == true)
        refresh()
    }
    func refresh() {
        isDefault = Self.schemes.allSatisfy {
            system.handler(for: $0)?.standardizedFileURL.resolvingSymlinksInPath().path == app.standardizedFileURL.resolvingSymlinksInPath().path
        }
    }
    func makeDefault() async {
        guard canRegister, !requesting else { return }
        requesting = true
        message = nil
        defer { requesting = false; refresh() }
        do {
            for scheme in Self.schemes { try await system.claim(scheme, app: app) }
            refresh()
            if !isDefault { message = "The default browser was not changed for both web-link types. You can try again or choose it in System Settings." }
        } catch {
            message = "macOS did not complete the default-browser change. You can keep your current browser or try again."
        }
    }
}
