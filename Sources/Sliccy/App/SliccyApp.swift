import AppKit
import SwiftUI
import OSLog

struct SliccyApp: App {
    @StateObject private var updater = AppUpdater()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var store = WorkspaceStore(
        preview: ProcessInfo.processInfo.arguments.contains("--preview"),
        defaults: ProcessInfo.processInfo.arguments.contains("--preview") ? nil : .standard)

    var body: some Scene {
        WindowGroup("Sliccy", id: "workspace") {
            ContentView(store: store)
                .onAppear {
                    delegate.attachWebLinks({ store.incomingLinks.receive($0) }, overflow: { store.errorMessage = "Too many links arrived during startup. Open them in smaller groups." })
                    delegate.shutdown = { store.incomingLinks.cancel(); store.shutdown() }
                }
        }
        .defaultSize(width: 1120, height: 780)
        .defaultLaunchBehavior(.presented)
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Check for Updates…", action: updater.check).disabled(!updater.canCheck)
            }
            CommandGroup(replacing: .newItem) {
                Button("New Session…") { store.startNew() }.keyboardShortcut("n")
            }
            CommandMenu("Session") {
                ForEach(store.sessions) { session in
                    Button(session.name) { store.requestedSelection = session.id }
                }
            }
        }
        Settings { SettingsView(store: store, updater: updater) }
        MenuBarExtra("Sliccy", systemImage: "circle.hexagongrid") {
            MenuBarView(store: store)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var shutdown: (() -> Void)?
    private var webLinks: (([URL]) -> Void)?
    private var pendingWebLinks: [URL] = []
    private var pendingLinkOverflow = false
    func application(_ application: NSApplication, open urls: [URL]) {
        if let webLinks { webLinks(urls) }
        else if pendingWebLinks.count + urls.count <= 32 { pendingWebLinks.append(contentsOf: urls) }
        else { pendingLinkOverflow = true }
    }
    func attachWebLinks(_ receive: @escaping ([URL]) -> Void, overflow: () -> Void) {
        webLinks = receive
        if pendingLinkOverflow {
            overflow()
        }
        let links = pendingWebLinks
        pendingWebLinks.removeAll()
        pendingLinkOverflow = false
        if !links.isEmpty { receive(links) }
    }
    private var auditMaintenance: ScreenAuditMaintenance?
    func applicationWillTerminate(_ notification: Notification) {
        auditMaintenance?.stop()
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        shutdown?()
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        if ScreenReleasePolicy.identityProofApproved && !ProcessInfo.processInfo.arguments.contains("--preview") {
            do {
                auditMaintenance = ScreenAuditMaintenance(audit: try ScreenAudit())
                NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(didWake), name: NSWorkspace.didWakeNotification, object: nil)
            } catch {
                Logger(subsystem: "ai.sliccy.mac", category: "Audit").error("Audit maintenance could not start")
            }
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        Task { @MainActor in
            await Task.yield()
            let windows = NSApp.windows.filter { $0.canBecomeMain }
            Logger(subsystem: "ai.sliccy.mac", category: "Lifecycle")
                .info("Launch completed: \(windows.count) main-capable windows; visible: \(windows.filter(\.isVisible).count)")
        }
    }
    @objc private func didWake(_ notification: Notification) { auditMaintenance?.sweepAfterWake() }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

private struct MenuBarView: View {
    let store: WorkspaceStore
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Text("Sliccy")
        Text("\(store.connectedCount) connections")
        Divider()
        ForEach(store.sessions) { session in
            Button(String(session.name.prefix(28))) {
                store.requestedSelection = session.id
                openWindow(id: "workspace")
                NSApp.activate(ignoringOtherApps: true)
            }
        }
        Divider()
        Button("Open Sliccy") { openWindow(id: "workspace"); NSApp.activate(ignoringOtherApps: true) }
        SettingsLink()
        Button("Quit Sliccy") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
