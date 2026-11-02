import AppKit
import SwiftUI
import OSLog

@main
struct SliccyApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var store = WorkspaceStore(defaults: ProcessInfo.processInfo.arguments.contains("--preview") ? nil : .standard)

    var body: some Scene {
        WindowGroup("Sliccy", id: "workspace") {
            ContentView(store: store)
                .onAppear { delegate.shutdown = { store.shutdown() } }
        }
        .defaultSize(width: 1120, height: 780)
        .defaultLaunchBehavior(.presented)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Session…") { store.startNew() }.keyboardShortcut("n")
            }
            CommandMenu("Session") {
                Button("New Session…") { store.startNew() }
                Divider()
                ForEach(store.sessions) { session in
                    Button(session.name) { store.requestedSelection = session.id }
                }
            }
        }
        Settings { SettingsView(store: store) }
        MenuBarExtra("Sliccy", systemImage: "circle.hexagongrid") {
            MenuBarView(store: store)
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var shutdown: (() -> Void)?
    func applicationWillTerminate(_ notification: Notification) { shutdown?() }
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        Task { @MainActor in
            await Task.yield()
            let windows = NSApp.windows.filter { $0.canBecomeMain }
            Logger(subsystem: "ai.sliccy.mac", category: "Lifecycle")
                .info("Launch completed: \(windows.count) main-capable windows; visible: \(windows.filter(\.isVisible).count)")
        }
    }
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
