import SwiftUI
import AppKit

struct SettingsView: View {
    let store: WorkspaceStore
    @ObservedObject var updater: AppUpdater
    @State private var reset = false
    @State private var defaultBrowser = DefaultBrowserRegistration()

    private var linkDestinationAvailable: Bool {
        guard !store.isDemo else { return false }
        guard let id = store.webLinkDestination else { return false }
        return store.session(id)?.localBrowserChoice.isInstalled == true
    }

    var body: some View {
        TabView {
            Form {
                UpdateSettingsView(updater: updater)
                Section("Default web browser") {
                    Picker("Preferred browser session", selection: Binding(get: { store.linkSessionID }, set: { store.linkSessionID = $0 })) {
                        Text("First configured profile").tag(nil as UUID?)
                        ForEach(store.linkSessions) { session in
                            Text("\(session.name) · \(session.localBrowserChoice.name) · \(session.localBrowserProfile ?? "")").tag(Optional(session.id))
                        }
                        if let id = store.linkSessionID, !store.linkSessions.contains(where: { $0.id == id }) {
                            Text("Session removed — choose a destination").tag(Optional(id))
                        }
                    }
                    Text("Web links go to an attached local browser first. If none is attached, Sliccy starts the preferred session, or the first configured profile, with its saved browser and access settings. The preference also chooses between attached browsers.")
                        .font(.caption).foregroundStyle(.secondary)
                    if defaultBrowser.isDefault {
                        Label("Sliccy is your default web browser", systemImage: "checkmark.circle.fill")
                    } else {
                        Button(defaultBrowser.requesting ? "Waiting for macOS…" : "Make Sliccy Default Browser…") {
                            Task { await defaultBrowser.makeDefault() }
                        }
                        .disabled(defaultBrowser.requesting || !defaultBrowser.canRegister || !linkDestinationAvailable)
                    }
                    if let message = defaultBrowser.message { Text(message).font(.caption) }
                    if !defaultBrowser.canRegister { Text("Use an installed app build to change the default browser.").font(.caption) }
                    if !linkDestinationAvailable { Text("Configure a local browser profile before making Sliccy the default.").font(.caption) }
                }
                .onAppear { defaultBrowser.refresh() }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in defaultBrowser.refresh() }
                Section("Instance management") {
                    Text("Inspect agents, models, credentials, and access from the instance overview. Live inventory appears when the connected runtime reports it.")
                        .foregroundStyle(.secondary)
                }
                Section("Windows") {
                    Text("Closing a window keeps Sliccy in the menu bar. Quit Sliccy disconnects live links. Remote agent runs continue in SLICC.")
                        .foregroundStyle(.secondary)
                }
            }.formStyle(.grouped).tabItem { Label("General", systemImage: "gearshape") }

            Form {
                Section("Runtime") {
                    TextField("CLI executable", text: Binding(get: { store.cliExecutable }, set: { store.cliExecutable = $0 }))
                    HStack {
                        Button(store.checkingCLI ? "Checking…" : "Check Compatibility") { Task { await store.checkCLI() } }
                            .disabled(store.checkingCLI)
                        if let version = store.cliVersion { Label("slicc \(version)", systemImage: "checkmark.circle.fill").foregroundStyle(.green) }
                    }
                    LabeledContent("Platform", value: "Native SwiftUI · macOS 27")
                    Text("Launch SLICC in its Chrome profile on this Mac, or connect to a remote instance with a join URL. Local sessions offer Chrome and network access; remote connections offer no Mac resources by default.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if store.isDemo {
                    Section("Local demo data") {
                        Text("Instance settings, sample grants, and folder paths are saved on this Mac. Live join URLs stay in memory until you quit.")
                            .font(.caption).foregroundStyle(.secondary)
                        Button("Reset Demo Workspace…", role: .destructive) { reset = true }
                    }
                }
            }.formStyle(.grouped).tabItem { Label("Runtime", systemImage: "terminal") }
        }
        .padding(12).frame(width: 510, height: 560)
        .alert("CLI compatibility", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
            Button("OK") { store.errorMessage = nil }
        } message: { Text(store.errorMessage ?? "") }
        .confirmationDialog("Reset the demo workspace?", isPresented: $reset) {
            Button("Reset Demo", role: .destructive) { store.resetDemo() }
        } message: { Text("This replaces your demo instances and access settings with the sample workspace.") }
    }
}
