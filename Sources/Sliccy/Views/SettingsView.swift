import SwiftUI

struct SettingsView: View {
    let store: WorkspaceStore
    @State private var reset = false

    var body: some View {
        TabView {
            Form {
                Section("Instance management") {
                    Text("Inspect agents, models, credentials, and access from the instance overview. Live inventory appears when the connected runtime reports it.")
                        .foregroundStyle(.secondary)
                }
                Section("Windows") {
                    Text("Closing a window keeps Sliccy in the menu bar. Quit Sliccy disconnects live links. Remote agent runs continue in seven.")
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
                    Text("New Session offers opt-in live remote connections. Browser sessions and access editing use demo data. The app does not launch browsers or share Mac resources yet.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Section("Local demo data") {
                    Text("Instance settings, sample grants, and folder paths are saved on this Mac. Live join URLs stay in memory until you quit.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Reset Demo Workspace…", role: .destructive) { reset = true }
                }
            }.formStyle(.grouped).tabItem { Label("Runtime", systemImage: "terminal") }
        }
        .padding(12).frame(width: 510, height: 440)
        .alert("CLI compatibility", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
            Button("OK") { store.errorMessage = nil }
        } message: { Text(store.errorMessage ?? "") }
        .confirmationDialog("Reset the demo workspace?", isPresented: $reset) {
            Button("Reset Demo", role: .destructive) { store.resetDemo() }
        } message: { Text("This replaces your demo instances and access settings with the sample workspace.") }
    }
}
