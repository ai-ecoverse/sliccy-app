import SwiftUI
import AppKit

struct CuaAccessView: View {
    let store: WorkspaceStore
    let session: Session
    @State private var installations: [CuaInstallation] = []
    @State private var selected = ""
    @State private var confirming = false
    @State private var copied = false
    private var state: WorkspaceStore.CuaAccessState { store.cuaAccess[session.id] ?? .init() }
    private var installation: CuaInstallation? { installations.first { $0.id == selected } }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text("Computer access via Cua").font(.headline)
            GroupBox {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Let SLICC use Cua’s screen, keyboard, mouse and other computer tools. Cua manages its own permissions; this can affect other apps and files on your Mac.")
                        .font(.caption).foregroundStyle(.secondary)
                    if installations.isEmpty {
                        Text("Install and open Cua, then complete its permission setup.").font(.callout)
                        Link("Get Cua…", destination: URL(string: "https://cua.ai/docs/cua-driver/guides/cua-spaces")!)
                        Button("Check Again") { refresh() }
                    } else {
                        Picker("Use", selection: $selected) {
                            ForEach(installations) { Text($0.name + " · " + $0.app.deletingLastPathComponent().path).tag($0.id) }
                        }.disabled(state.enabled)
                        HStack {
                            Button("Open Cua") { if let installation { NSWorkspace.shared.open(installation.app) } }
                            Spacer()
                            Toggle("Allow computer access", isOn: Binding(get: { state.enabled }, set: { enabled in
                                copied = false
                                if enabled { confirming = true } else { store.disableCua(session.id) }
                            })).toggleStyle(.switch)
                            .disabled(!state.enabled && (installation == nil || session.connection != .connected || !session.access.network))
                        }
                        if state.starting { ProgressView("Connecting to Cua…").controlSize(.small) }
                        if state.command != nil {
                            Text("Run the setup command in this session’s SLICC terminal. It contains a private access link; anyone with that link and access to this Mac can use it while enabled.").font(.caption)
                            Button(copied ? "Copied Setup Command" : "Copy Setup Command") {
                                guard let command = state.command else { return }
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(command, forType: .string)
                                copied = true
                            }
                            Text("Bridge ready · Registration in SLICC is not checked").font(.caption).foregroundStyle(.secondary)
                        }
                        if !session.access.network || session.connection != .connected {
                            Text("Connect this local browser with Network relay enabled first.").font(.caption)
                        }
                    }
                    if let message = state.message { Text(message).font(.caption).foregroundStyle(.secondary) }
                    Text("Off by default. Disconnecting, losing the link, or quitting closes this access route. Actions already sent may finish. Other Cua clients and Cua’s own permissions remain unchanged.")
                        .font(.caption2).foregroundStyle(.secondary)
                }.padding(8).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .onAppear { refresh() }
        .confirmationDialog("Allow computer access through Cua?", isPresented: $confirming) {
            Button("Allow Computer Access") { if let installation { store.enableCua(installation, for: session.id) } }
        } message: {
            Text("SLICC will be able to use the tools allowed by your Cua installation, including screen content and input across apps. Sliccy’s browser, shell and SFTP switches do not restrict Cua’s tools. You will register the connection in SLICC next.")
        }
    }

    private func refresh() {
        installations = CuaInstallation.discover()
        if !installations.contains(where: { $0.id == selected }) { selected = installations.first?.id ?? "" }
    }
}
