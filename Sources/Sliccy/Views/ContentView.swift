import SwiftUI

struct ContentView: View {
    @Bindable var store: WorkspaceStore
    @SceneStorage("workspace.selection") private var selection = ""
    @State private var search = ""
    @State private var removing: UUID?

    private var selectedSession: Session? { UUID(uuidString: selection).flatMap { store.session($0) } }

    var body: some View {
        NavigationSplitView {
            SidebarView(store: store, selection: $selection, search: search, onRemove: { removing = $0 })
                .navigationSplitViewColumnWidth(min: 210, ideal: 235, max: 300)
        } detail: {
            Group {
                if let session = selectedSession {
                    SessionDetailView(store: store, session: session)
                        .id(session.id)
                } else if selection == Destination.browsers.rawValue {
                    BrowsersView(store: store, search: search)
                } else if selection == Destination.folders.rawValue {
                    FoldersView(store: store, onSelect: { selection = $0.uuidString })
                } else {
                    ContentUnavailableView {
                        Label("Make room for your next idea", systemImage: "circle.hexagongrid")
                    } description: {
                        Text("Start a session to bring seven and this Mac together.")
                    } actions: {
                        Button("New Session…") { store.startNew() }.buttonStyle(.borderedProminent)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if selectedSession?.isLive != true { DemoBanner() }
            }
        }
        .searchable(text: $search, prompt: "Find sessions and apps")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { store.startNew() } label: { Label("New Session", systemImage: "plus") }
                    .help("New Session (⌘N)")
            }

        }
        .sheet(isPresented: $store.showNewSession) { NewSessionView(store: store) }
        .sheet(isPresented: Binding(get: { store.credentialSession != nil }, set: { if !$0 { store.credentialSession = nil } })) {
            if let id = store.credentialSession { ReconnectView(store: store, id: id) }
        }
        .alert("Sliccy", isPresented: Binding(get: { store.errorMessage != nil }, set: { if !$0 { store.errorMessage = nil } })) {
            Button("OK") { store.errorMessage = nil }
        } message: { Text(store.errorMessage ?? "") }
        .confirmationDialog("Remove this session?", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("Remove Session", role: .destructive) {
                if let id = removing { store.remove(id) }
                removing = nil
                if selectedSession == nil { selection = store.sessions.first?.id.uuidString ?? "" }
            }
        } message: { Text("Its local activity will be removed and its connection will close. Any remote agent run continues in seven.") }
        .onAppear {
            let knownDestination = Destination(rawValue: selection) != nil
            if !knownDestination && selectedSession == nil {
                selection = store.sessions.first?.id.uuidString ?? ""
            }
            store.save()
            if ProcessInfo.processInfo.arguments.contains("--show-overview") { selection = store.sessions.first?.id.uuidString ?? "" }
            if ProcessInfo.processInfo.arguments.contains("--show-live-setup") { store.showNewSession = true }
        }
        .onChange(of: store.requestedSelection) { _, id in
            if let id { selection = id.uuidString; store.requestedSelection = nil }
        }
        .frame(minWidth: 820, minHeight: 560)
    }
}

private struct DemoBanner: View {
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "flask")
            Text("Demo session") .fontWeight(.medium)
            Text("· Sample data. This sample is not connected or shared.")
            Spacer(minLength: 0)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 20).padding(.vertical, 9)
        .background(.bar)
    }
}
