import SwiftUI

struct SidebarView: View {
    let store: WorkspaceStore
    @Binding var selection: String
    let search: String
    var onRemove: (UUID) -> Void

    private var visible: [Session] {
        store.sessions.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.device.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        List(selection: $selection) {
            Section("Instances") {
                ForEach(visible) { session in
                    Label {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(session.name).lineLimit(1)
                            Text(session.runningAgentCount.map { "\($0) running · \(session.device)" } ?? "\(session.device) · Agents not reported")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                    } icon: {
                        Image(systemName: session.isFavorite ? "star" : session.kind.symbol)
                            .foregroundStyle(session.connection == .connected ? Color.accentColor : Color.secondary)
                    }
                    .padding(.vertical, 4)
                    .tag(session.id.uuidString)
                    .contextMenu {
                        Button(session.isFavorite ? "Remove Favorite" : "Favorite") {
                            store.update(session.id) { $0.isFavorite.toggle() }; store.save()
                        }
                        Button(session.connection == .disconnected ? "Connect" : "Disconnect") {
                            if session.connection == .disconnected { store.reconnect(session.id) }
                            else { store.disconnect(session.id) }
                        }
                        Divider()
                        Button("Remove Session…", role: .destructive) { onRemove(session.id) }
                    }
                }
                if visible.isEmpty { Text("No matching sessions").font(.caption).foregroundStyle(.secondary) }
            }
            Section("This Mac") {
                ForEach(Destination.allCases) { destination in
                    Label(destination.title, systemImage: destination.symbol).tag(destination.rawValue)
                }
            }
        }
        .listStyle(.sidebar)
        .navigationTitle("Sliccy")
        .safeAreaInset(edge: .bottom) {
            HStack {
                Image(systemName: "circle.hexagongrid.fill").foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Your Mac, connected").font(.caption).fontWeight(.medium)
                    Text("\(store.sessions.filter { $0.isLive && $0.connection == .connected }.count) live · \(store.sessions.filter { !$0.isLive && $0.connection == .connected }.count) demo").font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                SettingsLink { Image(systemName: "gearshape") }.buttonStyle(.plain).help("Settings")
            }
            .padding(14)
        }
    }
}
