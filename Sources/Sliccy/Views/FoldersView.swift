import SwiftUI

struct FoldersView: View {
    let store: WorkspaceStore
    var onSelect: (UUID) -> Void
    private var sharing: [Session] { store.sessions.filter { $0.access.folders.contains(where: \.isEnabled) } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                PageHeading(title: "Shared Folders", subtitle: "A clear view of what leaves this Mac.")
                Text("Folder access belongs to a session. Choose an instance to switch folder access on or off.")
                    .font(.callout).foregroundStyle(.secondary)
                if sharing.isEmpty {
                    ContentUnavailableView("No shared folders", systemImage: "folder", description: Text("Add a folder from an instance’s entitlement view."))
                }
                ForEach(sharing) { session in
                    VStack(alignment: .leading, spacing: 14) {
                        HStack {
                            Text(session.name).font(.headline)
                            Spacer()
                            Button("Open Session") { onSelect(session.id) }.controlSize(.small)
                        }
                        ForEach(session.access.folders.filter(\.isEnabled)) { folder in
                            HStack(spacing: 12) {
                                Image(systemName: "folder.fill").font(.title2).foregroundStyle(.tint)
                                VStack(alignment: .leading, spacing: 5) {
                                    Text(folder.name).fontWeight(.medium)
                                    Text(folder.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                                }
                                Spacer()
                                Text(folder.readOnly ? "Read only" : "Read & write").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    Divider()
                }
            }.padding(28)
        }.navigationTitle("Shared Folders")
    }
}
