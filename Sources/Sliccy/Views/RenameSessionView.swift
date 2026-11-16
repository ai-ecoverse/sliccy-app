import SwiftUI

struct RenameSessionView: View {
    let store: WorkspaceStore
    let session: Session
    @Environment(\.dismiss) private var dismiss
    @FocusState private var focused: Bool
    @State private var name: String

    init(store: WorkspaceStore, session: Session) {
        self.store = store
        self.session = session
        _name = State(initialValue: session.name)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("Rename connection").font(.title2).fontWeight(.semibold)
            TextField("Name", text: $name).focused($focused)
            Text("Changes its name in Sliccy. Your browser profile and connection stay the same.")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("Rename") {
                    if store.rename(session.id, to: name) { dismiss() }
                }
                .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
                .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || store.session(session.id) == nil)
            }
        }
        .padding(24).frame(width: 420)
        .onAppear { focused = true }
    }
}
