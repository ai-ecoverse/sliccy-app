import SwiftUI

struct ComposerView: View {
    let store: WorkspaceStore
    let session: Session
    @State private var mode = DeliveryMode.followUp
    @FocusState private var focused: Bool

    private var draft: Binding<String> {
        Binding(get: { store.session(session.id)?.draft ?? "" }, set: { value in store.update(session.id) { $0.draft = value }; store.save() })
    }
    private var canSend: Bool { !store.aborting.contains(session.id) && session.connection == .connected && !session.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !session.queuedPrompts.isEmpty {
                Label("\(session.queuedPrompts.count) follow-up\(session.queuedPrompts.count == 1 ? "" : "s") queued", systemImage: "text.line.first.and.arrowtriangle.forward")
                    .font(.caption).foregroundStyle(.secondary)
            }
            VStack(spacing: 12) {
                TextField(session.connection == .connected ? "Ask a question or describe a task…" : "Connect to send a message", text: draft, axis: .vertical)
                    .textFieldStyle(.plain).lineLimit(2...6).font(.system(size: 14))
                    .focused($focused).disabled(session.connection != .connected)
                HStack {
                    Label(session.isLive ? "Live remote agent" : "Demo runtime", systemImage: session.isLive ? "network" : "flask").font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    if session.isWorking {
                        Picker("Delivery", selection: $mode) {
                            ForEach(DeliveryMode.allCases) { Text($0.rawValue).tag($0) }
                        }.labelsHidden().frame(width: 105).controlSize(.small)
                    }
                    Button {
                        store.send(session.draft, to: session.id, mode: mode)
                        focused = true
                    } label: {
                        Label(session.isWorking ? (mode == .steer ? "Steer" : "Queue") : "Send", systemImage: "arrow.up")
                    }
                    .buttonStyle(.borderedProminent).disabled(!canSend)
                    .keyboardShortcut(.return, modifiers: .command)
                    .help("Send (⌘Return)")
                }
            }
            .padding(16)
            .background(.background, in: RoundedRectangle(cornerRadius: 16))
            .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(.separator.opacity(0.65)))
            HStack {
                Text(session.isWorking ? "Follow-ups wait. Steering changes the current response." : "Return for a new line · ⌘Return to send")
                Spacer()
            }.font(.caption2).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, 20).padding(.top, 8).padding(.bottom, 14)
    }
}
