import SwiftUI

struct SessionDetailView: View {
    let store: WorkspaceStore
    let session: Session

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(session.name).font(.title2).fontWeight(.semibold)
                    HStack(spacing: 6) {
                        StatusLabel(state: session.connection)
                        Text("·")
                        Text(session.access.browser ?? session.kind.rawValue)
                    }.font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(session.connection == .disconnected ? "Connect" : "Disconnect") {
                    if session.connection == .disconnected { store.reconnect(session.id) }
                    else { store.disconnect(session.id) }
                }

            }
            .padding(.horizontal, 24).padding(.top, 22).padding(.bottom, 20)

            if let message = session.connectionMessage, session.isLive {
                Label(message, systemImage: "info.circle")
                    .font(.callout).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 24).padding(.bottom, 12)
            }
            Divider()
            InstanceOverviewView(store: store, session: session)
        }
        .navigationTitle(session.name)
    }
}

struct StatusLabel: View {
    let state: ConnectionState
    var body: some View {
        Label(state.title, systemImage: state.symbol)
            .foregroundStyle(state == .connected ? Color.green : Color.secondary)
            .labelStyle(.titleAndIcon)
    }
}
