import SwiftUI

struct SessionDetailView: View {
    let store: WorkspaceStore
    let session: Session
    var onRename: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .center) {
                BrowserIcon(bundleID: session.localBrowserProfile != nil ? session.localBrowserChoice.bundleID : nil,
                            fallback: session.kind.symbol, size: 36)
                VStack(alignment: .leading, spacing: 6) {
                    Text(session.name).font(.title2).fontWeight(.semibold)
                    HStack(spacing: 6) {
                        StatusLabel(state: session.connection, waiting: store.linkWaiting.contains(session.id))
                        Text("·")
                        Text(session.access.browser ?? session.kind.rawValue)
                    }.font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(action: onRename) { Image(systemName: "pencil") }
                    .help("Rename connection").accessibilityLabel("Rename connection")
                if session.localBrowserProfile != nil {
                    Button { store.showBrowser(session.id) } label: { Label("Show in \(session.localBrowserChoice.name)", systemImage: "arrow.up.forward.app") }
                        .disabled(session.connection != .connected || store.localTabURLs[session.id] == nil || store.openingBrowser.contains(session.id))
                        .help("Bring the connected SLICC tab to the front")
                }
                if store.canRetryLocalConnection(session.id) {
                    Button("Retry Connection") { store.retryLocalConnection(session.id) }
                        .help("Restart the SLICC link using this session’s saved browser, profile and access settings")
                }
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
    var waiting = false
    var body: some View {
        // A stalled local link is still connecting; say so instead of spinning silently.
        Label(waiting && state != .connected ? "Waiting for SLICC" : state.title,
              systemImage: waiting && state != .connected ? "exclamationmark.triangle" : state.symbol)
            .foregroundStyle(state == .connected ? Color.green : Color.secondary)
            .labelStyle(.titleAndIcon)
    }
}
