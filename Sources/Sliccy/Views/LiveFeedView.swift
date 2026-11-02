import SwiftUI

struct LiveFeedView: View {
    let store: WorkspaceStore
    let session: Session
    private var feed: LiveFeed { session.liveFeed ?? .init() }
    private var display: Session {
        var copy = session
        copy.entries = feed.entries
        copy.isWorking = feed.busy == true
        return copy
    }
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: feed.state == .watching ? "dot.radiowaves.left.and.right" : "arrow.trianglehead.2.clockwise.rotate.90")
                Text(feed.state.title).fontWeight(.medium)
                if let wait = feed.retryDelay, feed.state == .reconnecting {
                    Text("Next attempt in about \(wait / 1000, specifier: "%.1f") s")
                }
                Spacer()
                if feed.state == .unavailable && session.connection == .connected {
                    Button("Retry") { store.startWatch(session.id) }.controlSize(.small)
                }
            }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 24).padding(.vertical, 12)
            if feed.entries.isEmpty {
                ContentUnavailableView("Waiting for activity", systemImage: "waveform", description: Text(
                    feed.state == .unsupported ? "This CLI cannot resume the live feed. Choose slicc 1.55 or later in Settings." :
                    session.connection == .disconnected ? "Connect to resume the feed from its saved position." :
                    "New activity from seven appears here. Earlier conversation history is not available."))
            } else {
                ActivityView(session: display, userLabel: "User")
            }
            Text("Live events and retained replay · Not a complete conversation history")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading).padding(16).background(.bar)
        }
    }
}
