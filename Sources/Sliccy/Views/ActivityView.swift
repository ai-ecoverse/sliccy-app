import SwiftUI

struct ActivityView: View {
    let session: Session
    var userLabel = "You"
    @AppStorage("appearance.showToolActivity") private var showTools = true
    @State private var followLatest = true

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                if session.entries.isEmpty {
                    ContentUnavailableView("A fresh conversation", systemImage: "bubble.left.and.text.bubble.right", description: Text("Connect and send a message to try the native activity view."))
                        .padding(.top, 45)
                } else {
                    LazyVStack(alignment: .leading, spacing: 24) {
                        ForEach(session.entries.filter { showTools || $0.role != .tool }) { entry in
                            ActivityRow(entry: entry, userLabel: userLabel).id(entry.id)
                        }
                        if session.isWorking {
                            HStack(spacing: 8) {
                                ProgressView().controlSize(.mini)
                                Text("Sliccy is responding…").font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Color.clear.frame(height: 1).id("latest")
                    }.padding(24)
                }
            }
            .defaultScrollAnchor(.bottom)
            .onChange(of: session.entries.last?.text) { _, _ in
                if followLatest { proxy.scrollTo("latest", anchor: .bottom) }
            }
            .onChange(of: session.entries.count) { _, _ in
                if followLatest { proxy.scrollTo("latest", anchor: .bottom) }
            }
            .overlay(alignment: .bottomTrailing) {
                Button {
                    followLatest.toggle()
                    if followLatest { proxy.scrollTo("latest", anchor: .bottom) }
                } label: {
                    Label(followLatest ? "Following" : "Follow latest", systemImage: followLatest ? "arrow.down.to.line" : "pause")
                }
                .font(.caption).buttonStyle(.bordered).controlSize(.small)
                .help("Turn off to read earlier activity without automatic scrolling")
                .padding(10)
            }
        }
    }
}

private struct ActivityRow: View {
    let entry: ActivityEntry
    let userLabel: String

    var body: some View {
        switch entry.role {
        case .tool:
            Label(entry.text, systemImage: "checkmark.circle")
                .font(.caption).foregroundStyle(.secondary)
                .padding(.vertical, 9).padding(.horizontal, 12)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                .textSelection(.enabled)
        case .notice:
            Label(entry.text, systemImage: "info.circle")
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
        case .user, .assistant:
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 7) {
                    if entry.role == .assistant {
                        Image(systemName: "circle.hexagongrid.fill").foregroundStyle(.tint)
                    }
                    Text(entry.role == .user ? userLabel : "Sliccy").fontWeight(.semibold)
                    Spacer()
                    Text(entry.date, style: .time).font(.caption2).foregroundStyle(.tertiary)
                }.font(.callout)
                Text(markdown(entry.text))
                    .font(.system(size: 14)).lineSpacing(5)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func markdown(_ text: String) -> AttributedString {
        (try? AttributedString(markdown: text, options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace))) ?? AttributedString(text)
    }
}
