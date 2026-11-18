import SwiftUI

struct ApprovalsView: View {
    let store: WorkspaceStore
    let session: Session
    private var queue: ApprovalQueue { store.approvals[session.id] ?? .init() }
    private var live: Bool { queue.active && session.connection == .connected }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(live ? "Live approvals" : queue.received ? "Not live · last snapshot shown" : "Approvals unavailable")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Retry") { store.startApprovals(session.id) }
                        .buttonStyle(.borderless)
                        .disabled(session.connection != .connected || store.approvalProcesses[session.id] != nil)
                }
                if let message = queue.message {
                    Text(message).font(.callout).foregroundStyle(.secondary)
                }
                if queue.items.isEmpty {
                    Text(queue.received ? "No pending approvals." : "No approvals received. Transcripts and prompts are not requested.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                ForEach(queue.items) { item in
                    row(item, now: context.date)
                    if item.id != queue.items.last?.id { Divider() }
                }
            }.padding(.vertical, 12)
        }
    }

    private func row(_ item: ApprovalItem, now: Date) -> some View {
        let busy = queue.deciding.contains(item.id)
        let answered = queue.answered.contains(item.id)
        let expired = item.expiresAt.date.map { $0 <= now } ?? false
        return VStack(alignment: .leading, spacing: 5) {
            HStack(alignment: .firstTextBaseline) {
                Text(item.kindLabel).font(.callout).fontWeight(.medium)
                Text(item.agentLabel).font(.caption).foregroundStyle(.secondary)
                Spacer()
                Text(item.timeLeft(at: now)).font(.caption).monospacedDigit().foregroundStyle(expired ? .red : .secondary)
            }
            Text(item.detailText).font(.callout.monospaced()).lineLimit(4).textSelection(.enabled)
                .help(item.detailText)
            Text(item.verdictText).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let refusal = queue.refusals[item.id] {
                Text(refusal).font(.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 8) {
                ForEach(item.answers, id: \.self) { answer in
                    Button(answer.title, role: answer == .deny || answer == .stop ? .destructive : nil) {
                        store.decide(item.id, answer: answer, for: session.id)
                    }
                }
                if busy { ProgressView().controlSize(.small) }
                if answered { Text("Answered · waiting for SLICC").font(.caption).foregroundStyle(.secondary) }
            }
            .controlSize(.small)
            .disabled(!live || busy || answered || expired || !item.answerable)
        }.padding(.vertical, 6)
    }
}
