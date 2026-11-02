import SwiftUI

struct AgentInventoryView: View {
    let store: WorkspaceStore
    let session: Session
    private var inventory: AgentInventory { store.inventories[session.id] ?? .init() }

    var body: some View {
        TimelineView(.periodic(from: .now, by: 5)) { context in
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text(inventory.isFresh(at: context.date) ? "Live inventory" : "Inventory unavailable or stale")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Button("Retry") { store.startInventory(session.id) }
                        .buttonStyle(.borderless)
                        .disabled(session.connection != .connected || store.inventoryProcesses[session.id] != nil)
                }
                if let message = inventory.message {
                    Text(message).font(.callout).foregroundStyle(.secondary)
                }
                if let reported = inventory.reportedAt {
                    Text("Seven reported \(reported.formatted(date: .omitted, time: .standard))")
                        .font(.caption2).foregroundStyle(.secondary)
                }
                if inventory.instance != nil {
                    Text(["running", "waiting", "queued", "idle", "error"].compactMap { key in
                        inventory.counts[key].map { "\($0) \(key)" }
                    }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary)
                }
                if inventory.agents.isEmpty {
                    Text(inventory.instance == nil ? "No inventory received. Names and transcript activity are not requested." : "No agents in the last reported inventory.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                ForEach(inventory.agents) { agent in
                    HStack(alignment: .top, spacing: 12) {
                        Circle().fill(inventory.isFresh(at: context.date) && agent.status == "running" ? Color.green : Color.secondary.opacity(0.4))
                            .frame(width: 6, height: 6).padding(.top, 5)
                        VStack(alignment: .leading, spacing: 3) {
                            Text("\(agent.kind.capitalized) · \(agent.id.prefix(8))").font(.callout)
                            if let parent = agent.parent { Text("Parent \(parent.prefix(8))").font(.caption2).foregroundStyle(.secondary) }
                        }.help(agent.id)
                        Spacer()
                        VStack(alignment: .trailing, spacing: 3) {
                            Text(agent.model ?? "Model not reported").font(.callout)
                            Text(agent.provider ?? "Provider not reported").font(.caption).foregroundStyle(.secondary)
                        }
                        VStack(alignment: .trailing, spacing: 3) {
                            Text(agent.status.capitalized).font(.caption)
                            Text("\(agent.queued) queued requests").font(.caption2).foregroundStyle(.secondary)
                        }.frame(minWidth: 90, alignment: .trailing)
                    }.padding(.vertical, 5)
                    if agent.id != inventory.agents.last?.id { Divider() }
                }
            }.padding(.vertical, 12)
        }
    }
}
