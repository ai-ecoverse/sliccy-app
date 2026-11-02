import Foundation

struct InventoryInstance: Decodable, Equatable, Sendable { var id: String; var name: String? }
struct InventoryAgent: Decodable, Equatable, Identifiable, Sendable {
    var id: String
    var kind: String
    var parent: String?
    var status: String
    var queued: Int
    var provider: String?
    var model: String?
}

struct InventoryTime: Decodable, Equatable, Sendable {
    var date: Date?
    init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer()
        if let milliseconds = try? value.decode(Double.self), milliseconds.isFinite {
            date = Date(timeIntervalSince1970: milliseconds / 1000)
        } else if let string = try? value.decode(String.self) {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions.insert(.withFractionalSeconds)
            date = formatter.date(from: string)
            if date == nil { formatter.formatOptions.remove(.withFractionalSeconds); date = formatter.date(from: string) }
        }
    }
}

struct AgentInventory {
    var agents: [InventoryAgent] = []
    var counts: [String: Int] = [:]
    var instance: InventoryInstance?
    var seq: UInt64?
    var reportedAt: Date?
    var receivedAt: Date?
    var observedAt: Date?
    var active = false
    var message: String?

    func isFresh(at now: Date) -> Bool {
        guard active, let reportedAt, let observedAt else { return false }
        return abs(now.timeIntervalSince(reportedAt)) <= 60 && now.timeIntervalSince(observedAt) <= 60
    }

    mutating func apply(_ event: CLIEvent, now: Date = Date()) {
        guard event.schema == 1 else { return }
        switch event.kind {
        case "inventory":
            guard event.v == 1, let agents = event.agents, let instance = event.instance,
                  let counts = event.counts, let seq = event.seq,
                  ["running", "queued", "waiting", "idle", "error"].allSatisfy({ counts[$0] != nil }),
                  counts.values.allSatisfy({ $0 >= 0 }), agents.allSatisfy({ $0.queued >= 0 }),
                  Set(agents.map(\.id)).count == agents.count else {
                active = false; message = "Seven returned an incompatible agent inventory."; return
            }
            // Whole snapshots: a lower seq means an agent restart, not a stale delta.
            self.agents = agents; self.instance = instance; self.counts = counts; self.seq = seq
            reportedAt = event.reportedAt?.date; receivedAt = event.receivedAt?.date; observedAt = now
            active = true; message = nil
        case "reconnecting": active = false; message = "Reconnecting to agent inventory…"
        case "error": active = false; message = event.message ?? "Agent inventory is unavailable."
        default: break
        }
    }
}
