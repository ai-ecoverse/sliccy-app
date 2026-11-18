import Foundation

/// One pending approval on seven's `user` tier, as `slicc approvals --json` reports it.
/// Unknown fields are ignored; `detail` keeps only what this view shows.
struct ApprovalItem: Decodable, Equatable, Identifiable, Sendable {
    struct Requester: Decodable, Equatable, Sendable { var kind: String; var name: String; var `where`: String? }
    /// The item's scrubbed detail. Which fields are present depends on `kind`.
    struct Detail: Decodable, Equatable, Sendable {
        struct Attachment: Decodable, Equatable, Sendable { var name: String? }
        // sudo
        var command: String?
        var cwd: String?
        // guest-tool
        var tool: String?
        var summary: String?
        var arguments: String?
        // capture
        var what: String?
        var mode: String?
        var seconds: Double?
        var system: Bool?
        var microphone: Bool?
        var program: String?
        // guest-message: the text is a prompt and is never shown here.
        var attachments: [Attachment]?
    }
    struct Verdict: Decodable, Equatable, Sendable { var level: Int?; var reason: String? }

    var id: String
    var kind: String
    var agentId: String?
    var agentName: String?
    var requester: Requester
    var detail: Detail
    var tier: String
    var always: Bool
    var stoppable: Bool
    var verdict: Verdict?
    var judging: Bool?
    var verdictError: String?
    var createdAt: InventoryTime
    var expiresAt: InventoryTime

    enum CodingKeys: String, CodingKey {
        case id, kind, agentId, agentName, requester, detail, tier, always, stoppable, verdict, judging, verdictError, createdAt, expiresAt
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decode(String.self, forKey: .kind)
        agentId = try c.decodeIfPresent(String.self, forKey: .agentId)
        agentName = try c.decodeIfPresent(String.self, forKey: .agentName)
        requester = try c.decode(Requester.self, forKey: .requester)
        detail = (try? c.decodeIfPresent(Detail.self, forKey: .detail)) ?? .init()
        tier = try c.decode(String.self, forKey: .tier)
        // Missing means not offered: never show Always or Deny and stop by default.
        always = try c.decodeIfPresent(Bool.self, forKey: .always) ?? false
        stoppable = try c.decodeIfPresent(Bool.self, forKey: .stoppable) ?? false
        verdict = try? c.decodeIfPresent(Verdict.self, forKey: .verdict)
        judging = try c.decodeIfPresent(Bool.self, forKey: .judging)
        verdictError = try c.decodeIfPresent(String.self, forKey: .verdictError)
        createdAt = try c.decode(InventoryTime.self, forKey: .createdAt)
        expiresAt = try c.decode(InventoryTime.self, forKey: .expiresAt)
    }

    /// The answers this item offers. Always and Deny and stop appear only when the item says so.
    var answers: [ApprovalAnswer] {
        [.once] + (always ? [.always] : []) + [.deny] + (stoppable ? [.stop] : [])
    }

    /// Ids go to the CLI as an argument, so one that could read as a flag is not answered.
    var answerable: Bool {
        !id.isEmpty && !id.hasPrefix("-") && id.unicodeScalars.allSatisfy { !CharacterSet.whitespacesAndNewlines.contains($0) && !CharacterSet.controlCharacters.contains($0) }
    }

    var kindLabel: String {
        switch kind {
        case "sudo": "sudo"
        case "guest-tool": "Guest tool call"
        case "guest-message": "Guest message"
        case "capture": "Capture"
        case "owner-tool": "Tool call"
        default: kind
        }
    }

    var agentLabel: String {
        let agent = agentName ?? agentId.map { "Agent \($0.prefix(8))" }
        let who = requester.name + (requester.where.map { " · \($0)" } ?? "")
        return [agent, who].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
    }

    var detailText: String {
        switch kind {
        case "sudo":
            return (detail.command ?? "Command not reported") + (detail.cwd.map { "  (in \($0))" } ?? "")
        case "guest-tool", "owner-tool":
            let arguments = detail.arguments ?? detail.summary
            return [detail.tool ?? "Tool not reported", arguments].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
        case "capture":
            var what = [detail.what, detail.mode].compactMap { $0 }.joined(separator: " ")
            if let seconds = detail.seconds { what += " · \(seconds.formatted()) s" }
            if detail.system == true { what += " · system audio" }
            if detail.microphone == true { what += " · microphone" }
            if let program = detail.program { what += " · by \(program)" }
            return what.isEmpty ? "Capture details not reported" : what
        case "guest-message":
            let count = detail.attachments?.count ?? 0
            return "Message text is shown in SLICC, not here" + (count > 0 ? " · \(count) attachments" : "")
        default:
            return detail.summary ?? detail.command ?? detail.tool ?? "Details not shown"
        }
    }

    var verdictText: String {
        if let verdict, verdict.level != nil || verdict.reason != nil {
            return ["Judge" + (verdict.level.map { ": level \($0)" } ?? ""), verdict.reason].compactMap { $0 }.joined(separator: " · ")
        }
        if judging == true { return "Judge checking…" }
        if let verdictError { return "No verdict: \(verdictError)" }
        return "No verdict"
    }

    func timeLeft(at now: Date) -> String {
        guard let expires = expiresAt.date else { return "Expiry not reported" }
        let seconds = Int(expires.timeIntervalSince(now).rounded(.down))
        guard seconds > 0 else { return "Expired" }
        return String(format: "%d:%02d left", seconds / 60, seconds % 60)
    }
}

enum ApprovalAnswer: String, CaseIterable, Sendable {
    case once, always, deny, stop
    var title: String {
        switch self {
        case .once: "Allow once"
        case .always: "Always"
        case .deny: "Deny"
        case .stop: "Deny and stop"
        }
    }
}

/// In-memory approvals for one live connection. Each snapshot replaces the list.
struct ApprovalQueue {
    var items: [ApprovalItem] = []
    var received = false
    var active = false
    var message: String?
    /// Items with a decide in flight, or answered and waiting to leave the snapshot.
    var deciding: Set<String> = []
    var answered: Set<String> = []
    /// The CLI's sentence for a refused answer, by item id.
    var refusals: [String: String] = [:]
    /// Items a notification was already posted for.
    var notified: Set<String> = []

    /// Applies a CLI event. Returns items that are new since the last snapshot.
    @discardableResult
    mutating func apply(_ event: CLIEvent) -> [ApprovalItem] {
        guard event.schema == 1 else { return [] }
        switch event.kind {
        case "approvals":
            guard let items = event.approvals, Set(items.map(\.id)).count == items.count else {
                active = false; message = "SLICC returned incompatible approvals."; return []
            }
            let ids = Set(items.map(\.id))
            let fresh = items.filter { !notified.contains($0.id) }
            self.items = items; received = true; active = true; message = nil
            deciding.formIntersection(ids); answered.formIntersection(ids)
            refusals = refusals.filter { ids.contains($0.key) }
            notified = notified.intersection(ids).union(fresh.map(\.id))
            return fresh
        case "reconnecting": active = false; message = "Reconnecting to approvals…"
        case "error": active = false; message = event.message ?? "Approvals are unavailable."
        default: break
        }
        return []
    }
}
