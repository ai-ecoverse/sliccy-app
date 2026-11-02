import Foundation

enum FeedState: String, Codable {
    case stopped, opening, watching, reconnecting, unavailable, unsupported
    var title: String {
        switch self {
        case .stopped: "Not watching"
        case .opening: "Opening live feed…"
        case .watching: "Live feed"
        case .reconnecting: "Reconnecting feed…"
        case .unavailable: "Feed unavailable"
        case .unsupported: "CLI update required"
        }
    }
}

/// Separate from the prompt's response stream: each has its own ordering and cursor.
struct LiveFeed: Codable, Equatable {
    var entries: [ActivityEntry] = []
    var cursor: String?
    var state: FeedState = .stopped
    var busy: Bool?
    var retryDelay: Double?

    mutating func apply(_ event: CLIEvent, initialReplay: inout String?) {
        switch event.kind {
        case "opened":
            state = .watching; retryDelay = nil; busy = event.busy
            // `head` is the server's current head, not the last event we've consumed.
            if event.gap == true {
                cursor = nil; initialReplay = nil
                entries.append(.init(role: .notice, text: "Some activity was missed. Seven no longer holds the saved position; this feed continues with new events."))
            }
        case "reconnecting":
            state = .reconnecting; busy = nil; retryDelay = event.wait?.milliseconds
        case "busy": busy = event.busy
        case "run":
            if event.state == "start" { busy = true }
            if event.state == "end" { busy = false }
        case "text":
            guard let source = event.id else { return }
            let text = event.delta ?? event.text ?? ""
            if let index = entries.firstIndex(where: { $0.sourceID == source }) {
                if initialReplay == source {
                    // On a NEW process, --since replays this entry's entire text once.
                    // On reconnects INSIDE that process the CLI already trims replay.
                    entries[index].text = text
                } else { entries[index].text += text }
            } else {
                entries.append(.init(role: .assistant, text: text, sourceID: source))
            }
            initialReplay = nil
            cursor = source
        case "user", "tool", "tool-result", "notice", "error":
            guard let source = event.id else {
                if event.kind == "error" { entries.append(.init(role: .notice, text: event.message ?? "Feed error")) }
                return
            }
            let role: MessageRole = event.kind == "user" ? .user : ["tool", "tool-result"].contains(event.kind) ? .tool : .notice
            let text = event.text ?? event.message ?? event.summary ?? event.name ?? "Activity"
            if !entries.contains(where: { $0.sourceID == source }) {
                entries.append(.init(role: role, text: text, sourceID: source))
            }
            cursor = source; initialReplay = nil
        default: break
        }
    }
}
