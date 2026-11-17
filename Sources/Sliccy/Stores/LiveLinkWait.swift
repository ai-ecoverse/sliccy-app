import Foundation

/// Explains a local launch that reached the browser but never linked, instead of
/// leaving it at "Connecting" with no cause. Nothing here stops the CLI process:
/// the user decides whether to close duplicate tabs or retry.
extension WorkspaceStore {
    static let statusLineCount = 3

    /// Records one redacted stderr status line from the session's own CLI process.
    /// It may replace a message derived from an earlier status line, never one
    /// reported through the JSON contract.
    func applyStatus(_ line: String, to id: UUID) {
        let line = redacted(line, id: id)
        var lines = cliStatus[id] ?? []
        lines.append(line)
        if lines.count > Self.statusLineCount { lines.removeFirst(lines.count - Self.statusLineCount) }
        cliStatus[id] = lines
        guard let session = session(id), session.isLive,
              session.connection == .connecting || session.connection == .reconnecting else { return }
        if linkWaiting.contains(id) {
            let message = linkWaitMessage(id)
            update(id) { $0.connectionMessage = message }
            return
        }
        guard session.connectionMessage == nil || session.connectionMessage == statusMessages[id] else { return }
        let message = "SLICC: " + line
        statusMessages[id] = message
        update(id) { $0.connectionMessage = message }
    }

    /// Starts the stall timer once seven's browser is reported. Later browser
    /// events in the same launch keep the original deadline.
    func armLinkWait(_ id: UUID) {
        guard session(id)?.localBrowserProfile != nil, session(id)?.connection != .connected,
              linkWaitTasks[id] == nil, !linkWaiting.contains(id), let token = liveTokens[id] else { return }
        let delay = linkStallDelay
        linkWaitTasks[id] = Task { [weak self] in
            do { try await Task.sleep(for: delay) } catch { return }
            guard let self, self.liveTokens[id] == token else { return }
            self.linkWaitTasks[id] = nil
            guard let connection = self.session(id)?.connection,
                  connection == .connecting || connection == .reconnecting else { return }
            self.linkWaiting.insert(id)
            let message = self.linkWaitMessage(id)
            self.update(id) { $0.connectionMessage = message }
            self.notice(message, id: id)
            self.save()
        }
    }

    /// A newer CLI's explicit reason for waiting. Gated on `capabilities --json`.
    func applyLinkWait(_ event: CLIEvent, to id: UUID) {
        guard linkWaitSupported.contains(id), session(id)?.localBrowserProfile != nil,
              session(id)?.connection != .connected else { return }
        linkWaitReasons[id] = redacted(Self.linkWaitReason(event), id: id)
        if linkWaiting.contains(id) {
            let message = linkWaitMessage(id)
            update(id) { $0.connectionMessage = message }
        } else {
            // The CLI already debounces this event (5–15 s), so show its reason now.
            // The stall advice still waits for the app's own deadline.
            let message = "SLICC: " + Self.sentence(linkWaitReasons[id] ?? "")
            if session(id)?.connectionMessage == nil || session(id)?.connectionMessage == statusMessages[id] {
                statusMessages[id] = message
                update(id) { $0.connectionMessage = message }
            }
            armLinkWait(id)
        }
    }

    func clearLinkWait(_ id: UUID) {
        linkWaitTasks.removeValue(forKey: id)?.cancel()
        linkWaiting.remove(id)
        linkWaitReasons[id] = nil
        statusMessages[id] = nil
    }

    func linkWaitMessage(_ id: UUID) -> String {
        let browser = session(id)?.localBrowserChoice.name ?? "the browser"
        var message = "SLICC is open in \(browser) but hasn't linked. Close duplicate SLICC tabs, then choose Retry Connection."
        if let reason = linkWaitReasons[id] { message += " The CLI reports: " + Self.sentence(reason) }
        else if let status = cliStatus[id]?.last { message += " Last CLI status: " + Self.sentence(status) }
        return message
    }

    static func linkWaitReason(_ event: CLIEvent) -> String {
        var reason: String
        if let message = event.message?.trimmingCharacters(in: .whitespacesAndNewlines), !message.isEmpty {
            reason = message
        } else {
            switch event.reason {
            case "no-ready-seven": reason = "no SLICC tab is ready to link"
            case "no-seven-tab": reason = "no SLICC tab is open"
            case let code?: reason = code
            case nil: reason = "waiting for a SLICC tab"
            }
            if let count = event.candidates, count > 0 {
                reason += count == 1 ? " (1 SLICC tab open)" : " (\(count) SLICC tabs open)"
            }
        }
        return String(reason.prefix(CLIStatusLines.lineLimit))
    }

    static func sentence(_ text: String) -> String {
        guard let last = text.last, !".!?…".contains(last) else { return text }
        return text + "."
    }
}
