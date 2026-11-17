import Foundation

/// Explains a local launch that reached the browser but never linked, instead of
/// leaving it at "Connecting" with no cause. Nothing here stops the CLI process:
/// the user decides whether to close duplicate tabs or retry.
///
/// Message precedence: text the app derives here (stderr status, the CLI's waiting
/// reason, stall advice) only replaces an empty connection message or one it derived
/// itself. A message from the JSON contract, such as an `error`, stays visible until
/// the contract clears it; the stall is still shown by the status label and a notice.
extension WorkspaceStore {
    static let statusLineCount = CLIStatusBuffer.keep

    /// Moves pending status lines from the session's own CLI into the store.
    func drainStatus(_ id: UUID) {
        for line in liveProcesses[id]?.status?.drain() ?? [] { applyStatus(line, to: id) }
    }

    /// Records one redacted stderr status line from the session's own CLI process.
    func applyStatus(_ line: String, to id: UUID) {
        let line = redacted(line, id: id)
        var lines = cliStatus[id] ?? []
        lines.append(line)
        if lines.count > Self.statusLineCount { lines.removeFirst(lines.count - Self.statusLineCount) }
        cliStatus[id] = lines
        guard let session = session(id), session.isLive,
              session.connection == .connecting || session.connection == .reconnecting else { return }
        showDerivedMessage(linkWaiting.contains(id) ? linkWaitMessage(id) : "SLICC: " + line, id: id)
    }

    /// Shows app-derived text unless the connection message came from the JSON contract.
    @discardableResult
    func showDerivedMessage(_ message: String, id: UUID) -> Bool {
        guard let session = session(id) else { return false }
        guard session.connectionMessage == nil || session.connectionMessage == statusMessages[id] else { return false }
        statusMessages[id] = message
        update(id) { $0.connectionMessage = message }
        return true
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
            self.showDerivedMessage(self.linkWaitMessage(id), id: id)
            // The saved notice carries only contract text, never stderr.
            self.notice(self.linkWaitMessage(id, status: false), id: id)
            self.save()
        }
    }

    /// A newer CLI's explicit reason for waiting. Gated on `capabilities --json`.
    func applyLinkWait(_ event: CLIEvent, to id: UUID) {
        guard linkWaitSupported.contains(id), session(id)?.localBrowserProfile != nil,
              session(id)?.connection != .connected else { return }
        linkWaitReasons[id] = redacted(Self.linkWaitReason(event), id: id)
        linkWaitCodes[id] = event.reason
        if linkWaiting.contains(id) {
            showDerivedMessage(linkWaitMessage(id), id: id)
        } else {
            // The CLI already debounces this event (5–15 s), so show its reason now.
            // The stall advice still waits for the app's own deadline.
            showDerivedMessage("SLICC: " + Self.sentence(linkWaitReasons[id] ?? ""), id: id)
            armLinkWait(id)
        }
    }

    func clearLinkWait(_ id: UUID) {
        linkWaitTasks.removeValue(forKey: id)?.cancel()
        linkWaiting.remove(id)
        linkWaitReasons[id] = nil
        linkWaitCodes[id] = nil
        statusMessages[id] = nil
    }

    func linkWaitMessage(_ id: UUID, status: Bool = true) -> String {
        let browser = session(id)?.localBrowserChoice.name ?? "the browser"
        var message = linkWaitCodes[id] == "no-seven-tab"
            ? "\(browser) is open but has no SLICC tab to link. Open SLICC in that browser or choose Retry Connection."
            : "SLICC is open in \(browser) but hasn't linked. Close duplicate SLICC tabs, then choose Retry Connection."
        if let reason = linkWaitReasons[id] { message += " The CLI reports: " + Self.sentence(reason) }
        else if status, let line = cliStatus[id]?.last { message += " Last CLI status: " + Self.sentence(line) }
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
