import AppKit

extension WorkspaceStore {
    var linkSessions: [Session] { sessions.filter { $0.isLive && $0.localBrowserProfile != nil } }

    /// Attached browsers take priority. Preference orders ties and the cold-start fallback.
    var webLinkDestination: UUID? {
        var candidates = linkSessions
        if let preferred = linkSessionID, let index = candidates.firstIndex(where: { $0.id == preferred }) {
            candidates.insert(candidates.remove(at: index), at: 0)
        }
        return candidates.first(where: { localBrowserEndpoints[$0.id] != nil && $0.connection == .connected })?.id
            ?? candidates.first?.id
    }

    /// Called only for an incoming OS web link, not at ordinary app startup.
    func openWebLink(_ url: URL) async throws {
        guard !isDemo, IncomingWebLinks.accepts(url) else { throw BrowserTabClient.Failure.invalid }
        guard let id = webLinkDestination else {
            startNew()
            throw BrowserTabClient.Failure.missing
        }
        if session(id)?.connection == .disconnected { reconnect(id) }
        requestedSelection = id
        let deadline = ContinuousClock.now.advanced(by: .seconds(45))
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            guard let target = session(id) else { throw BrowserTabClient.Failure.missing }
            if let endpoint = localBrowserEndpoints[id], target.connection == .connected {
                try await BrowserTabClient.open(url, endpoint: endpoint)
                NSRunningApplication.runningApplications(withBundleIdentifier: target.localBrowserChoice.bundleID).first?.activate()
                return
            }
            if target.connection == .disconnected { throw BrowserTabClient.Failure.missing }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw BrowserTabClient.Failure.missing
    }
}
