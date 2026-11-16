import AppKit
import Foundation

extension WorkspaceStore {
    func setLocalEntitlement(_ entitlement: Entitlement, enabled: Bool, for id: UUID) {
        guard session(id)?.localBrowserProfile != nil, !reconfiguring.contains(id) else { return }
        if entitlement == .browser {
            if enabled { reconnect(id) } else { disconnectLive(id) }
            return
        }
        guard session(id)?.connection == .connected else { return }
        update(id) {
            var access = $0.localAccess ?? .init()
            switch entitlement {
            case .network: access.network = enabled
            case .shell: access.shell = enabled; if !enabled { access.sftp = false }
            case .sftp: access.sftp = enabled; if enabled { access.shell = true }
            case .browser: break
            }
            $0.localAccess = access
        }
        restartLocalConnection(id, offerCredentials: credentialOffers.contains(id))
    }

    func restartLocalConnection(_ id: UUID, offerCredentials: Bool) {
        guard session(id)?.localBrowserProfile != nil, !reconfiguring.contains(id) else { return }
        let previous = liveProcesses[id]
        disconnectLive(id)
        if offerCredentials { credentialOffers.insert(id) }
        reconfiguring.insert(id)
        update(id) { $0.connection = .connecting; $0.connectionMessage = "Applying access settings… Your browser stays open." }
        configurationTasks[id] = Task { [weak self] in
            let deadline = ContinuousClock.now.advanced(by: .seconds(8))
            // Never overlap old and new grants. If the old owned process won't exit,
            // report failure rather than silently launching another connection.
            while previous?.runningPID != nil, ContinuousClock.now < deadline {
                do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
            }
            guard let self, !Task.isCancelled else { return }
            self.configurationTasks[id] = nil
            self.reconfiguring.remove(id)
            guard previous?.runningPID == nil else {
                self.update(id) { $0.connection = .disconnected; $0.connectionMessage = "The previous CLI has not exited. Settings were not applied; quit that process before reconnecting." }
                self.save()
                return
            }
            self.connectLive(id)
        }
    }

    func showBrowser(_ id: UUID) {
        guard session(id)?.localBrowserProfile != nil, session(id)?.connection == .connected,
              let endpoint = localBrowserEndpoints[id], let tab = localTabURLs[id],
              !openingBrowser.contains(id) else { return }
        let generation = liveTokens[id]
        openingBrowser.insert(id)
        Task { [weak self] in
            defer { self?.openingBrowser.remove(id) }
            do {
                try await BrowserTabClient.activate(endpoint: endpoint, tabURL: tab)
                guard let self, self.liveTokens[id] == generation else { return }
                guard let browser = NSRunningApplication.runningApplications(withBundleIdentifier: self.session(id)?.localBrowserChoice.bundleID ?? LocalBrowserChoice.chrome.bundleID).first else {
                    throw BrowserTabClient.Failure.missing
                }
                browser.activate()
            } catch { self?.errorMessage = error.localizedDescription }
        }
    }
}
