import Foundation
import CryptoKit

extension WorkspaceStore {
    func checkCLI() async {
        checkingCLI = true
        let executable = cliExecutable
        defer { checkingCLI = false }
        do {
            let version = try await CLIClient.capabilities(at: executable).version
            if cliExecutable == executable { cliVersion = version }
        }
        catch { cliVersion = nil; errorMessage = error.localizedDescription }
    }

    @discardableResult
    func createLive(name: String, join: String) -> UUID {
        let session = Session(name: sessionName(for: name), device: "Remote SLICC", kind: .remote,
                              profile: "Remote", connection: .disconnected, access: .init(browser: nil, network: false), usesLiveRuntime: true)
        sessions.append(session)
        bindCredential(join, to: session.id)
        requestedSelection = session.id
        reconnect(session.id)
        return session.id
    }

    @discardableResult
    func createLocalBrowser(name: String, browser: LocalBrowserChoice = .chrome, profile: String? = nil) -> UUID {
        let profile = profile ?? browser.defaultProfile
        // Reuse the selected profile rather than opening overlapping app-owned links.
        if let existing = sessions.first(where: { $0.isLive && $0.localBrowserProfile == profile }) {
            guard existing.localBrowserChoice == browser else {
                errorMessage = "This profile is already assigned to \(existing.localBrowserChoice.name). Choose another profile."
                return existing.id
            }
            requestedSelection = existing.id
            if existing.connection == .disconnected { reconnect(existing.id) }
            return existing.id
        }
        let session = Session(name: sessionName(for: name), device: "This Mac", kind: .browser,
                              profile: profile == browser.defaultProfile ? "SLICC \(browser.name) profile" : profile, connection: .disconnected,
                              access: .init(browser: nil, network: false), usesLiveRuntime: true,
                              localBrowserProfile: profile, localBrowser: browser, localAccess: .init())
        sessions.append(session)
        requestedSelection = session.id
        reconnect(session.id)
        return session.id
    }

    func inventoryInvocation(_ id: UUID) -> CLIInvocation? {
        if session(id)?.localBrowserProfile != nil {
            return localBrowserEndpoints[id].map { .agents(cdp: $0) }
        }
        return joinCredentials[id].map { .agents(join: $0) }
    }

    func bindCredential(_ join: String, to id: UUID) {
        let credential = join.trimmingCharacters(in: .whitespacesAndNewlines)
        let identity = SHA256.hash(data: Data(credential.utf8)).map { String(format: "%02x", $0) }.joined()
        update(id) { session in
            if let previous = session.watchIdentity, previous != identity {
                // Keep old visible activity, but never reuse its cursor or ids for a different URL.
                session.liveFeed?.cursor = nil
                if var feed = session.liveFeed {
                    for index in feed.entries.indices { feed.entries[index].sourceID = nil }
                    feed.entries.append(.init(role: .notice, text: "The join URL changed. Live activity will start from the next event."))
                    session.liveFeed = feed
                }
            }
            session.watchIdentity = identity
        }
        joinCredentials[id] = credential
    }

    func supplyCredential(_ join: String, for id: UUID) {
        bindCredential(join, to: id)
        credentialSession = nil
        reconnect(id)
    }

    func connectLive(_ id: UUID) {
        let profile = session(id)?.localBrowserProfile
        let join = joinCredentials[id]
        guard profile != nil || join != nil else { return }
        localBrowserEndpoints[id] = nil
        let token = UUID()
        liveTokens[id] = token
        let executable = cliExecutable
        credentialAccess[id] = .init()
        update(id) { $0.connection = .connecting; $0.connectionMessage = nil }
        connections[id] = Task { [weak self] in
            guard let self else { return }
            do {
                let deadline = ContinuousClock.now.advanced(by: .seconds(8))
                while self.retiringProcesses[id]?.runningPID != nil, ContinuousClock.now < deadline {
                    try await Task.sleep(for: .milliseconds(50))
                }
                guard self.retiringProcesses[id]?.runningPID == nil else { throw CLIControlError.timeout }
                self.retiringProcesses[id] = nil
                try Task.checkCancellation()
                let capabilities = try await CLIClient.capabilities(at: executable)
                guard !Task.isCancelled, self.liveTokens[id] == token else { return }
                if profile != nil, !capabilities.supportsLocalBrowser { throw CLIError.incompatible }
                self.cliVersion = capabilities.version
                if capabilities.commands["agents"]?.json == "events" { self.inventorySupported.insert(id) }
                else { self.inventorySupported.remove(id) }
                if self.credentialOffers.contains(id), !capabilities.supportsCredentialLeases { throw CLIError.incompatible }
                if capabilities.supportsCredentialLeases { self.leaseSupported.insert(id) }
                else { self.leaseSupported.remove(id) }
                if profile == nil, capabilities.supportsResumableWatch {
                    self.watchSupported.insert(id)
                } else {
                    self.watchSupported.remove(id)
                    self.update(id) {
                        if $0.liveFeed == nil { $0.liveFeed = .init() }
                        $0.liveFeed?.state = .unsupported
                    }
                }
                let child = CLIProcess()
                self.liveProcesses[id] = child
                self.liveExecutables[id] = executable
                var decoder = NDJSONDecoder()
                let invocation: CLIInvocation
                if let profile {
                    invocation = .localBrowser(profile: profile, browser: self.session(id)?.localBrowserChoice ?? .chrome, access: self.session(id)?.localAccess ?? .init(), offerCredentials: self.credentialOffers.contains(id))
                } else if let join {
                    invocation = .follow(join: join, offerCredentials: self.credentialOffers.contains(id))
                } else { return }
                let stream = try child.start(executable: executable, invocation: invocation)
                for try await data in stream {
                    guard !Task.isCancelled, self.liveTokens[id] == token else { return }
                    for event in try decoder.append(data) { self.applyLifecycle(event, to: id) }
                }
                guard !Task.isCancelled, self.liveTokens[id] == token else { return }
                for event in try decoder.finish() { self.applyLifecycle(event, to: id) }
            } catch {
                guard !Task.isCancelled, self.liveTokens[id] == token else { return }
                let message = self.redacted(error.localizedDescription, id: id)
                self.update(id) { $0.connectionMessage = message }
                self.notice(message, id: id)
            }
            guard self.liveTokens[id] == token else { return }
            self.liveProcesses.removeValue(forKey: id)?.terminate()
            self.connections[id] = nil
            self.clearLiveConnection(id)
            self.save()
        }
    }

    /// An error reports an offer failure. Only `closed` (or process exit) ends the process.
    func applyLifecycle(_ event: CLIEvent, to id: UUID) {
        guard event.schema == nil || event.schema == 1 else { return }
        switch event.kind {
        case "attached", "launched":
            // Protocol role is named "seven" by the released CLI. It is not UI branding.
            if session(id)?.localBrowserProfile != nil, event.role == "seven",
               let endpoint = event.cdp, let url = URL(string: endpoint),
               url.scheme == "http", ["127.0.0.1", "localhost", "[::1]"].contains(url.host ?? ""),
               url.user == nil, url.password == nil, let port = url.port, (1...65535).contains(port) {
                localBrowserEndpoints[id] = endpoint
                if let browser = event.browser, let name = event.name {
                    attachedBrowsers[id] = .init(id: browser, name: name, role: event.role!, owned: event.launched == true)
                }
                startInventory(id)
            }
        case "connecting":
            disableCua(id)
            update(id) { $0.connection = .connecting }
        case "reconnecting", "link-lost":
            disableCua(id)
            stopInventory(id)
            let details = [event.reason, event.message].compactMap { $0 }.filter { !$0.isEmpty }
            let explanation = details.isEmpty ? "" : " " + redacted(details.joined(separator: ": "), id: id)
            let message = event.kind == "link-lost"
                ? "Connection lost.\(explanation) Waiting for SLICC to reconnect."
                : "Reconnecting to SLICC.\(explanation)"
            update(id) {
                $0.connection = .reconnecting; $0.effectiveResources = nil; $0.access = .init(browser: nil, network: false)
                // Preserve the reported failure when a later retry event has no details.
                if event.kind == "link-lost" || !details.isEmpty || $0.connectionMessage == nil { $0.connectionMessage = message }
            }
            if event.kind == "link-lost" { notice(message, id: id) }
        case "linked":
            let local = session(id)?.localBrowserProfile != nil
            let resources = event.resources ?? (local ? (session(id)?.localAccess ?? .init()).resources(from: event, browser: attachedBrowsers[id]) : nil)
            if local, let tab = event.tab, BrowserTabClient.isSLICCTab(tab) { localTabURLs[id] = tab }
            update(id) {
                $0.connection = .connected
                $0.connectionMessage = nil
                $0.effectiveResources = resources
                $0.access = resources?.access ?? .init(browser: nil, network: false)
            }
            if session(id)?.access.network != true { disableCua(id) }
            notice("Connected to SLICC. Access shows the resources reported by the CLI.", id: id)
            // Launcher UI does not subscribe to agent transcripts.
            refreshCredentials(id)
            startInventory(id)
        case "credential":
            var access = credentialAccess[id] ?? .init()
            access.apply(event)
            credentialAccess[id] = access
        case "error":
            let message = redacted((event.message ?? "Connection error") + (event.retryable == true ? " Waiting for another offer." : ""), id: id)
            update(id) { $0.connectionMessage = message }
            notice(message, id: id)
        case "closed": clearLiveConnection(id)
        default: break
        }
        save()
    }

    func clearLiveConnection(_ id: UUID) {
        disableCua(id)
        stopInventory(id)
        localBrowserEndpoints[id] = nil
        attachedBrowsers[id] = nil
        localTabURLs[id] = nil
        credentialTasks.removeValue(forKey: id)?.cancel()
        if var credentials = credentialAccess[id] {
            credentials.ops = []; credentials.sealing = nil; credentials.complete = false; credentials.busy = false
            credentials.message = "This process ended. Its credentials may still be valid; use the Mac broker to revoke any remaining leases."
            credentialAccess[id] = credentials
        }
        stopWatch(id)
        abortProcesses.removeValue(forKey: id)?.terminate()
        aborting.remove(id)
        cancelStream(id)
        update(id) {
            $0.connection = .disconnected; $0.isWorking = false; $0.queuedPrompts = []
            $0.effectiveResources = nil; $0.access = .init(browser: nil, network: false)
        }
    }

    func disconnectLive(_ id: UUID) {
        configurationTasks.removeValue(forKey: id)?.cancel()
        reconfiguring.remove(id)
        credentialOffers.remove(id)
        leaseSupported.remove(id)
        liveTokens[id] = nil
        abortProcesses.removeValue(forKey: id)?.terminate()
        aborting.remove(id)
        connections.removeValue(forKey: id)?.cancel()
        // Local launches use --keep-browsers; follow never owns a browser.
        // SIGTERM ends our link while preserving Chrome, its profile and the agent.
        if let child = liveProcesses.removeValue(forKey: id) {
            child.terminate()
            retiringProcesses[id] = child
        }
        liveExecutables[id] = nil
        clearLiveConnection(id)
        notice("Disconnected. Any agent run continues in SLICC. Unsent follow-ups were cleared.", id: id)
        save()
    }

    func beginLivePrompt(_ prompt: String, id: UUID, steer: Bool) {
        guard let join = joinCredentials[id], let executable = liveExecutables[id] else { return }
        let generation = UUID()
        generations[id] = generation
        update(id) { $0.isWorking = true }
        let child = CLIProcess()
        promptProcesses[id] = child
        runs[id] = Task { [weak self] in
            guard let self else { return }
            var entries: [String: UUID] = [:]
            var sawEnd = false
            do {
                var decoder = NDJSONDecoder()
                let stream = try child.start(executable: executable, invocation: .prompt(join: join, text: prompt, steer: steer))
                for try await data in stream {
                    guard !Task.isCancelled, self.generations[id] == generation else { return }
                    for event in try decoder.append(data) {
                        self.applyAgent(event, to: id, entries: &entries)
                        if event.kind == "end" { sawEnd = true }
                    }
                }
                for event in try decoder.finish() {
                    self.applyAgent(event, to: id, entries: &entries)
                    if event.kind == "end" { sawEnd = true }
                }
                if !sawEnd { throw CLIError.exit(1) }
            } catch {
                guard !Task.isCancelled, self.generations[id] == generation else { return }
                self.notice(error.localizedDescription + " The agent may still be running in SLICC.", id: id)
                self.update(id) { $0.queuedPrompts = [] }
            }
            guard self.generations[id] == generation else { return }
            self.promptProcesses.removeValue(forKey: id)?.terminate()
            self.runs[id] = nil
            self.update(id) { $0.isWorking = false }
            if let next = self.session(id)?.queuedPrompts.first, self.session(id)?.connection == .connected {
                self.update(id) { $0.queuedPrompts.removeFirst() }
                self.beginLivePrompt(next, id: id, steer: false)
            }
            self.save()
        }
        save()
    }

    func applyAgent(_ event: CLIEvent, to id: UUID, entries: inout [String: UUID]) {
        switch event.kind {
        case "text":
            let key = event.id ?? "current"
            let text = redacted(event.delta ?? event.text ?? "", id: id)
            if let entry = entries[key] {
                update(id) { session in
                    if let index = session.entries.firstIndex(where: { $0.id == entry }) { session.entries[index].text += text }
                }
            } else {
                let entry = ActivityEntry(role: .assistant, text: text)
                entries[key] = entry.id
                update(id) { $0.entries.append(entry) }
            }
        case "tool", "tool-result":
            let text = redacted(event.summary ?? event.name ?? "Tool activity", id: id)
            update(id) { $0.entries.append(.init(role: .tool, text: text)) }
        case "notice", "error": notice(event.text ?? event.message ?? "Agent notice", id: id)
        case "end":
            if let reason = event.reason, reason != "stop" {
                notice(event.message ?? "Agent ended: \(reason)", id: id)
                update(id) { $0.queuedPrompts = [] }
            }
        default: break
        }
    }

    func abortLive(_ id: UUID) {
        guard !aborting.contains(id), let join = joinCredentials[id], let executable = liveExecutables[id], session(id)?.isWorking == true else { return }
        aborting.insert(id)
        update(id) { $0.queuedPrompts = [] }
        let generation = generations[id]
        let child = CLIProcess()
        abortProcesses[id] = child
        // Keep the prompt stream until abort is acknowledged; stopping a pipe is not abort.
        Task { [weak self] in
            defer {
                child.terminate()
                if self?.abortProcesses[id] === child {
                    self?.aborting.remove(id)
                    self?.abortProcesses[id] = nil
                }
            }
            do {
                let stream = try child.start(executable: executable, invocation: .abort(join: join), deadline: .seconds(65))
                for try await _ in stream { }
                guard let self, self.generations[id] == generation else { return }
                self.cancelStream(id)
                self.update(id) { $0.isWorking = false; $0.queuedPrompts = [] }
                self.notice("SLICC acknowledged Stop Agent.", id: id)
                self.save()
            } catch {
                if self?.abortProcesses[id] === child { self?.errorMessage = error.localizedDescription }
            }
        }
    }

    func notice(_ text: String, id: UUID) {
        let text = redacted(text, id: id)
        update(id) { $0.entries.append(.init(role: .notice, text: text)) }
    }
    func redacted(_ text: String, id: UUID) -> String {
        guard let secret = joinCredentials[id], !secret.isEmpty else { return text }
        return text.replacingOccurrences(of: secret, with: "<join URL>")
    }

    func shutdown() {
        for session in sessions where session.isLive { disconnectLive(session.id) }
        save()
    }
}
