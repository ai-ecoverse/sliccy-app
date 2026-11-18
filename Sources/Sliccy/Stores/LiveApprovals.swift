import Foundation

extension WorkspaceStore {
    func approvalsInvocation(_ id: UUID) -> CLIInvocation? {
        if session(id)?.localBrowserProfile != nil { return localBrowserEndpoints[id].map { .approvals(cdp: $0) } }
        return joinCredentials[id].map { .approvals(join: $0) }
    }

    func decideInvocation(_ id: UUID, item: String, answer: ApprovalAnswer) -> CLIInvocation? {
        if session(id)?.localBrowserProfile != nil { return localBrowserEndpoints[id].map { .decide(cdp: $0, id: item, answer: answer) } }
        return joinCredentials[id].map { .decide(join: $0, id: item, answer: answer) }
    }

    /// A separate `approvals --json --watch` child, like the agent inventory. Data stays in memory.
    func startApprovals(_ id: UUID) {
        guard session(id)?.isLive == true, session(id)?.connection == .connected,
              approvalProcesses[id] == nil, let invocation = approvalsInvocation(id), let executable = liveExecutables[id] else { return }
        guard approvalsSupported.contains(id) else {
            approvals[id] = .init(message: "This CLI does not answer approvals. Update slicc to a release with approvals and decide.")
            return
        }
        let token = UUID()
        approvalTokens[id] = token
        var queue = approvals[id] ?? .init()
        queue.active = false; queue.message = "Waiting for SLICC’s approvals…"
        approvals[id] = queue
        let child = CLIProcess()
        approvalProcesses[id] = child
        approvalTasks[id] = Task { [weak self] in
            guard let self else { return }
            do {
                var decoder = NDJSONDecoder()
                let stream = try child.start(executable: executable, invocation: invocation)
                for try await chunk in stream {
                    guard !Task.isCancelled, self.approvalTokens[id] == token else { return }
                    for event in try decoder.append(chunk) { self.applyApprovals(event, to: id) }
                }
                guard !Task.isCancelled, self.approvalTokens[id] == token else { return }
                for event in try decoder.finish() { self.applyApprovals(event, to: id) }
                if self.approvals[id]?.message == nil { self.approvals[id]?.message = "The approvals stream stopped." }
            } catch {
                guard !Task.isCancelled, self.approvalTokens[id] == token else { return }
                let message: String
                if case CLIError.exit(1) = error {
                    message = "Approvals are unavailable. The link may have failed, or SLICC may need an update to share approvals with linked devices."
                } else if case CLIError.exit(3) = error {
                    message = "Allow agent access for this device in SLICC’s Linked devices to see and answer approvals."
                } else if error is DecodingError {
                    message = "SLICC returned incompatible approvals."
                } else { message = self.redacted(error.localizedDescription, id: id) }
                self.approvals[id]?.message = message
            }
            guard self.approvalTokens[id] == token else { return }
            self.approvals[id]?.active = false
            self.approvalProcesses.removeValue(forKey: id)?.terminate()
            self.approvalTasks[id] = nil
            self.withdrawApprovalNotifications(id)
            self.approvals[id]?.notified = []
        }
    }

    func applyApprovals(_ event: CLIEvent, to id: UUID) {
        var event = event
        event.message = event.message.map { redacted($0, id: id) }
        var queue = approvals[id] ?? .init()
        let before = Set(queue.items.map(\.id))
        let fresh = queue.apply(event)
        approvals[id] = queue
        let gone = before.subtracting(queue.items.map(\.id))
        if !gone.isEmpty { approvalNotifier?.withdraw(Array(gone), session: id) }
        let name = session(id)?.name ?? "SLICC"
        for item in fresh where item.answerable { approvalNotifier?.post(item, session: id, title: name) }
    }

    func stopApprovals(_ id: UUID) {
        approvalTokens[id] = nil
        approvalTasks.removeValue(forKey: id)?.cancel()
        approvalProcesses.removeValue(forKey: id)?.terminate()
        for key in decideProcesses.keys where key.session == id { decideProcesses.removeValue(forKey: key)?.terminate() }
        withdrawApprovalNotifications(id)
        guard approvals[id] != nil else { return }
        // Their notifications are withdrawn, so items still pending after a reconnect notify again.
        approvals[id]?.notified = []
        approvals[id]?.active = false
        approvals[id]?.deciding = []
        approvals[id]?.message = "Approvals disconnected."
    }

    func withdrawApprovalNotifications(_ id: UUID) {
        guard let ids = approvals[id]?.items.map(\.id), !ids.isEmpty else { return }
        approvalNotifier?.withdraw(ids, session: id)
    }

    /// Runs `slicc decide <id> <answer>` and waits for it. Exit 1 shows the CLI's sentence.
    func decide(_ item: String, answer: ApprovalAnswer, for id: UUID) {
        guard var queue = approvals[id] else { return }
        guard queue.active else {
            queue.message = "Approvals aren’t live. Answer in SLICC, or wait for Sliccy to reconnect."
            approvals[id] = queue
            return
        }
        guard let listed = queue.items.first(where: { $0.id == item }) else {
            queue.message = "That request is no longer pending."
            approvals[id] = queue
            return
        }
        guard listed.answerable, listed.answers.contains(answer), !queue.deciding.contains(item), !queue.answered.contains(item),
              let executable = liveExecutables[id], let invocation = decideInvocation(id, item: item, answer: answer) else { return }
        queue.deciding.insert(item)
        queue.refusals[item] = nil
        approvals[id] = queue
        let key = DecideKey(session: id, item: item)
        let child = CLIProcess()
        decideProcesses[key] = child
        Task { [weak self] in
            // `decide --json` prints `decided` or an `error` line with the agent's sentence and a code.
            // stderr is not read.
            var output = Data()
            var events: [CLIEvent] = []
            var refusal: String?
            do {
                let stream = try child.start(executable: executable, invocation: invocation, deadline: .seconds(65))
                for try await chunk in stream { output.append(chunk); guard output.count <= 64 * 1024 else { throw CLIError.oversized } }
                events = Self.decideEvents(output)
                if !events.contains(where: { $0.kind == "decided" }) { refusal = "SLICC didn’t confirm this answer." }
            } catch CLIError.exit(3) {
                refusal = "Allow agent access for this device in SLICC’s Linked devices to answer approvals."
            } catch CLIError.exit(1) {
                events = Self.decideEvents(output)
                let sentence = events.last { $0.kind == "error" }?.message?.trimmingCharacters(in: .whitespacesAndNewlines)
                refusal = sentence.flatMap { $0.isEmpty ? nil : self?.redacted($0, id: id) } ?? "The answer wasn’t delivered. Check the connection, or answer in SLICC."
            } catch {
                refusal = self?.redacted(error.localizedDescription, id: id) ?? error.localizedDescription
            }
            child.terminate()
            guard let self, self.decideProcesses[key] === child else { return }
            self.decideProcesses[key] = nil
            self.approvals[id]?.deciding.remove(item)
            if let refusal { self.approvals[id]?.refusals[item] = refusal }
            else { self.approvals[id]?.answered.insert(item) }
        }
    }
}

extension WorkspaceStore {
    /// decide's stdout lines, skipping any that aren't JSON, including a last line without a newline.
    nonisolated static func decideEvents(_ output: Data) -> [CLIEvent] {
        output.split(separator: 10, omittingEmptySubsequences: true).compactMap { try? JSONDecoder().decode(CLIEvent.self, from: Data($0)) }
    }
}

struct DecideKey: Hashable { var session: UUID; var item: String }
