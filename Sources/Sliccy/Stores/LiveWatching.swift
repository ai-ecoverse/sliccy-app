import Foundation

extension WorkspaceStore {
    func startWatch(_ id: UUID) {
        guard watchSupported.contains(id), watchProcesses[id] == nil,
              session(id)?.connection == .connected,
              let join = joinCredentials[id], let executable = liveExecutables[id] else { return }
        let token = UUID()
        watchTokens[id] = token
        let child = CLIProcess()
        watchProcesses[id] = child
        let cursor = session(id)?.liveFeed?.cursor
        update(id) {
            if $0.liveFeed == nil { $0.liveFeed = .init() }
            $0.liveFeed?.state = .opening
            $0.liveFeed?.busy = nil
        }
        watchTasks[id] = Task { [weak self] in
            guard let self else { return }
            var replay = cursor
            do {
                var decoder = NDJSONDecoder()
                let stream = try child.start(executable: executable, invocation: .watch(join: join, since: cursor))
                for try await data in stream {
                    guard !Task.isCancelled, self.watchTokens[id] == token else { return }
                    for event in try decoder.append(data) { self.applyWatch(event, to: id, initialReplay: &replay) }
                }
                for event in try decoder.finish() { self.applyWatch(event, to: id, initialReplay: &replay) }
            } catch {
                guard !Task.isCancelled, self.watchTokens[id] == token else { return }
                let message = self.redacted(error.localizedDescription, id: id)
                self.update(id) { $0.liveFeed?.entries.append(.init(role: .notice, text: message)) }
            }
            guard self.watchTokens[id] == token else { return }
            self.watchProcesses.removeValue(forKey: id)?.terminate()
            self.watchTasks[id] = nil
            self.update(id) { $0.liveFeed?.state = .unavailable; $0.liveFeed?.busy = nil }
            self.save()
        }
    }

    func applyWatch(_ event: CLIEvent, to id: UUID, initialReplay: inout String?) {
        var event = event
        event.text = event.text.map { redacted($0, id: id) }
        event.delta = event.delta.map { redacted($0, id: id) }
        event.message = event.message.map { redacted($0, id: id) }
        event.summary = event.summary.map { redacted($0, id: id) }
        event.name = event.name.map { redacted($0, id: id) }
        update(id) { $0.liveFeed?.apply(event, initialReplay: &initialReplay) }
        if feedSave == nil {
            feedSave = Task { [weak self] in
                do { try await Task.sleep(for: .milliseconds(500)) } catch { return }
                guard let self else { return }
                self.feedSave = nil
                self.save()
            }
        }
    }

    func stopWatch(_ id: UUID) {
        watchTokens[id] = nil
        watchTasks.removeValue(forKey: id)?.cancel()
        watchProcesses.removeValue(forKey: id)?.terminate()
        update(id) { $0.liveFeed?.state = .stopped; $0.liveFeed?.busy = nil; $0.liveFeed?.retryDelay = nil }
    }
}
