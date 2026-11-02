import Foundation

extension WorkspaceStore {
    func startInventory(_ id: UUID) {
        guard session(id)?.isLive == true, session(id)?.connection == .connected,
              inventoryProcesses[id] == nil, let join = joinCredentials[id], let executable = liveExecutables[id] else { return }
        guard inventorySupported.contains(id) else {
            inventories[id] = .init(message: "This CLI does not report agents. Select slicc 1.57 or later.")
            return
        }
        let token = UUID()
        inventoryTokens[id] = token
        var state = inventories[id] ?? .init()
        state.active = false; state.message = "Waiting for seven’s agent inventory…"
        inventories[id] = state
        let child = CLIProcess()
        inventoryProcesses[id] = child
        inventoryTasks[id] = Task { [weak self] in
            guard let self else { return }
            do {
                var decoder = NDJSONDecoder()
                let stream = try child.start(executable: executable, invocation: .agents(join: join))
                for try await chunk in stream {
                    guard !Task.isCancelled, self.inventoryTokens[id] == token else { return }
                    for event in try decoder.append(chunk) { self.applyInventory(event, to: id) }
                }
                for event in try decoder.finish() { self.applyInventory(event, to: id) }
            } catch {
                guard !Task.isCancelled, self.inventoryTokens[id] == token else { return }
                let message: String
                if case CLIError.exit(1) = error {
                    message = "Agent inventory is unavailable. Seven may need an update, or its agent may not be running."
                } else if case CLIError.exit(3) = error {
                    message = "Allow agent access for this device in seven’s Linked devices."
                } else { message = self.redacted(error.localizedDescription, id: id) }
                self.inventories[id]?.message = message
            }
            guard self.inventoryTokens[id] == token else { return }
            self.inventories[id]?.active = false
            self.inventoryProcesses.removeValue(forKey: id)?.terminate()
            self.inventoryTasks[id] = nil
        }
    }

    func applyInventory(_ event: CLIEvent, to id: UUID) {
        var event = event
        event.message = event.message.map { redacted($0, id: id) }
        var inventory = inventories[id] ?? .init()
        inventory.apply(event)
        inventories[id] = inventory
    }

    func stopInventory(_ id: UUID) {
        inventoryTokens[id] = nil
        inventoryTasks.removeValue(forKey: id)?.cancel()
        inventoryProcesses.removeValue(forKey: id)?.terminate()
        inventories[id]?.active = false
        inventories[id]?.message = "Agent inventory disconnected."
    }
}
