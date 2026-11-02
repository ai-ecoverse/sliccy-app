import Foundation

extension WorkspaceStore {
    func refreshCredentials(_ id: UUID) {
        credentialOperation(id, operation: nil)
    }

    func setCredentialSealing(_ enabled: Bool, for id: UUID) {
        guard session(id)?.isLive == true, session(id)?.connection == .connected,
              credentialAccess[id]?.busy != true else { return }
        let operation = enabled ? "seal-on" : "seal-off"
        if credentialAccess[id]?.ops.contains(operation) == true {
            credentialOperation(id, operation: operation)
        } else if enabled, leaseSupported.contains(id), !credentialOffers.contains(id), credentialAccess[id]?.ops.contains("status") == true {
            // Explicit user switch: add the broker to a fresh follow process.
            // Default follow offers no credentials; no flags are inferred from metadata.
            disconnectLive(id)
            credentialOffers.insert(id)
            connectLive(id)
        }
    }

    func revokeCredential(_ leaseID: String, for id: UUID) {
        guard credentialAccess[id]?.leases.contains(where: { $0.leaseId == leaseID }) == true,
              credentialAccess[id]?.ops.contains("unseal") == true else { return }
        credentialOperation(id, operation: "unseal", leaseID: leaseID)
    }

    private func credentialOperation(_ id: UUID, operation: String?, leaseID: String? = nil) {
        guard session(id)?.isLive == true, let child = liveProcesses[id], let pid = child.runningPID,
              let generation = liveTokens[id], credentialAccess[id]?.busy != true else { return }
        var access = credentialAccess[id] ?? .init()
        access.busy = true
        access.message = operation == "unseal" ? "Waiting for the broker to revoke this lease…" : nil
        credentialAccess[id] = access
        credentialTasks[id] = Task { [weak self] in
            guard let self else { return }
            defer {
                if self.liveTokens[id] == generation, !Task.isCancelled {
                    self.credentialAccess[id]?.busy = false
                    self.credentialTasks[id] = nil
                }
            }
            do {
                let status = try await CLIControlClient.request(pid: pid, request: .init(op: "status"))
                guard !Task.isCancelled, self.liveTokens[id] == generation, child.runningPID == pid else { return }
                let ops = Set(status.ops ?? [])
                self.credentialAccess[id]?.ops = ops
                if let operation {
                    guard ops.contains(operation) else { throw CLIControlError.unavailable }
                    let reply = try await CLIControlClient.request(pid: pid, request: .init(op: operation, leaseId: leaseID))
                    guard !Task.isCancelled, self.liveTokens[id] == generation, child.runningPID == pid else { return }
                    guard reply.ok == true else { throw CLIControlError.invalid }
                    if operation == "unseal" {
                        guard reply.revoked == true else { throw CLIControlError.invalid }
                        if let leaseID { self.credentialAccess[id]?.released(leaseID, upstream: reply.upstream) }
                    } else {
                        guard let sealing = reply.sealing, sealing == (operation == "seal-on") else { throw CLIControlError.invalid }
                        self.credentialAccess[id]?.sealing = sealing
                        self.credentialAccess[id]?.message = sealing ? "New leases are allowed." : "New leases are blocked. Existing leases remain valid."
                    }
                    // Do not replace a confirmed revoke with the known stale listing race.
                    return
                }
                guard ops.contains("leases") else {
                    self.credentialAccess[id]?.sealing = false
                    self.credentialAccess[id]?.complete = false
                    return
                }
                let revision = self.credentialAccess[id]?.revision
                let snapshot = try await CLIControlClient.request(pid: pid, request: .init(op: "leases"))
                guard !Task.isCancelled, self.liveTokens[id] == generation, child.runningPID == pid else { return }
                guard let leases = snapshot.leases, let sealing = snapshot.sealing else { throw CLIControlError.invalid }
                if self.credentialAccess[id]?.revision == revision {
                    self.credentialAccess[id]?.replaceSnapshot(leases, sealing: sealing)
                } else {
                    self.credentialAccess[id]?.complete = false
                    self.credentialAccess[id]?.message = "Leases changed while refreshing. Refresh again for a complete list."
                }
            } catch {
                guard !Task.isCancelled, self.liveTokens[id] == generation else { return }
                self.credentialAccess[id]?.complete = false
                self.credentialAccess[id]?.message = self.redacted(error.localizedDescription, id: id)
            }
        }
    }
}
