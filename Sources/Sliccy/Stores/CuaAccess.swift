import Foundation

extension WorkspaceStore {
    struct CuaAccessState {
        var starting = false
        var command: String?
        var message: String?
        var enabled: Bool { starting || command != nil }
    }

    func enableCua(_ installation: CuaInstallation, for id: UUID) {
        guard !isDemo, let session = session(id), session.isLive, session.localBrowserProfile != nil,
              session.connection == .connected, session.access.network,
              cuaAccess[id]?.enabled != true else { return }
        disableCua(id)
        do {
            let bridge = try CuaBridge()
            cuaBridges[id] = bridge
            cuaAccess[id] = .init(starting: true)
            bridge.onFailure = { [weak self, weak bridge] message in
                guard let self, self.cuaBridges[id] === bridge else { return }
                self.disableCua(id)
                self.cuaAccess[id] = .init(message: message)
            }
            cuaTasks[id] = Task { [weak self, weak bridge] in
                guard let self, let bridge else { return }
                do {
                    try await bridge.start(executable: installation.executable, arguments: installation.arguments, sessionID: id)
                    guard !Task.isCancelled, self.cuaBridges[id] === bridge,
                          self.session(id)?.connection == .connected else { bridge.stop(); return }
                    self.cuaAccess[id] = .init(command: bridge.setupCommand)
                } catch {
                    guard self.cuaBridges[id] === bridge else { return }
                    self.disableCua(id)
                    self.cuaAccess[id] = .init(message: error.localizedDescription)
                }
                self.cuaTasks[id] = nil
            }
        } catch { cuaAccess[id] = .init(message: error.localizedDescription) }
    }

    func disableCua(_ id: UUID) {
        cuaTasks.removeValue(forKey: id)?.cancel()
        cuaBridges.removeValue(forKey: id)?.stop()
        cuaAccess[id] = nil
    }
}
