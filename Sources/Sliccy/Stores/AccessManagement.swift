import Foundation

extension WorkspaceStore {
    func setDemoCredential(_ credentialID: String, enabled: Bool, for id: UUID) {
        guard let session = session(id), !session.isLive else { return }
        update(id) {
            var snapshot = $0.managementSnapshot!
            if let index = snapshot.credentials.firstIndex(where: { $0.id == credentialID }) {
                snapshot.credentials[index].enabled = enabled
            }
            $0.management = snapshot
        }
        save()
    }

    func setDemoScreen(_ target: String?, for id: UUID) {
        guard let session = session(id), !session.isLive,
              target == nil || session.connection == .connected else { return }
        update(id) {
            var snapshot = $0.managementSnapshot!
            snapshot.screenTarget = target
            $0.management = snapshot
        }
        save()
    }
}

extension WorkspaceStore {
    enum Entitlement { case browser, network, shell, sftp }

    func setDemoEntitlement(_ entitlement: Entitlement, enabled: Bool, for id: UUID) {
        guard session(id)?.isLive == false else { return }
        update(id) { session in
            switch entitlement {
            case .browser:
                if let current = session.access.browser { session.access.preferredBrowser = current }
                session.access.browser = enabled ? session.access.preferredBrowser ?? "Google Chrome" : nil
            case .network: session.access.network = enabled
            case .shell:
                session.access.shell = enabled
                if !enabled { session.access.sftp = false }
            case .sftp:
                session.access.sftp = enabled
                if enabled { session.access.shell = true }
            }
        }
        save()
    }

    func setDemoFolder(_ folderID: UUID, enabled: Bool? = nil, readOnly: Bool? = nil, for id: UUID) {
        guard session(id)?.isLive == false else { return }
        update(id) { session in
            guard let index = session.access.folders.firstIndex(where: { $0.id == folderID }) else { return }
            if let enabled { session.access.folders[index].enabled = enabled }
            if let readOnly { session.access.folders[index].readOnly = readOnly }
        }
        save()
    }

    func addDemoFolder(_ url: URL, for id: UUID) {
        guard session(id)?.isLive == false else { return }
        update(id) { session in
            if let index = session.access.folders.firstIndex(where: { $0.path == url.path }) {
                session.access.folders[index].enabled = true
                return
            }
            let base = url.lastPathComponent
            var name = base
            var suffix = 2
            while session.access.folders.contains(where: { $0.name == name }) { name = "\(base)-\(suffix)"; suffix += 1 }
            session.access.folders.append(.init(name: name, path: url.path))
        }
        save()
    }
}
