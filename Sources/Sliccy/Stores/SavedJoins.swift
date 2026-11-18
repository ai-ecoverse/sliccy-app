import CryptoKit
import Foundation

extension Session {
    /// SHA-256 hex of a trimmed join URL: `watchIdentity`, and the id slicc's Apple apps
    /// use for the same URL in iCloud.
    static func joinIdentity(_ joinURL: String) -> String {
        let trimmed = joinURL.trimmingCharacters(in: .whitespacesAndNewlines)
        return SHA256.hash(data: Data(trimmed.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

extension WorkspaceStore {
    /// Whether join URLs are shared through iCloud. Only possible when the build can sync.
    var syncsJoinsWithICloud: Bool { joinSync != nil && iCloudJoins }

    /// After the user turns iCloud sync on, shares every join URL that linked before:
    /// connected sessions, and disconnected ones whose URL the keychain already holds.
    /// The keychain is written only on `linked`; `watchIdentity` is set as soon as a URL
    /// is entered, so it proves nothing about a link.
    func iCloudJoinsChanged() {
        guard syncsJoinsWithICloud, let joinSync else { return }
        for session in sessions where session.isLive && session.localBrowserProfile == nil {
            guard let url = joinCredentials[session.id] else { continue }
            if session.connection == .connected { rememberJoin(session.id) }
            else if joinVault?.read(session.id) == url { joinSync.record(joinURL: url, label: session.name) }
        }
        restoreSavedJoins()
    }

    /// How this build keeps join URLs, for the join URL fields.
    var joinStorageSummary: String {
        if syncsJoinsWithICloud { return "After it connects, Sliccy saves the join URL in your keychain and syncs it through iCloud with your other devices." }
        if joinVault != nil { return "After it connects, Sliccy saves the join URL in your keychain on this Mac." }
        return "The join URL stays in memory for this app session."
    }

    /// iCloud join URLs not already bound to a session here, for New Session.
    var iCloudSuggestions: [ICloudJoin] { iCloudSuggestions(reconnecting: nil) }

    /// For Reconnect: the same list, plus the session's own URL first when iCloud has it.
    func iCloudSuggestions(reconnecting id: UUID?) -> [ICloudJoin] {
        guard syncsJoinsWithICloud, let joinSync else { return [] }
        let own = id.flatMap { session($0)?.watchIdentity }
        let used = Set(sessions.compactMap(\.watchIdentity)).subtracting(own.map { [$0] } ?? [])
        let joins = joinSync.joins.filter { !used.contains($0.id) }
        return joins.filter { $0.id == own } + joins.filter { $0.id != own }
    }

    /// Restores each remote session's join URL from the keychain, or from iCloud when
    /// the keychain has none and an iCloud entry has the session's identity.
    func restoreSavedJoins() {
        for session in sessions where session.isLive && session.localBrowserProfile == nil && joinCredentials[session.id] == nil {
            if let url = joinVault?.read(session.id), session.watchIdentity == nil || session.watchIdentity == Session.joinIdentity(url) {
                joinCredentials[session.id] = url
            } else if syncsJoinsWithICloud, let identity = session.watchIdentity, let url = joinSync?.joinURL(identity: identity) {
                joinCredentials[session.id] = url
                joinVault?.write(url, for: session.id)
            }
        }
    }

    /// Saves the join URL of a remote session that just linked, so only URLs that work persist.
    func rememberJoin(_ id: UUID) {
        guard let session = session(id), session.isLive, session.localBrowserProfile == nil,
              let url = joinCredentials[id] else { return }
        joinVault?.write(url, for: id)
        if syncsJoinsWithICloud { joinSync?.record(joinURL: url, label: session.name) }
    }

    /// Removes the saved join URL when its session is removed.
    func forgetJoin(_ id: UUID) {
        joinVault?.delete(id)
        if let identity = session(id)?.watchIdentity { joinSync?.forget(identity: identity) }
    }
}
