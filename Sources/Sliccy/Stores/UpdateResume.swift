import Darwin
import Foundation

/// What an in-app update reconnects after Sparkle relaunches Sliccy.
///
/// This mirrors the CLI's dashboard update (`u`, `SLICC_RESUME`): the old process
/// detaches with `--keep-browsers`, so Chrome and its SLICC tab stay open. The new
/// process links the same sessions again with the same settings. The record is read
/// once, never after an ordinary quit, and grants nothing the user had not already
/// turned on. Join URLs are never written, so remote sessions still ask for theirs.
struct UpdateResume: Codable, Equatable, Sendable {
    struct Link: Codable, Equatable, Sendable {
        var id: UUID
        var local: Bool
        var offerCredentials: Bool
    }

    var v = 1
    var written: Date
    var links: [Link]
    /// CLI children of the old instance, so the new links start only after they detach.
    var pids: [Int32]

    static let key = "sliccy.update.resume"
    /// A relaunch that fails or is delayed this long resumes nothing.
    static let lifetime: TimeInterval = 10 * 60
    static let detachWait: Duration = .seconds(8)
}

extension WorkspaceStore {
    /// Called by the updater right before Sparkle quits Sliccy to relaunch the update.
    /// Records the sessions that are linked or linking now; the normal shutdown then
    /// detaches them without closing their browsers.
    func prepareUpdateRelaunch(now: Date = Date()) {
        guard !isDemo, let defaults else { return }
        let links = sessions
            .filter { $0.isLive && ($0.connection != .disconnected || reconfiguring.contains($0.id)) }
            .map { UpdateResume.Link(id: $0.id, local: $0.localBrowserProfile != nil,
                                     offerCredentials: credentialOffers.contains($0.id)) }
        guard !links.isEmpty else { defaults.removeObject(forKey: UpdateResume.key); return }
        let pids = (Array(liveProcesses.values) + Array(retiringProcesses.values)).compactMap(\.runningPID)
        let record = UpdateResume(written: now, links: links, pids: pids)
        guard let data = try? JSONEncoder().encode(record) else { return }
        defaults.set(data, forKey: UpdateResume.key)
    }

    /// Reconnects what `prepareUpdateRelaunch` recorded. The record is removed before
    /// anything else, so a later launch never resumes from it.
    @discardableResult
    func resumeAfterUpdate(now: Date = Date(), detachWait: Duration = UpdateResume.detachWait) -> Task<Void, Never>? {
        guard !isDemo, let defaults, let data = defaults.data(forKey: UpdateResume.key) else { return nil }
        defaults.removeObject(forKey: UpdateResume.key)
        guard let record = try? JSONDecoder().decode(UpdateResume.self, from: data), record.v == 1 else { return nil }
        let age = now.timeIntervalSince(record.written)
        guard age >= 0, age <= UpdateResume.lifetime else { return nil }

        var local: [UUID] = []
        for link in record.links {
            guard let session = session(link.id), session.isLive, session.connection == .disconnected else { continue }
            if link.local, session.localBrowserProfile != nil {
                if link.offerCredentials { credentialOffers.insert(link.id) }
                notice("Sliccy was updated. Linking SLICC again in the browser that stayed open.", id: link.id)
                local.append(link.id)
            } else if !link.local {
                notice("Sliccy was updated. Join URLs are not saved, so connect again with this instance’s join URL.", id: link.id)
            }
        }
        save()
        guard !local.isEmpty else { return nil }
        resumingLinks.formUnion(local)
        let pids = record.pids
        return Task { [weak self] in
            let deadline = ContinuousClock.now.advanced(by: detachWait)
            while pids.contains(where: Self.processExists), ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(50))
            }
            guard let self else { return }
            for id in local where self.resumingLinks.remove(id) != nil {
                self.reconnect(id)
            }
        }
    }

    nonisolated static func processExists(_ pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        return kill(pid, 0) == 0 || errno == EPERM
    }
}
