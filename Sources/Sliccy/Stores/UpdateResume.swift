import Darwin
import Foundation

/// What an in-app update reconnects after Sparkle relaunches Sliccy.
///
/// This mirrors the CLI's dashboard update (`u`, `SLICC_RESUME`): the old process
/// detaches with `--keep-browsers`, so Chrome and its SLICC tab stay open. The new
/// process links the same sessions again with the same settings. The record is read
/// once and only by a different build than the one that wrote it, so an ordinary
/// quit, or an update that did not install, resumes nothing. It grants nothing the
/// user had not already turned on. The record holds no join URL: a remote session
/// resumes only with the join URL it saved in the keychain after it last linked
/// (`SavedJoins`).
struct UpdateResume: Codable, Equatable, Sendable {
    struct Link: Codable, Equatable, Sendable {
        var id: UUID
        var local: Bool
        var offerCredentials: Bool
    }

    var v = 1
    var written: Date
    /// `CFBundleVersion` of the app that wrote the record.
    var build: String
    var links: [Link]
    /// CLI children of the old instance, so the new links start only after they detach.
    var pids: [Int32]

    static let key = "sliccy.update.resume"
    /// A relaunch that fails or is delayed this long resumes nothing.
    static let lifetime: TimeInterval = 10 * 60
    static let detachWait: Duration = .seconds(8)
    static var currentBuild: String? { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String }
}

extension WorkspaceStore {
    /// Called by the updater right before Sparkle quits Sliccy to relaunch the update.
    /// Records the sessions that are linked or linking now; the normal shutdown then
    /// detaches them without closing their browsers.
    func prepareUpdateRelaunch(now: Date = Date(), build: String? = UpdateResume.currentBuild) {
        guard !isDemo, let defaults else { return }
        let links = sessions
            .filter { $0.isLive && ($0.connection != .disconnected || reconfiguring.contains($0.id)) }
            .map { UpdateResume.Link(id: $0.id, local: $0.localBrowserProfile != nil,
                                     offerCredentials: credentialOffers.contains($0.id)) }
        guard let build, !links.isEmpty else { defaults.removeObject(forKey: UpdateResume.key); return }
        let pids = (Array(liveProcesses.values) + Array(retiringProcesses.values)).compactMap(\.runningPID)
        let record = UpdateResume(written: now, build: build, links: links, pids: pids)
        guard let data = try? JSONEncoder().encode(record) else { return }
        defaults.set(data, forKey: UpdateResume.key)
    }

    /// Reconnects what `prepareUpdateRelaunch` recorded. The record is removed before
    /// anything else, so a later launch never resumes from it.
    ///
    /// Resuming sessions show as connecting while the old CLI processes detach, the same
    /// way an access change does: Connect is unavailable and Disconnect cancels. If an old
    /// process is still running at the deadline, nothing is linked, so two CLIs never
    /// serve the same profile or grants.
    @discardableResult
    func resumeAfterUpdate(now: Date = Date(), build: String? = UpdateResume.currentBuild,
                           detachWait: Duration = UpdateResume.detachWait) -> Task<Void, Never>? {
        guard !isDemo, let defaults, let data = defaults.data(forKey: UpdateResume.key) else { return nil }
        defaults.removeObject(forKey: UpdateResume.key)
        guard let record = try? JSONDecoder().decode(UpdateResume.self, from: data), record.v == 1,
              let build, build != record.build else { return nil }
        let age = now.timeIntervalSince(record.written)
        guard age >= 0, age <= UpdateResume.lifetime else { return nil }

        var resumed: [UUID] = []
        for link in record.links {
            guard let session = session(link.id), session.isLive, session.connection == .disconnected,
                  !reconfiguring.contains(link.id), link.local == (session.localBrowserProfile != nil) else { continue }
            guard link.local || joinCredentials[link.id] != nil else {
                notice("Sliccy was updated. This join URL was not saved, so connect again with it.", id: link.id)
                continue
            }
            if link.offerCredentials { credentialOffers.insert(link.id) }
            notice(link.local ? "Sliccy was updated. Linking SLICC again in the browser that stayed open."
                              : "Sliccy was updated. Connecting to SLICC again with the saved join URL.", id: link.id)
            resumed.append(link.id)
        }
        save()
        guard !resumed.isEmpty else { return nil }
        let pids = record.pids
        var tasks: [Task<Void, Never>] = []
        for id in resumed {
            reconfiguring.insert(id)
            update(id) { $0.connection = .connecting; $0.connectionMessage = $0.localBrowserProfile != nil ? "Sliccy was updated. Waiting for the previous link to detach… Your browser stays open." : "Sliccy was updated. Waiting for the previous link to detach…" }
            let task = Task { [weak self] in
                let deadline = ContinuousClock.now.advanced(by: detachWait)
                while pids.contains(where: Self.processExists), ContinuousClock.now < deadline {
                    do { try await Task.sleep(for: .milliseconds(50)) } catch { return }
                }
                // Disconnect cancels this task and clears `reconfiguring`.
                guard let self, !Task.isCancelled, self.reconfiguring.contains(id) else { return }
                self.configurationTasks[id] = nil
                self.reconfiguring.remove(id)
                guard !pids.contains(where: Self.processExists) else {
                    self.credentialOffers.remove(id)
                    self.update(id) { $0.connection = .disconnected; $0.connectionMessage = "The previous CLI has not exited, so this session was not linked again. Quit that process, then connect." }
                    self.notice("The previous CLI has not exited, so this session was not linked again after the update.", id: id)
                    self.save()
                    return
                }
                self.update(id) { $0.connection = .disconnected; $0.connectionMessage = nil }
                self.reconnect(id)
            }
            configurationTasks[id] = task
            tasks.append(task)
        }
        return Task { for task in tasks { await task.value } }
    }

    nonisolated static func processExists(_ pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        return kill(pid, 0) == 0 || errno == EPERM
    }
}
