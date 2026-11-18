import Foundation
import Testing
@testable import Sliccy

@MainActor
struct UpdateResumeTests {
    private func defaults() throws -> (UserDefaults, String) {
        let domain = "SliccyTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: domain))
        // A CLI that cannot start: the test only observes that a link was started.
        defaults.set("/nonexistent/slicc", forKey: "sliccy.cli.path")
        return (defaults, domain)
    }

    private func local(_ name: String, _ connection: ConnectionState, profile: String) -> Session {
        Session(name: name, device: "This Mac", kind: .browser, profile: profile, connection: connection,
                access: .init(), usesLiveRuntime: true, localBrowserProfile: profile, localAccess: .init())
    }

    private func record(_ id: UUID, build: String = "7", pids: [Int32] = []) throws -> Data {
        try JSONEncoder().encode(UpdateResume(written: Date(), build: build,
                                              links: [.init(id: id, local: true, offerCredentials: false)], pids: pids))
    }

    @Test func updateRelaunchRelinksLocalSessionsOnceWithTheirSettings() async throws {
        let (defaults, domain) = try defaults()
        defer { defaults.removePersistentDomain(forName: domain) }
        let linked = local("Linked", .connected, profile: "six")
        let reconnecting = local("Reconnecting", .reconnecting, profile: "work")
        let idle = local("Idle", .disconnected, profile: "home")
        let remote = Session(name: "Remote", device: "Remote SLICC", kind: .remote, profile: "Remote",
                             connection: .connected, access: .init(browser: nil, network: false), usesLiveRuntime: true)

        let old = WorkspaceStore(defaults: defaults)
        old.sessions = [linked, reconnecting, idle, remote]
        old.credentialOffers = [linked.id]
        old.joinCredentials[remote.id] = "https://www.sliccy.ai/join/secret"
        old.save()
        old.prepareUpdateRelaunch(build: "7")
        old.shutdown()

        let raw = try #require(defaults.data(forKey: UpdateResume.key))
        #expect(!String(decoding: raw, as: UTF8.self).contains("secret"))
        let record = try JSONDecoder().decode(UpdateResume.self, from: raw)
        #expect(Set(record.links.map(\.id)) == [linked.id, reconnecting.id, remote.id])
        #expect(record.build == "7")

        let new = WorkspaceStore(defaults: defaults)
        #expect(new.sessions.allSatisfy { $0.connection == .disconnected })
        let task = try #require(new.resumeAfterUpdate(build: "8", detachWait: .milliseconds(10)))
        #expect(defaults.data(forKey: UpdateResume.key) == nil)
        // While the old CLIs detach, resuming sessions are busy, not offering Connect.
        #expect(new.session(linked.id)?.connection == .connecting)
        #expect(new.reconfiguring == [linked.id, reconnecting.id])
        await task.value

        #expect(new.reconfiguring.isEmpty)
        #expect(new.liveTokens[linked.id] != nil)
        #expect(new.liveTokens[reconnecting.id] != nil)
        #expect(new.liveTokens[idle.id] == nil)
        #expect(new.liveTokens[remote.id] == nil)
        #expect(new.credentialSession == nil)
        #expect(new.credentialOffers.contains(linked.id))
        #expect(!new.credentialOffers.contains(reconnecting.id))
        #expect(new.session(remote.id)?.entries.last?.text.contains("join URL") == true)

        // The record is consumed: a later launch is an ordinary one.
        let later = WorkspaceStore(defaults: defaults)
        #expect(later.resumeAfterUpdate(build: "9") == nil)
        #expect(later.liveTokens.isEmpty)
    }

    @Test func staleUnknownOrUninstalledUpdatesResumeNothing() throws {
        let (defaults, domain) = try defaults()
        defer { defaults.removePersistentDomain(forName: domain) }
        let linked = local("Linked", .connected, profile: "six")
        let store = WorkspaceStore(defaults: defaults)
        store.sessions = [linked]
        store.save()

        store.prepareUpdateRelaunch(now: Date().addingTimeInterval(-UpdateResume.lifetime - 1), build: "7")
        let stale = WorkspaceStore(defaults: defaults)
        #expect(stale.resumeAfterUpdate(build: "8") == nil)
        #expect(stale.liveTokens.isEmpty)
        #expect(defaults.data(forKey: UpdateResume.key) == nil)

        var future = UpdateResume(written: Date(), build: "7", links: [.init(id: linked.id, local: true, offerCredentials: false)], pids: [])
        future.v = 2
        defaults.set(try JSONEncoder().encode(future), forKey: UpdateResume.key)
        let unknown = WorkspaceStore(defaults: defaults)
        #expect(unknown.resumeAfterUpdate(build: "8") == nil)
        #expect(unknown.liveTokens.isEmpty)
        #expect(defaults.data(forKey: UpdateResume.key) == nil)

        // Sparkle announced a relaunch but the same build came back (or the user
        // launched it by hand): that is an ordinary launch.
        store.prepareUpdateRelaunch(build: "7")
        let same = WorkspaceStore(defaults: defaults)
        #expect(same.resumeAfterUpdate(build: "7") == nil)
        #expect(same.liveTokens.isEmpty)
        #expect(same.reconfiguring.isEmpty)
        #expect(defaults.data(forKey: UpdateResume.key) == nil)

        // A build without a version neither writes nor reads a record.
        store.prepareUpdateRelaunch(build: nil)
        #expect(defaults.data(forKey: UpdateResume.key) == nil)
        defaults.set(try record(linked.id), forKey: UpdateResume.key)
        #expect(WorkspaceStore(defaults: defaults).resumeAfterUpdate(build: nil) == nil)
    }

    @Test func nothingLinkedClearsTheRecordAndDisconnectCancelsAPendingResume() async throws {
        let (defaults, domain) = try defaults()
        defer { defaults.removePersistentDomain(forName: domain) }
        let linked = local("Linked", .connected, profile: "six")
        let store = WorkspaceStore(defaults: defaults)
        store.sessions = [linked]
        store.save()
        store.prepareUpdateRelaunch(build: "7")
        #expect(defaults.data(forKey: UpdateResume.key) != nil)
        store.sessions[0].connection = .disconnected
        store.prepareUpdateRelaunch(build: "7")
        #expect(defaults.data(forKey: UpdateResume.key) == nil)

        // The old instance's CLI is still detaching; the user disconnects meanwhile.
        defaults.set(try record(linked.id, pids: [getpid()]), forKey: UpdateResume.key)
        let new = WorkspaceStore(defaults: defaults)
        let task = try #require(new.resumeAfterUpdate(build: "8", detachWait: .seconds(5)))
        // Connect does nothing while the old link detaches.
        new.reconnect(linked.id)
        #expect(new.liveTokens[linked.id] == nil)
        new.disconnect(linked.id)
        await task.value
        #expect(new.liveTokens[linked.id] == nil)
        #expect(new.reconfiguring.isEmpty)
        #expect(new.session(linked.id)?.connection == .disconnected)
    }

    @Test func anOldCLIThatOutlivesTheDeadlineIsNotJoinedByASecond() async throws {
        let (defaults, domain) = try defaults()
        defer { defaults.removePersistentDomain(forName: domain) }
        let linked = local("Linked", .connected, profile: "six")
        let seed = WorkspaceStore(defaults: defaults)
        seed.sessions = [linked]
        seed.save()
        let offering = UpdateResume(written: Date(), build: "7", links: [.init(id: linked.id, local: true, offerCredentials: true)],
                                    pids: [getpid()])
        defaults.set(try JSONEncoder().encode(offering), forKey: UpdateResume.key)

        let new = WorkspaceStore(defaults: defaults)
        let task = try #require(new.resumeAfterUpdate(build: "8", detachWait: .milliseconds(50)))
        await task.value
        #expect(new.liveTokens[linked.id] == nil)
        #expect(new.reconfiguring.isEmpty)
        #expect(!new.credentialOffers.contains(linked.id))
        #expect(new.session(linked.id)?.connection == .disconnected)
        #expect(new.session(linked.id)?.connectionMessage?.contains("has not exited") == true)
    }
}
