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
        old.prepareUpdateRelaunch()
        old.shutdown()

        let raw = try #require(defaults.data(forKey: UpdateResume.key))
        #expect(!String(decoding: raw, as: UTF8.self).contains("secret"))
        let record = try JSONDecoder().decode(UpdateResume.self, from: raw)
        #expect(Set(record.links.map(\.id)) == [linked.id, reconnecting.id, remote.id])

        let new = WorkspaceStore(defaults: defaults)
        #expect(new.sessions.allSatisfy { $0.connection == .disconnected })
        let task = try #require(new.resumeAfterUpdate(detachWait: .milliseconds(10)))
        #expect(defaults.data(forKey: UpdateResume.key) == nil)
        await task.value

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
        #expect(later.resumeAfterUpdate() == nil)
        #expect(later.liveTokens.isEmpty)
    }

    @Test func staleOrUnknownRecordsResumeNothing() throws {
        let (defaults, domain) = try defaults()
        defer { defaults.removePersistentDomain(forName: domain) }
        let linked = local("Linked", .connected, profile: "six")
        let store = WorkspaceStore(defaults: defaults)
        store.sessions = [linked]
        store.save()

        store.prepareUpdateRelaunch(now: Date().addingTimeInterval(-UpdateResume.lifetime - 1))
        let stale = WorkspaceStore(defaults: defaults)
        #expect(stale.resumeAfterUpdate() == nil)
        #expect(stale.liveTokens.isEmpty)
        #expect(defaults.data(forKey: UpdateResume.key) == nil)

        var future = UpdateResume(written: Date(), links: [.init(id: linked.id, local: true, offerCredentials: false)], pids: [])
        future.v = 2
        defaults.set(try JSONEncoder().encode(future), forKey: UpdateResume.key)
        let unknown = WorkspaceStore(defaults: defaults)
        #expect(unknown.resumeAfterUpdate() == nil)
        #expect(unknown.liveTokens.isEmpty)
        #expect(defaults.data(forKey: UpdateResume.key) == nil)
    }

    @Test func nothingLinkedClearsTheRecordAndDisconnectCancelsAPendingResume() async throws {
        let (defaults, domain) = try defaults()
        defer { defaults.removePersistentDomain(forName: domain) }
        let linked = local("Linked", .connected, profile: "six")
        let store = WorkspaceStore(defaults: defaults)
        store.sessions = [linked]
        store.save()
        store.prepareUpdateRelaunch()
        #expect(defaults.data(forKey: UpdateResume.key) != nil)
        store.sessions[0].connection = .disconnected
        store.prepareUpdateRelaunch()
        #expect(defaults.data(forKey: UpdateResume.key) == nil)

        // The old instance's CLI is still detaching; the user disconnects meanwhile.
        let record = UpdateResume(written: Date(), links: [.init(id: linked.id, local: true, offerCredentials: false)],
                                  pids: [getpid()])
        defaults.set(try JSONEncoder().encode(record), forKey: UpdateResume.key)
        let new = WorkspaceStore(defaults: defaults)
        let task = try #require(new.resumeAfterUpdate(detachWait: .milliseconds(200)))
        new.disconnectLive(linked.id)
        await task.value
        #expect(new.liveTokens[linked.id] == nil)
        #expect(new.session(linked.id)?.connection == .disconnected)
    }
}
