import AppKit
import Foundation
import Testing
@testable import Sliccy

@MainActor struct DefaultBrowserTests {
    final class System: DefaultBrowserSystem {
        var handlers: [String: URL] = [:]
        var claims: [String] = []
        var refusal: String?
        func handler(for scheme: String) -> URL? { handlers[scheme] }
        func claim(_ scheme: String, app: URL) async throws {
            claims.append(scheme)
            if refusal == scheme { throw CocoaError(.userCancelled) }
            handlers[scheme] = app
        }
    }
    @Test func registrationRequiresBothSchemesAndExplicitRequest() async {
        let app = URL(fileURLWithPath: "/Applications/Sliccy.app")
        let system = System()
        system.handlers["https"] = app
        let registration = DefaultBrowserRegistration(app: app, system: system, canRegister: true)
        #expect(!registration.isDefault)
        #expect(system.claims.isEmpty)
        await registration.makeDefault()
        #expect(system.claims == ["http", "https"])
        #expect(registration.isDefault)
        system.handlers["http"] = URL(fileURLWithPath: "/Other/Sliccy.app")
        registration.refresh()
        #expect(!registration.isDefault)
    }
    @Test func cancellationAndUnbundledBuildNeverClaimSuccess() async {
        let system = System(); system.refusal = "https"
        let registration = DefaultBrowserRegistration(system: system, canRegister: true)
        await registration.makeDefault()
        #expect(!registration.isDefault)
        #expect(registration.message != nil)
        let unbundled = DefaultBrowserRegistration(system: system, canRegister: false)
        system.claims.removeAll()
        await unbundled.makeDefault()
        #expect(system.claims.isEmpty)
    }
    @Test func webLinksPreserveQueryFragmentAndCannotEscapeCDPEndpoint() throws {
        let url = URL(string: "https://example.com/search?q=a%26b&next=https%3A%2F%2Fother.test%2F#section")!
        let request = try BrowserTabClient.openRequest(url, endpoint: "http://127.0.0.1:9222")
        #expect(request.httpMethod == "PUT")
        #expect(request.url?.host == "127.0.0.1")
        #expect(request.url?.path == "/json/new")
        #expect(URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.percentEncodedQuery?.removingPercentEncoding == url.absoluteString)
        for bad in ["file:///etc/passwd", "javascript:alert(1)", "data:text/html,test", "https://user:secret@example.com", "slicc://join/test"] {
            #expect(!IncomingWebLinks.accepts(URL(string: bad)!))
        }
        #expect(throws: (any Error).self) { try BrowserTabClient.openRequest(url, endpoint: "https://evil.example") }
    }
    @Test func burstQueuePreservesOrderAndDoesNotReplayOnFailure() async {
        var opened: [URL] = []; var errors: [String] = []
        let router = IncomingWebLinks(open: { opened.append($0); await Task.yield() }, report: { errors.append($0) })
        let a = URL(string: "https://example.com/a")!, b = URL(string: "https://example.com/b")!
        router.receive([a]); router.receive([b]); await router.waitUntilIdle()
        #expect(opened == [a,b]); #expect(errors.isEmpty)
        let failing = IncomingWebLinks(open: { opened.append($0); throw CocoaError(.fileReadUnknown) }, report: { errors.append($0) })
        failing.receive([a,b]); await failing.waitUntilIdle()
        #expect(opened == [a,b,a]); #expect(errors.count == 1)
        #expect(!errors[0].contains(a.absoluteString))
        router.receive(Array(repeating: a, count: 33)); await router.waitUntilIdle()
        #expect(opened == [a,b,a]); #expect(errors.count == 2)
    }
    @Test func coldLaunchQueuesUntilStoreAttachesAndSelectionPersists() throws {
        let delegate = AppDelegate(); let url = URL(string: "https://example.com")!
        delegate.application(NSApplication.shared, open: [url])
        var delivered: [URL] = []
        delegate.attachWebLinks({ delivered += $0 }, overflow: { Issue.record("unexpected overflow") })
        delegate.attachWebLinks({ delivered += $0 }, overflow: {})
        #expect(delivered == [url])
        let domain = "DefaultBrowserTests.\(UUID())"
        let defaults = try #require(UserDefaults(suiteName: domain)); defer { defaults.removePersistentDomain(forName: domain) }
        let store = WorkspaceStore(defaults: defaults); let id = UUID(); store.linkSessionID = id
        #expect(WorkspaceStore(defaults: defaults).linkSessionID == id)
        #expect(store.linkSessions.isEmpty)
    }
    @Test func attachedBrowserWinsThenPreferredOrFirstConfiguredProfile() {
        let store = WorkspaceStore(defaults: nil)
        func local(_ browser: LocalBrowserChoice, _ profile: String) -> Session {
            Session(name: profile, device: "This Mac", kind: .browser, profile: profile, connection: .disconnected,
                    access: .init(), usesLiveRuntime: true, localBrowserProfile: profile, localBrowser: browser)
        }
        let first = local(.edge, "work"), second = local(.brave, "personal")
        store.sessions = [first,second]
        #expect(store.webLinkDestination == first.id)
        store.linkSessionID = second.id
        #expect(store.webLinkDestination == second.id)
        store.update(first.id) { $0.connection = .connected }
        store.localBrowserEndpoints[first.id] = "http://127.0.0.1:9222"
        #expect(store.webLinkDestination == first.id) // attached wins over disconnected preference
        store.update(second.id) { $0.connection = .connected }
        store.localBrowserEndpoints[second.id] = "http://127.0.0.1:9223"
        #expect(store.webLinkDestination == second.id)
        store.linkSessionID = nil
        #expect(store.webLinkDestination == first.id)
        store.sessions = []
        #expect(store.webLinkDestination == nil) // no silent Chrome/default-profile creation
    }

}
