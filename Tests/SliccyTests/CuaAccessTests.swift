import Foundation
import Testing
@testable import Sliccy

struct CuaAccessTests {
    @Test func strictLocalHTTPBoundary() throws {
        func packet(_ first: String = "POST /mcp/secret HTTP/1.1", _ headers: String = "", _ body: String = "{}") -> Data {
            Data("\(first)\r\nHost: 127.0.0.1:1234\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\(headers)\r\n\(body)".utf8)
        }
        let valid = packet()
        #expect(try CuaHTTP.parse(valid, port: 1234, token: "secret")?.body == Data("{}".utf8))
        #expect(try CuaHTTP.parse(valid.dropLast(), port: 1234, token: "secret") == nil)
        #expect(throws: CuaHTTP.Rejection.self) { try CuaHTTP.parse(valid, port: 1234, token: "wrong") }
        #expect(throws: CuaHTTP.Rejection.self) { try CuaHTTP.parse(valid, port: 4321, token: "secret") }
        for headers in ["Origin: https://www.sliccy.ai\r\n", "Origin: null\r\n", "Host: attacker.test\r\n",
                        "Transfer-Encoding: chunked\r\n", "Content-Length: 2\r\n", "Expect: 100-continue\r\n"] {
            #expect(throws: CuaHTTP.Rejection.self) { try CuaHTTP.parse(packet("POST /mcp/secret HTTP/1.1", headers), port: 1234, token: "secret") }
        }
        for first in ["GET /mcp/secret HTTP/1.1", "POST /mcp/secret?x=1 HTTP/1.1", "POST http://127.0.0.1:1234/mcp/secret HTTP/1.1"] {
            #expect(throws: CuaHTTP.Rejection.self) { try CuaHTTP.parse(packet(first), port: 1234, token: "secret") }
        }
        #expect(throws: CuaHTTP.Rejection.self) { try CuaHTTP.parse(valid + valid, port: 1234, token: "secret") }
        #expect(throws: CuaHTTP.Rejection.self) { try CuaHTTP.parse(Data(repeating: 65, count: 8193), port: 1234, token: "secret") }
        let oversized = packet().replacingUTF8("Content-Length: 2", with: "Content-Length: 1048577")
        #expect(throws: CuaHTTP.Rejection.self) { try CuaHTTP.parse(oversized, port: 1234, token: "secret") }
    }

    @Test func discoversExternalAppsWithoutDirectRuntimeOrFallbackFromSpaces() throws {
        let home = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: home) }
        func app(_ name: String, _ id: String, _ binary: String, extra: [String: String] = [:]) throws -> URL {
            let root = home.appending(path: "Applications/\(name).app")
            let exe = root.appending(path: "Contents/\(binary)")
            try FileManager.default.createDirectory(at: exe.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data().write(to: exe)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: exe.path)
            var info = extra; info["CFBundleIdentifier"] = id
            try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: root.appending(path: "Contents/Info.plist"))
            return root
        }
        let standalone = try app("CuaDriver", "com.trycua.driver", "MacOS/cua-driver")
        let driver = try #require(CuaInstallation.inspect(app: standalone, home: home))
        #expect(driver.arguments == ["mcp"])
        let spaces = try app("Cua Spaces", "com.trycua.spaces.macos", "Helpers/cua-driver")
        let bundled = try #require(CuaInstallation.inspect(app: spaces, home: home))
        #expect(bundled.arguments == ["mcp", "--embedded", "--socket", home.appending(path: ".cua/run/cua-driver.sock").path, "--host-bundle-id", "com.trycua.spaces.macos"])
        #expect(!bundled.arguments.contains("--direct"))
        _ = try app("Cua Spaces", "com.trycua.spaces.macos", "Helpers/cua-driver", extra: ["CuaChannel": "local"])
        #expect(CuaInstallation.inspect(app: spaces, home: home) == nil)
        _ = try app("CuaDriver", "other.app", "MacOS/cua-driver")
        #expect(CuaInstallation.inspect(app: standalone, home: home) == nil)
    }

    @MainActor @Test func bridgeSpeaksHTTPAndStdioAndRevokesAccess() async throws {
        let bridge = try CuaBridge()
        defer { bridge.stop() }
        try await bridge.start(executable: URL(fileURLWithPath: "/usr/bin/python3"), arguments: [fixture.path], sessionID: UUID())
        let command = try #require(bridge.setupCommand)
        let url = try #require(command.split(separator: " ").first(where: { $0.hasPrefix("http:") }).flatMap { URL(string: String($0)) })
        #expect(url.host == "127.0.0.1")
        #expect(url.lastPathComponent.count == 64)
        let client = URLSession(configuration: .ephemeral)
        defer { client.invalidateAndCancel() }
        func call(_ method: String, id: Any = "client-id", params: [String: Any] = [:], at endpoint: URL? = nil) async throws -> (Data, Int) {
            var request = URLRequest(url: endpoint ?? url)
            request.httpMethod = "POST"
            request.timeoutInterval = 5
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "method": method, "params": params])
            let (data, response) = try await client.data(for: request)
            return (data, (response as? HTTPURLResponse)?.statusCode ?? 0)
        }
        let (discovery, _) = try await call("server/discover")
        let discoveryJSON = try #require(JSONSerialization.jsonObject(with: discovery) as? [String: Any])
        #expect((discoveryJSON["error"] as? [String: Any])?["code"] as? Int == -32601)
        let (initialized, status) = try await call("initialize")
        #expect(status == 200)
        let initialJSON = try #require(JSONSerialization.jsonObject(with: initialized) as? [String: Any])
        #expect((initialJSON["result"] as? [String: Any])?["protocolVersion"] as? String == "2025-06-18")
        let (tools, _) = try await call("tools/list", id: 42)
        let toolsJSON = try #require(JSONSerialization.jsonObject(with: tools) as? [String: Any])
        #expect(toolsJSON["id"] as? Int == 42)
        #expect((toolsJSON["result"] as? [String: Any])?["tools"] as? [[String: Any]] != nil)
        let (echo, _) = try await call("tools/call", params: ["name": "fake_echo", "arguments": ["value": "synthetic"]])
        #expect(String(decoding: echo, as: UTF8.self).contains("synthetic"))
        #expect(try await call("tools/list", at: url.deletingLastPathComponent().appending(path: "wrong")).1 == 404)
        bridge.stop()
        #expect(bridge.setupCommand == nil)
        let denied = await bridge.respond(Data("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}".utf8))
        #expect(String(decoding: denied, as: UTF8.self).hasPrefix("HTTP/1.1 410"))
        do { _ = try await call("tools/list"); Issue.record("Revoked listener remained reachable") } catch { }
    }

    @MainActor @Test func timeoutStopsProxyAndDoesNotRetry() async throws {
        let proxy = CuaMCPProcess()
        defer { proxy.stop() }
        try proxy.start(executable: URL(fileURLWithPath: "/usr/bin/python3"), arguments: [fixture.path])
        do {
            _ = try await proxy.request(method: "tools/call", params: ["arguments": ["sleep": 1]], timeout: .milliseconds(50))
            Issue.record("Timeout was not enforced")
        } catch { #expect(error as? CuaError == .timeout) }
        do { _ = try await proxy.request(method: "tools/list", params: [:]); Issue.record("Proxy reused after timeout") }
        catch { #expect(error as? CuaError == .stopped) }
    }

    @MainActor @Test func lossCloseAndShutdownClearNonPersistentOptIn() {
        let store = WorkspaceStore(defaults: nil)
        let session = Session(name: "Local", device: "Mac", kind: .browser, profile: "test", connection: .connected,
                              access: .init(network: true), usesLiveRuntime: true, localBrowserProfile: "test")
        store.sessions = [session]
        for event in ["connecting", "link-lost", "reconnecting", "closed", "linked"] {
            store.cuaAccess[session.id] = .init(command: "temporary secret")
            store.applyLifecycle(try! JSONDecoder().decode(CLIEvent.self, from: Data("{\"event\":\"\(event)\"}".utf8)), to: session.id)
            #expect(store.cuaAccess[session.id] == nil)
        }
        store.cuaAccess[session.id] = .init(command: "temporary secret")
        store.shutdown()
        #expect(store.cuaAccess[session.id] == nil)
        #expect(!String(decoding: try! JSONEncoder().encode(store.sessions), as: UTF8.self).contains("temporary secret"))
    }

    @MainActor @Test func proxyExitClosesRouteAndFreshEnableRotatesSecret() async throws {
        let bridge = try CuaBridge()
        defer { bridge.stop() }
        try await bridge.start(executable: URL(fileURLWithPath: "/usr/bin/python3"), arguments: [fixture.path], sessionID: UUID())
        let oldCommand = try #require(bridge.setupCommand)
        let request = Data(#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fake_echo","arguments":{"exit":true}}}"#.utf8)
        _ = await bridge.respond(request)
        #expect(bridge.setupCommand == nil)
        let next = try CuaBridge()
        defer { next.stop() }
        try await next.start(executable: URL(fileURLWithPath: "/usr/bin/python3"), arguments: [fixture.path], sessionID: UUID())
        #expect(next.setupCommand != oldCommand)
    }

    @MainActor @Test func ineligibleSessionsCannotStartCuaAndRestartDoesNotRestoreConsent() throws {
        let suite = "cua-consent-" + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = WorkspaceStore(defaults: defaults)
        let unavailable = CuaInstallation(app: URL(fileURLWithPath: "/missing.app"), name: "Missing", executable: URL(fileURLWithPath: "/must-not-run"), arguments: ["mcp"])
        let session = Session(name: "Local", device: "Mac", kind: .browser, profile: "test", connection: .connected,
                              access: .init(network: false), usesLiveRuntime: true, localBrowserProfile: "test")
        store.sessions = [session]
        store.enableCua(unavailable, for: session.id)
        #expect(store.cuaAccess.isEmpty && store.cuaBridges.isEmpty)
        store.update(session.id) { $0.access.network = true; $0.localBrowserProfile = nil }
        store.enableCua(unavailable, for: session.id)
        #expect(store.cuaAccess.isEmpty && store.cuaBridges.isEmpty)
        store.update(session.id) { $0.localBrowserProfile = "test"; $0.connection = .disconnected }
        store.enableCua(unavailable, for: session.id)
        #expect(store.cuaAccess.isEmpty && store.cuaBridges.isEmpty)
        store.cuaAccess[session.id] = .init(command: "private-link")
        store.save()
        let restored = WorkspaceStore(defaults: defaults)
        #expect(restored.cuaAccess.isEmpty && restored.cuaBridges.isEmpty)
        #expect(restored.sessions.first?.connection == .disconnected)
    }

    private var fixture: URL { Bundle.module.resourceURL!.appending(path: "Fixtures/cua-mcp-fake.py") }
}

private extension Data {
    func replacingUTF8(_ before: String, with after: String) -> Data {
        Data(String(decoding: self, as: UTF8.self).replacingOccurrences(of: before, with: after).utf8)
    }
}
