import Foundation
import Network
import Security

/// A per-enable, loopback-only capability URL. It is a bearer credential, not browser/session
/// isolation: anyone with it and local network access can use Cua while the bridge is enabled.
@MainActor
final class CuaBridge {
    private let proxy = CuaMCPProcess()
    private var ready: CheckedContinuation<Void, any Error>?
    private var startTimeout: Task<Void, Never>?
    private var listener: NWListener?
    private var connections: [UUID: NWConnection] = [:]
    private var timers: [UUID: Task<Void, Never>] = [:]
    private var initialization: Any?
    private var active = true
    private var port: UInt16 = 0
    private let token: String
    var onFailure: ((String) -> Void)?
    private(set) var setupCommand: String?

    init() throws {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw CuaError.unavailable }
        token = bytes.map { String(format: "%02x", $0) }.joined()
    }

    func start(executable: URL, arguments: [String], sessionID: UUID) async throws {
        proxy.onFailure = { [weak self] message in
            self?.stop()
            self?.onFailure?(message)
        }
        do {
            try proxy.start(executable: executable, arguments: arguments)
            let reply = try await proxy.request(method: "initialize", params: ["protocolVersion": "2025-06-18",
                "capabilities": [:], "clientInfo": ["name": "Sliccy", "version": "1"]], timeout: .seconds(10))
            guard let object = try JSONSerialization.jsonObject(with: reply) as? [String: Any],
                  let result = object["result"] as? [String: Any],
                  ["2024-11-05", "2025-03-26", "2025-06-18"].contains(result["protocolVersion"] as? String ?? ""),
                  result["capabilities"] as? [String: Any] != nil else { throw CuaError.protocolFailure }
            // The bridge presents the 2025-06-18 HTTP subset; the upstream version is independent.
            var exposed = result
            exposed["protocolVersion"] = "2025-06-18"
            exposed["capabilities"] = ["tools": [:], "resources": [:]]
            initialization = exposed
            try proxy.initialized()
            guard active else { throw CuaError.stopped }
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
            let server = try NWListener(using: parameters)
            listener = server
            server.newConnectionHandler = { [weak self] connection in
                Task { @MainActor in self?.accept(connection) }
            }
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                ready = continuation
                server.stateUpdateHandler = { [weak self] state in
                    Task { @MainActor in
                        guard let self else { return }
                        switch state {
                        case .ready:
                            guard self.active, let port = server.port?.rawValue else { self.stop(); return }
                            self.port = port
                            let name = "sliccy-cua-" + sessionID.uuidString.lowercased()
                            // Replace only this connection's prior registration; never touch other MCP servers.
                            self.setupCommand = "mcp delete \(name); mcp add http://127.0.0.1:\(port)/mcp/\(self.token) \(name)"
                            self.startTimeout?.cancel(); self.startTimeout = nil
                            self.ready?.resume(); self.ready = nil
                        case .failed:
                            self.stop()
                            self.onFailure?(CuaError.unavailable.localizedDescription)
                        case .cancelled: self.stop()
                        default: break
                        }
                    }
                }
                server.start(queue: .main)
                startTimeout = Task { [weak self] in
                    do { try await Task.sleep(for: .seconds(5)) } catch { return }
                    self?.stop()
                }
            }
        } catch { stop(); throw error }
    }

    func stop() {
        active = false
        ready?.resume(throwing: CuaError.stopped); ready = nil
        startTimeout?.cancel(); startTimeout = nil
        setupCommand = nil
        listener?.cancel(); listener = nil
        for timer in timers.values { timer.cancel() }
        timers.removeAll()
        for connection in connections.values { connection.cancel() }
        connections.removeAll()
        proxy.stop()
    }

    private func accept(_ connection: NWConnection) {
        guard active, connections.count < 8 else { connection.cancel(); return }
        let id = UUID()
        connections[id] = connection
        connection.start(queue: .main)
        timers[id] = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(60)) } catch { return }
            self?.finish(id)
        }
        receive(id, data: Data())
    }

    private func finish(_ id: UUID) {
        timers.removeValue(forKey: id)?.cancel()
        connections.removeValue(forKey: id)?.cancel()
    }

    private func receive(_ id: UUID, data: Data) {
        guard active, let connection = connections[id] else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] chunk, _, complete, error in
            Task { @MainActor in
                guard let self, self.active, self.connections[id] != nil else { return }
                var buffer = data
                if let chunk { buffer.append(chunk) }
                do {
                    if let request = try CuaHTTP.parse(buffer, port: self.port, token: self.token) {
                        let response = await self.respond(request.body)
                        guard self.active, self.connections[id] != nil else { return }
                        connection.send(content: response, completion: .contentProcessed { _ in
                            Task { @MainActor in self.finish(id) }
                        })
                    } else if complete || error != nil { self.finish(id) }
                    else { self.receive(id, data: buffer) }
                } catch {
                    let status = (error as? CuaHTTP.Rejection)?.status ?? 400
                    connection.send(content: CuaHTTP.response(status: status), completion: .contentProcessed { _ in
                        Task { @MainActor in self.finish(id) }
                    })
                }
            }
        }
    }

    func respond(_ data: Data) async -> Data {
        guard active else { return CuaHTTP.response(status: 410) }
        guard let message = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              message["jsonrpc"] as? String == "2.0", let method = message["method"] as? String else {
            return CuaHTTP.response(status: 400)
        }
        if method == "notifications/initialized", message["id"] == nil { return CuaHTTP.response(status: 202) }
        guard let id = message["id"], id is String || (id is NSNumber && CFGetTypeID(id as CFTypeRef) != CFBooleanGetTypeID()) else {
            return CuaHTTP.response(status: 400)
        }
        func frame(_ key: String, _ value: Any) -> Data {
            guard let encoded = try? JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, key: value]) else { return CuaHTTP.response(status: 502) }
            return CuaHTTP.response(status: 200, body: encoded)
        }
        if method == "initialize", let initialization { return frame("result", initialization) }
        let methods = ["ping", "tools/list", "tools/call", "resources/list", "resources/read", "resources/templates/list"]
        guard methods.contains(method) else {
            // SLICC's modern discovery probe falls back to initialize on this exact error.
            return frame("error", ["code": -32601, "message": "Method not supported"])
        }
        do {
            let response = try await proxy.request(method: method, params: message["params"] ?? [:])
            guard active else { return CuaHTTP.response(status: 410) }
            guard let object = try JSONSerialization.jsonObject(with: response) as? [String: Any] else { throw CuaError.protocolFailure }
            if let error = object["error"] { return frame("error", error) }
            return frame("result", object["result"] ?? NSNull())
        } catch {
            return frame("error", ["code": -32000, "message": (error as? CuaError)?.localizedDescription ?? CuaError.unavailable.localizedDescription])
        }
    }
}
