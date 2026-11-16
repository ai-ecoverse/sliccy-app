import Foundation
import Darwin

/// One stdio MCP client per explicitly enabled connection. The child is only a proxy;
/// Cua's independently installed app remains responsible for OS permissions and actions.
@MainActor
final class CuaMCPProcess {
    static let maximumFrame = 16 * 1024 * 1024
    private let process = Process()
    private let input = Pipe()
    private let output = Pipe()
    private let writer = DispatchQueue(label: "ai.sliccy.cua.stdin")
    private var reader: Task<Void, Never>?
    private var pending: [Int: CheckedContinuation<Data, any Error>] = [:]
    private var deadlines: [Int: Task<Void, Never>] = [:]
    private var nextID = 0
    private var stopped = false
    var onFailure: ((String) -> Void)?

    func start(executable: URL, arguments: [String]) throws {
        process.executableURL = executable
        process.arguments = arguments
        // Do not inherit CUA_DRIVER_DIRECT/EMBEDDED, permission modes, grants, or unrelated secrets.
        process.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                               "TMPDIR": NSTemporaryDirectory(), "LANG": "en_US.UTF-8"]
        process.standardInput = input
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        let (stream, continuation) = AsyncThrowingStream<Data, any Error>.makeStream(bufferingPolicy: .bufferingOldest(256))
        guard fcntl(input.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else { throw CuaError.unavailable }
        try process.run()
        // Parent must not hold the child's pipe ends open: EOF must be observable.
        try? input.fileHandleForReading.close()
        try? output.fileHandleForWriting.close()
        let handle = output.fileHandleForReading
        DispatchQueue.global(qos: .utility).async {
            defer { try? handle.close() }
            do {
                var bytes = [UInt8](repeating: 0, count: 64 * 1024)
                while true {
                    let count = Darwin.read(handle.fileDescriptor, &bytes, bytes.count)
                    if count == 0 { break }
                    if count < 0 {
                        if errno == EINTR { continue }
                        throw CuaError.unavailable
                    }
                    switch continuation.yield(Data(bytes.prefix(count))) {
                    case .enqueued: break
                    case .dropped, .terminated: throw CuaError.protocolFailure
                    @unknown default: throw CuaError.protocolFailure
                    }
                }
                continuation.finish()
            } catch { continuation.finish(throwing: error) }
        }
        reader = Task { [weak self] in
            var buffer = Data()
            do {
                for try await chunk in stream {
                    guard let self, !self.stopped else { return }
                    buffer.append(chunk)
                    while let newline = buffer.firstIndex(of: 10) {
                        guard newline <= Self.maximumFrame else { throw CuaError.protocolFailure }
                        let line = Data(buffer[..<newline])
                        buffer.removeSubrange(...newline)
                        if !line.isEmpty { try self.receive(line) }
                    }
                    guard buffer.count <= Self.maximumFrame else { throw CuaError.protocolFailure }
                }
                self?.fail(CuaError.unavailable)
            } catch { self?.fail(CuaError.protocolFailure) }
        }
    }

    func request(method: String, params: Any, timeout: Duration = .seconds(50)) async throws -> Data {
        guard !stopped, process.isRunning else { throw CuaError.stopped }
        guard pending.count < 8 else { throw CuaError.busy }
        nextID += 1
        let id = nextID
        let data = try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id, "method": method, "params": params])
        guard data.count <= CuaHTTP.maximumBody else { throw CuaError.protocolFailure }
        return try await withCheckedThrowingContinuation { continuation in
            pending[id] = continuation
            deadlines[id] = Task { [weak self] in
                do { try await Task.sleep(for: timeout) } catch { return }
                self?.fail(CuaError.timeout)
            }
            write(data)
        }
    }

    func initialized() throws {
        write(try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "method": "notifications/initialized"]))
    }

    private func write(_ data: Data) {
        let handle = input.fileHandleForWriting
        writer.async { [weak self] in
            do { var line = data; line.append(10); try handle.write(contentsOf: line) }
            catch { Task { @MainActor in self?.fail(CuaError.unavailable) } }
        }
    }

    private func receive(_ data: Data) throws {
        guard let message = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              message["jsonrpc"] as? String == "2.0" else { throw CuaError.protocolFailure }
        if let id = message["id"] as? Int, let continuation = pending.removeValue(forKey: id) {
            guard (message["result"] != nil) != (message["error"] != nil), message["method"] == nil else {
                continuation.resume(throwing: CuaError.protocolFailure)
                throw CuaError.protocolFailure
            }
            deadlines.removeValue(forKey: id)?.cancel()
            continuation.resume(returning: data)
        } else if message["method"] != nil, let id = message["id"] {
            // No client sampling, filesystem roots, or elicitation capability was advertised.
            write(try JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id,
                "error": ["code": -32601, "message": "Client method not supported"]]))
        }
        // Server notifications are intentionally not retained or logged.
    }

    private func fail(_ error: CuaError) {
        guard !stopped else { return }
        stop(error: error)
        onFailure?(error.localizedDescription)
    }

    func stop(error: CuaError = .stopped) {
        guard !stopped else { return }
        stopped = true
        reader?.cancel(); reader = nil
        for task in deadlines.values { task.cancel() }
        deadlines.removeAll()
        let waiters = pending.values; pending.removeAll()
        for waiter in waiters { waiter.resume(throwing: error) }
        try? input.fileHandleForWriting.close()
        if process.isRunning { process.terminate() }
        // Terminate only the owned proxy. Never stop/revoke the shared Cua daemon.
    }
}
