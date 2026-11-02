import Foundation

struct CLICapabilities: Decodable, Sendable {
    struct Command: Decodable, Sendable { var json: String }
    struct Agent: Decodable, Sendable { var own: [String]? }
    struct Control: Decodable, Sendable { var v: Int; var ops: [String] }
    var schema: Int
    var version: String
    var contract: Int
    var commands: [String: Command]
    var control: Control
    var agent: Agent?

    var supportsCredentialLeases: Bool {
        schema == 1 && contract == 1 && control.v == 1 &&
        ["leases", "unseal", "seal-off", "seal-on"].allSatisfy(control.ops.contains)
    }

    var supportsResumableWatch: Bool {
        supportsRemoteWorkspace && commands["watch"]?.json == "events" &&
        ["opened", "reconnecting"].allSatisfy { agent?.own?.contains($0) == true }
    }

    var supportsRemoteWorkspace: Bool {
        schema == 1 && contract == 1 && control.v == 1 && control.ops.contains("detach") &&
        ["follow", "prompt"].allSatisfy { commands[$0]?.json == "events" } && commands["abort"] != nil
    }
}

struct CLIInvocation: Sendable {
    var arguments: [String]
    var input: Data = Data()

    static func follow(join: String, offerCredentials: Bool = false) -> Self {
        // The broker is offered only after the user enables the credential switch.
        .init(arguments: ["-", "follow", "--json"] + (offerCredentials ? ["--jerk-seal"] : []), input: Data((join + "\n").utf8))
    }
    static func prompt(join: String, text: String, steer: Bool) -> Self {
        .init(arguments: ["-", "prompt", "--json"] + (steer ? ["--steer"] : []) + ["-"],
              input: Data((join + "\n" + text).utf8))
    }
    static func watch(join: String, since: String?) -> Self {
        .init(arguments: ["-", "watch", "--json"] + (since.map { ["--since", $0] } ?? []),
              input: Data((join + "\n").utf8))
    }
    static func abort(join: String) -> Self {
        .init(arguments: ["-", "abort"], input: Data((join + "\n").utf8))
    }
    static func agents(join: String) -> Self {
        .init(arguments: ["-", "agents", "--json", "--watch"], input: Data((join + "\n").utf8))
    }
}

enum CLIError: LocalizedError {
    case exit(Int32), incompatible, missing, oversized
    var errorDescription: String? {
        switch self {
        case .exit(let status): "slicc exited with status \(status). Check CLI compatibility and reconnect with a current join URL."
        case .incompatible: "This CLI does not provide the required native-app contract. Choose slicc 1.53 or later."
        case .missing: "Choose an executable slicc binary in Settings → Runtime."
        case .oversized: "The CLI response exceeded the size limit."
        }
    }
}

/// Owns one child process. Pipe reads and writes run off the UI thread.
/// Human stderr is drained by /dev/null; only the JSON contract controls UI state.
@MainActor
final class CLIProcess {
    private let process = Process()
    private let output = Pipe()
    private let input = Pipe()
    private var reader: Task<Void, Never>?
    private var timeout: Task<Void, Never>?
    var runningPID: Int32? { process.isRunning ? process.processIdentifier : nil }

    func start(executable: String, invocation: CLIInvocation, deadline: Duration? = nil) throws -> AsyncThrowingStream<Data, Error> {
        guard FileManager.default.isExecutableFile(atPath: executable) else { throw CLIError.missing }
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = invocation.arguments
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.standardInput = input
        try process.run()
        // Close the parent's duplicates, so EOF follows child exit.
        try? output.fileHandleForWriting.close()
        try? input.fileHandleForReading.close()
        let handle = output.fileHandleForReading
        let writer = input.fileHandleForWriting
        let process = process
        let data = invocation.input
        let stream = AsyncThrowingStream<Data, Error>(bufferingPolicy: .bufferingOldest(256)) { continuation in
            Task.detached {
                defer { try? writer.close() }
                try? writer.write(contentsOf: data)
            }
            reader = Task.detached {
                defer { try? handle.close() }
                do {
                    while true {
                        let bytes = handle.availableData
                        if bytes.isEmpty { break }
                        if case .dropped = continuation.yield(bytes) { throw CLIError.oversized }
                    }
                    process.waitUntilExit()
                    if process.terminationStatus == 0 { continuation.finish() }
                    else { continuation.finish(throwing: CLIError.exit(process.terminationStatus)) }
                } catch {
                    if process.isRunning { process.terminate() }
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { @Sendable [weak self] _ in
                Task { @MainActor [weak self] in self?.terminate() }
            }
        }
        if let deadline {
            timeout = Task { [weak self] in
                do { try await Task.sleep(for: deadline) } catch { return }
                self?.terminate()
            }
        }
        return stream
    }

    func terminate() {
        timeout?.cancel(); timeout = nil
        if process.isRunning { process.terminate() }
    }
}

@MainActor
struct CLIClient {
    static var defaultExecutable: String {
        if let path = Bundle.main.path(forResource: "slicc", ofType: nil), FileManager.default.isExecutableFile(atPath: path) { return path }
        return FileManager.default.homeDirectoryForCurrentUser.appending(path: ".local/bin/slicc").path
    }
    static func capabilities(at path: String) async throws -> CLICapabilities {
        let child = CLIProcess()
        defer { child.terminate() }
        let stream = try child.start(executable: path, invocation: .init(arguments: ["capabilities", "--json"]), deadline: .seconds(10))
        var data = Data()
        for try await chunk in stream {
            data.append(chunk)
            guard data.count < 1024 * 1024 else { throw CLIError.oversized }
        }
        let capabilities = try JSONDecoder().decode(CLICapabilities.self, from: data)
        guard capabilities.supportsRemoteWorkspace else { throw CLIError.incompatible }
        return capabilities
    }
}
