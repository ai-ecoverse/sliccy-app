import Foundation

struct CLICapabilities: Decodable, Sendable {
    struct Command: Decodable, Sendable { var json: String }
    struct Agent: Decodable, Sendable { var own: [String]?; var ops: [String]? }
    struct Control: Decodable, Sendable { var v: Int; var ops: [String] }
    struct Events: Decodable, Sendable { var schema: Int?; var names: [String] }
    var schema: Int
    var version: String
    var contract: Int
    var commands: [String: Command]
    var control: Control
    var agent: Agent?
    var events: Events?

    /// Newer CLIs explain why a local launch has not linked yet. Older CLIs (1.67.12 and before)
    /// don't advertise the event, and the app falls back to its own timer.
    var supportsLinkWaitEvent: Bool {
        supportsLocalBrowser && events?.names.contains(CLIInvocation.linkWaitEvent) == true
    }

    /// `approvals --json --watch` and `decide --json` (slicc-cli#801, v1.68.0). Seven support is reported by the commands' exits.
    var supportsApprovals: Bool {
        commands["approvals"]?.json == "events" && commands["decide"]?.json == "events" &&
        (agent?.ops.map { ["approvals", "decide"].allSatisfy($0.contains) } ?? true)
    }

    var supportsCredentialLeases: Bool {
        schema == 1 && contract == 1 && control.v == 1 &&
        ["leases", "unseal", "seal-off", "seal-on"].allSatisfy(control.ops.contains)
    }

    var supportsResumableWatch: Bool {
        supportsRemoteWorkspace && commands["watch"]?.json == "events" &&
        ["opened", "reconnecting"].allSatisfy { agent?.own?.contains($0) == true }
    }

    var supportsLocalBrowser: Bool {
        supportsRemoteWorkspace && commands["default"]?.json == "events"
    }

    var supportsRemoteWorkspace: Bool {
        schema == 1 && contract == 1 && control.v == 1 && control.ops.contains("detach") &&
        ["follow", "prompt"].allSatisfy { commands[$0]?.json == "events" } && commands["abort"] != nil
    }
}

struct CLIInvocation: Sendable {
    var arguments: [String]
    var input: Data = Data()

    /// The origin of every SLICC tab the app opens, inventories and activates.
    static let localOrigin = "https://www.sliccy.ai"
    /// The CLI's documented page in SLICC six's profile, where six upgrades in place.
    /// The bare origin redirects (to sliccy.com without six's service worker), so never open it directly.
    static let localPage = "https://www.sliccy.ai/7/"
    /// Lifecycle event a newer CLI emits while it has no seven target ready to link.
    static let linkWaitEvent = "waiting"

    static func usesSixHome(_ profile: String) -> Bool { profile == "six" || profile.hasPrefix("six:") }

    static func localBrowser(profile: String, browser: LocalBrowserChoice = .chrome, access: LocalAccessOptions = .init(), offerCredentials: Bool = false) -> Self {
        // In six's profile the CLI picks its own page and only adopts tabs on its app
        // routes; an explicit --page would make it accept any tab on the origin.
        // --origin keeps the accepted origin explicit without changing the page.
        let page = usesSixHome(profile) ? ["--origin", localOrigin] : ["--page", localPage]
        var arguments = ["--browser", browser.rawValue, "--profile", profile] + page +
                        ["--json", "--keep-browsers", "--no-fallback"]
        if !offerCredentials { arguments.append("--no-jerk") }
        if !access.network {
            arguments += ["--no-kernel", "--deny", LocalAccessOptions.blockedNetworks.joined(separator: ",")]
        }
        if access.shell {
            arguments += [access.sftp ? "--sftp" : "--no-sftp", "--runner", "/bin/zsh", "-c", "--"]
        }
        return .init(arguments: arguments)
    }

    static func agents(cdp: String) -> Self {
        .init(arguments: ["agents", "--cdp", cdp, "--origin", localOrigin, "--json", "--watch"])
    }

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
    static func approvals(join: String) -> Self {
        .init(arguments: ["-", "approvals", "--json", "--watch"], input: Data((join + "\n").utf8))
    }
    static func approvals(cdp: String) -> Self {
        .init(arguments: ["approvals", "--cdp", cdp, "--origin", localOrigin, "--json", "--watch"])
    }
    /// Flags come before the id and answer; `--` ends them, so an id is never read as a flag.
    static func decide(join: String, id: String, answer: ApprovalAnswer) -> Self {
        .init(arguments: ["-", "decide", "--json", "--", id, answer.rawValue], input: Data((join + "\n").utf8))
    }
    static func decide(cdp: String, id: String, answer: ApprovalAnswer) -> Self {
        .init(arguments: ["decide", "--cdp", cdp, "--origin", localOrigin, "--json", "--", id, answer.rawValue])
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

/// Splits the CLI's human stderr into short, printable status lines.
/// Bounded: a raw line longer than 8 KiB is dropped whole, so no partial text is shown.
/// Each complete line is redacted before it is cleaned and cut to `lineLimit`, so a
/// secret can't survive as a truncated prefix. Text is display-only and never controls state.
struct CLIStatusLines {
    static let lineLimit = 240
    static let byteLimit = 8 * 1024
    var redact: @Sendable (String) -> String = { $0 }
    private var buffer = Data()
    private var skipping = false

    init(redact: @escaping @Sendable (String) -> String = { $0 }) { self.redact = redact }

    mutating func append(_ data: Data) -> [String] {
        var lines: [String] = []
        for byte in data {
            if byte == 10 {
                if !skipping, let line = clean(buffer) { lines.append(line) }
                buffer.removeAll(keepingCapacity: true)
                skipping = false
            } else if !skipping {
                buffer.append(byte)
                if buffer.count > Self.byteLimit {
                    buffer.removeAll(keepingCapacity: true)
                    skipping = true
                }
            }
        }
        return lines
    }

    mutating func finish() -> [String] {
        defer { buffer.removeAll(); skipping = false }
        return skipping ? [] : clean(buffer).map { [$0] } ?? []
    }

    func clean(_ bytes: Data) -> String? {
        // Redact the whole raw line first, and again after control characters are removed.
        var text = redact(String(decoding: bytes, as: UTF8.self))
        // Drop ANSI escapes and other control characters before display.
        text = text.replacingOccurrences(of: "\u{1B}\\[[0-9;?]*[ -/]*[@-~]", with: "", options: .regularExpression)
        text = String(text.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) || $0 == "\t" }
            .map(Character.init)).replacingOccurrences(of: "\t", with: " ")
        text = redact(text).trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("slicc: ") { text.removeFirst("slicc: ".count) }
        // The app pins its bundled CLI; its self-update hint is not a connection status.
        guard !text.isEmpty, !text.hasSuffix("run `slicc update`") else { return nil }
        return text.count > Self.lineLimit ? String(text.prefix(Self.lineLimit - 1)) + "…" : text
    }
}

/// Asks a child to capture stderr as status lines. `changed` is called at most once
/// per drain, so a noisy child cannot queue unbounded main-actor work.
struct CLIStatusCapture: Sendable {
    var redact: @Sendable (String) -> String = { $0 }
    var changed: @Sendable () -> Void = {}
}

/// Thread-safe, bounded hand-off of status lines from the stderr reader.
final class CLIStatusBuffer: @unchecked Sendable {
    static let keep = 3
    private let lock = NSLock()
    private var recentLines: [String] = []
    private var pendingLines: [String] = []
    private var scheduled = false

    /// The newest lines, complete once the stream has finished.
    var recent: [String] { lock.withLock { recentLines } }

    /// Returns true when the consumer has to be woken for a drain.
    func push(_ lines: [String]) -> Bool {
        guard !lines.isEmpty else { return false }
        return lock.withLock {
            recentLines = Array((recentLines + lines).suffix(Self.keep))
            pendingLines = Array((pendingLines + lines).suffix(Self.keep))
            defer { scheduled = true }
            return !scheduled
        }
    }

    func drain() -> [String] {
        lock.withLock {
            defer { pendingLines = []; scheduled = false }
            return pendingLines
        }
    }

    private let finished = DispatchSemaphore(value: 0)
    /// Called by the stderr reader once its last line is buffered.
    func finish() { finished.signal() }
    /// Blocks the calling reader thread (never the main actor) until stderr is drained.
    func waitUntilFinished(seconds: Double) { _ = finished.wait(timeout: .now() + seconds) }
}

/// Owns one child process. Pipe reads and writes run off the UI thread.
/// Only the JSON contract controls UI state. Human stderr is drained to /dev/null
/// unless the caller asks for bounded status lines to display.
@MainActor
final class CLIProcess {
    private let process = Process()
    private let output = Pipe()
    private let input = Pipe()
    private var reader: Task<Void, Never>?
    private var statusReader: Task<Void, Never>?
    /// Present when stderr is captured.
    private(set) var status: CLIStatusBuffer?
    private var timeout: Task<Void, Never>?
    var runningPID: Int32? { process.isRunning ? process.processIdentifier : nil }

    func start(executable: String, invocation: CLIInvocation, deadline: Duration? = nil,
               status capture: CLIStatusCapture? = nil) throws -> AsyncThrowingStream<Data, Error> {
        guard FileManager.default.isExecutableFile(atPath: executable) else { throw CLIError.missing }
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = invocation.arguments
        process.standardOutput = output
        let errors = capture.map { _ in Pipe() }
        process.standardError = errors ?? FileHandle.nullDevice
        process.standardInput = input
        try process.run()
        // Close the parent's duplicates, so EOF follows child exit.
        try? output.fileHandleForWriting.close()
        try? input.fileHandleForReading.close()
        let buffer = capture.map { _ in CLIStatusBuffer() }
        status = buffer
        if let errors, let capture, let buffer {
            try? errors.fileHandleForWriting.close()
            let handle = errors.fileHandleForReading
            // Always drain, so a blocked stderr write can never stall the child.
            statusReader = Task.detached {
                defer { try? handle.close(); buffer.finish() }
                var lines = CLIStatusLines(redact: capture.redact)
                while true {
                    let bytes = handle.availableData
                    if bytes.isEmpty { break }
                    if buffer.push(lines.append(bytes)) { capture.changed() }
                }
                if buffer.push(lines.finish()) { capture.changed() }
            }
        }
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
                    // Report exit only after the final stderr line is buffered. A descendant
                    // that inherited stderr can hold it open, so don't wait for long.
                    buffer?.waitUntilFinished(seconds: 1)
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
