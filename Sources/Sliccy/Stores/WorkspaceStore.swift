import Foundation
import Observation

@MainActor @Observable
final class WorkspaceStore {
    var sessions: [Session]
    var showNewSession = false
    var requestedSelection: UUID?
    var newSessionBrowser: String?
    var errorMessage: String?
    @ObservationIgnored private let runtime: any SessionRuntime
    @ObservationIgnored private let defaults: UserDefaults?
    @ObservationIgnored var runs: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored var connections: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored var generations: [UUID: UUID] = [:]
    var cliExecutable: String {
        didSet { defaults?.set(cliExecutable, forKey: "sliccy.cli.path"); cliVersion = nil }
    }
    var aborting: Set<UUID> = []
    @ObservationIgnored var feedSave: Task<Void, Never>?
    @ObservationIgnored var watchSupported: Set<UUID> = []
    @ObservationIgnored var watchProcesses: [UUID: CLIProcess] = [:]
    @ObservationIgnored var watchTasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored var watchTokens: [UUID: UUID] = [:]
    @ObservationIgnored var abortProcesses: [UUID: CLIProcess] = [:]
    var cliVersion: String?
    var checkingCLI = false
    var credentialAccess: [UUID: CredentialAccess] = [:]
    var leaseSupported: Set<UUID> = []
    var credentialOffers: Set<UUID> = []
    var inventories: [UUID: AgentInventory] = [:]
    @ObservationIgnored var inventorySupported: Set<UUID> = []
    @ObservationIgnored var inventoryProcesses: [UUID: CLIProcess] = [:]
    @ObservationIgnored var inventoryTasks: [UUID: Task<Void, Never>] = [:]
    @ObservationIgnored var inventoryTokens: [UUID: UUID] = [:]
    @ObservationIgnored var credentialTasks: [UUID: Task<Void, Never>] = [:]
    var credentialSession: UUID?
    @ObservationIgnored var joinCredentials: [UUID: String] = [:]
    @ObservationIgnored var liveProcesses: [UUID: CLIProcess] = [:]
    @ObservationIgnored var promptProcesses: [UUID: CLIProcess] = [:]
    @ObservationIgnored var liveTokens: [UUID: UUID] = [:]
    @ObservationIgnored var liveExecutables: [UUID: String] = [:]
    private static let storageKey = "sliccy.demo.sessions.v1"

    init(runtime: any SessionRuntime = MockRuntime(), defaults: UserDefaults? = .standard) {
        self.runtime = runtime
        self.defaults = defaults
        self.cliExecutable = defaults?.string(forKey: "sliccy.cli.path") ?? CLIClient.defaultExecutable
        if let data = defaults?.data(forKey: Self.storageKey),
           let saved = try? JSONDecoder().decode([Session].self, from: data) {
            sessions = saved.map { session in
                var restored = session
                if restored.isWorking {
                    restored.entries.append(.init(role: .notice, text: restored.isLive ? "Activity stream ended when Sliccy closed. The agent may still be running in seven." : "Demo run interrupted when the app closed."))
                }
                restored.management?.screenTarget = nil
                restored.isWorking = false
                restored.queuedPrompts = []
                if restored.isLive || restored.connection == .connecting || restored.connection == .reconnecting {
                    restored.connection = .disconnected
                }
                if restored.isLive {
                    restored.liveFeed?.state = .stopped
                    restored.liveFeed?.busy = nil
                    restored.liveFeed?.retryDelay = nil
                    restored.effectiveResources = nil
                    restored.access = .init(browser: nil, network: false)
                }
                return restored
            }
        } else { sessions = DemoData.sessions() }
    }

    var isDemo: Bool { runtime.isDemo }
    var connectedCount: Int { sessions.filter { $0.connection == .connected }.count }
    var workingCount: Int { sessions.filter(\.isWorking).count }
    func session(_ id: UUID) -> Session? { sessions.first { $0.id == id } }

    func update(_ id: UUID, _ change: (inout Session) -> Void) {
        guard let index = sessions.firstIndex(where: { $0.id == id }) else { return }
        change(&sessions[index])
    }

    func save() {
        guard let data = try? JSONEncoder().encode(sessions) else { return }
        defaults?.set(data, forKey: Self.storageKey)
    }

    func create(name: String, kind: SessionKind, browser: String, profile: String) -> UUID {
        let session = Session(name: name.trimmingCharacters(in: .whitespacesAndNewlines), device: kind == .remote ? "Remote Mac" : "This Mac", kind: kind, profile: profile, connection: .disconnected, access: .init(browser: kind == .browser ? browser : nil))
        sessions.append(session)
        requestedSelection = session.id
        reconnect(session.id)
        return session.id
    }

    func startNew(browser: String? = nil) {
        newSessionBrowser = browser
        showNewSession = true
    }

    func reconnect(_ id: UUID) {
        guard let session = session(id), session.connection == .disconnected else { return }
        if session.isLive {
            guard joinCredentials[id] != nil else { credentialSession = id; return }
            connectLive(id)
            return
        }
        update(id) { $0.connection = .connecting }
        connections[id] = Task { [weak self] in
            do { try await Task.sleep(for: .milliseconds(700)) } catch { return }
            guard let self, self.session(id) != nil else { return }
            self.update(id) {
                $0.connection = .connected
                $0.entries.append(.init(role: .notice, text: "Demo connection ready. No resources are shared."))
            }
            self.connections[id] = nil
            self.save()
        }
    }

    func disconnect(_ id: UUID) {
        if session(id)?.isLive == false { setDemoScreen(nil, for: id) }
        if session(id)?.isLive == true { disconnectLive(id); return }
        connections[id]?.cancel()
        connections[id] = nil
        cancelStream(id)
        update(id) {
            $0.connection = .disconnected
            $0.isWorking = false
            $0.queuedPrompts = []
            $0.entries.append(.init(role: .notice, text: "Disconnected from the demo. In a live session, disconnecting does not abort seven’s agent."))
        }
        save()
    }

    func send(_ text: String, to id: UUID, mode: DeliveryMode = .followUp) {
        let prompt = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !aborting.contains(id), !prompt.isEmpty, let session = session(id), session.connection == .connected else { return }
        guard prompt.utf8.count <= 16 * 1024 * 1024 else { errorMessage = "Prompts must be smaller than 16 MiB."; return }
        update(id) {
            $0.draft = ""
            $0.entries.append(.init(role: .user, text: prompt))
            $0.lastActivity = Date()
        }
        if session.isWorking && mode == .followUp {
            update(id) { $0.queuedPrompts.append(prompt) }
            save()
            return
        }
        if session.isWorking {
            cancelStream(id)
            update(id) { $0.entries.append(.init(role: .notice, text: session.isLive ? "Sending a new direction to seven." : "Steering the simulated response with your latest message.")) }
        }
        begin(prompt, id: id, steer: session.isWorking && mode == .steer)
    }

    func begin(_ prompt: String, id: UUID, steer: Bool = false) {
        guard let session = session(id) else { return }
        if session.isLive { beginLivePrompt(prompt, id: id, steer: steer); return }
        let generation = UUID()
        generations[id] = generation
        update(id) { $0.isWorking = true }
        let stream = runtime.response(to: prompt, sessionName: session.name)
        runs[id] = Task { [weak self] in
            var assistantID: UUID?
            for await event in stream {
                guard !Task.isCancelled, let self, self.generations[id] == generation else { return }
                switch event {
                case .tool(let text):
                    self.update(id) { $0.entries.append(.init(role: .tool, text: text)) }
                case .text(let delta):
                    if let entryID = assistantID {
                        self.update(id) { session in
                            if let index = session.entries.firstIndex(where: { $0.id == entryID }) {
                                session.entries[index].text += delta
                            }
                        }
                    } else {
                        let entry = ActivityEntry(role: .assistant, text: delta)
                        assistantID = entry.id
                        self.update(id) { $0.entries.append(entry) }
                    }
                case .completed: break
                }
            }
            guard !Task.isCancelled, let self, self.generations[id] == generation else { return }
            self.update(id) { $0.isWorking = false }
            self.runs[id] = nil
            if let next = self.session(id)?.queuedPrompts.first {
                self.update(id) { $0.queuedPrompts.removeFirst() }
                self.begin(next, id: id)
            }
            self.save()
        }
        save()
    }

    func stop(_ id: UUID) {
        if session(id)?.isLive == true { abortLive(id); return }
        guard session(id)?.isWorking == true else { return }
        cancelStream(id)
        update(id) {
            $0.isWorking = false
            $0.queuedPrompts = []
            $0.entries.append(.init(role: .notice, text: "Demo response stopped. Queued follow-ups were cleared."))
        }
        save()
    }

    func cancelStream(_ id: UUID) {
        promptProcesses.removeValue(forKey: id)?.terminate()
        generations[id] = nil
        runs[id]?.cancel()
        runs[id] = nil
    }

    func applyAccess(_ access: SessionAccess, to id: UUID) {
        guard session(id)?.isWorking == false, session(id)?.isLive == false else { return }
        update(id) {
            $0.access = access
            $0.entries.append(.init(role: .notice, text: "Demo access settings updated. No real permissions changed."))
        }
        save()
    }

    func remove(_ id: UUID) {
        if session(id)?.isLive == true { disconnectLive(id); joinCredentials[id] = nil }
        cancelStream(id)
        connections[id]?.cancel()
        connections[id] = nil
        sessions.removeAll { $0.id == id }
        save()
    }

    func resetDemo() {
        for session in sessions where !session.isLive {
            cancelStream(session.id)
            connections.removeValue(forKey: session.id)?.cancel()
        }
        sessions = sessions.filter(\.isLive) + DemoData.sessions()
        requestedSelection = sessions.first?.id
        save()
    }
}
