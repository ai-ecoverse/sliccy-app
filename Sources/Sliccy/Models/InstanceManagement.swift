import Foundation

/// Preview metadata only. Live inventory will come from seven and the credential broker.
/// This model deliberately has no field for a secret value.
struct InstanceManagement: Codable, Equatable {
    struct Agent: Identifiable, Codable, Equatable {
        var id: String
        var name: String
        var model: String
        var provider: String
        var running: Bool
    }
    struct Credential: Identifiable, Codable, Equatable {
        var id: String
        var name: String
        var provider: String
        var source: String
        var scope: String
        var delivery: String
        var enabled: Bool
    }
    var agents: [Agent]
    var credentials: [Credential]
    var screenTarget: String?

    static func sample(for kind: SessionKind) -> Self {
        .init(agents: [
            .init(id: "coordinator", name: "Coordinator", model: "GPT-6.1", provider: "OpenAI", running: true),
            .init(id: "reviewer", name: kind == .remote ? "Researcher" : "Browser reviewer", model: "Claude Sonnet", provider: "Anthropic", running: true),
            .init(id: "worker", name: "Code worker", model: "GPT-6.1", provider: "OpenAI", running: false)
        ], credentials: [
            .init(id: "openai", name: "Project API key", provider: "OpenAI", source: "Seven vault", scope: "Coordinator, Code worker", delivery: "Provider requests", enabled: true),
            .init(id: "anthropic", name: "Team API key", provider: "Anthropic", source: "Seven vault", scope: kind == .remote ? "Researcher" : "Browser reviewer", delivery: "Provider requests", enabled: true),
            .init(id: "github", name: "Repository access", provider: "GitHub", source: "Mac credential broker", scope: "Code worker · example/website", delivery: "Expiring lease", enabled: false)
        ])
    }
}

extension Session {
    var managementSnapshot: InstanceManagement? {
        isLive ? nil : management ?? .sample(for: kind)
    }
    var runningAgentCount: Int? {
        guard let snapshot = managementSnapshot else { return nil }
        return connection == .connected ? snapshot.agents.filter(\.running).count : 0
    }
}
