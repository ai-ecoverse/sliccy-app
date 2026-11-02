import Foundation

enum RuntimeEvent: Sendable {
    case tool(String), text(String), completed
}

@MainActor
protocol SessionRuntime {
    var isDemo: Bool { get }
    func response(to prompt: String, sessionName: String) -> AsyncStream<RuntimeEvent>
}

@MainActor
final class MockRuntime: SessionRuntime {
    let isDemo = true

    func response(to prompt: String, sessionName: String) -> AsyncStream<RuntimeEvent> {
        AsyncStream { continuation in
            let task = Task { @MainActor in
                do {
                    try await Task.sleep(for: .milliseconds(450))
                    continuation.yield(.tool("Preparing a simulated response"))
                    let answer = "This is a preview response for **\(sessionName)**.\n\nYour message reached the demo runtime. In a connected session, Sliccy will stream seven’s response here, with tool activity alongside it.\n\nYou can try a follow-up, steer this response, or stop it. No browser, file, or shell access was used."
                    for word in answer.split(separator: " ", omittingEmptySubsequences: false) {
                        try Task.checkCancellation()
                        continuation.yield(.text(String(word) + " "))
                        try await Task.sleep(for: .milliseconds(55))
                    }
                    continuation.yield(.completed)
                    continuation.finish()
                } catch { continuation.finish() }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}
