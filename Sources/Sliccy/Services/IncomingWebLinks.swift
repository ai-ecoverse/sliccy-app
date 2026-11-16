import Foundation

/// A bounded, memory-only queue. URLs never go through the OS default handler again.
@MainActor final class IncomingWebLinks {
    typealias Open = @MainActor (URL) async throws -> Void
    private var pending: [URL] = []
    private var task: Task<Void, Never>?
    private var inFlight = false
    private let open: Open
    private let report: @MainActor (String) -> Void

    init(open: @escaping Open, report: @escaping @MainActor (String) -> Void) {
        self.open = open
        self.report = report
    }
    nonisolated static func accepts(_ url: URL) -> Bool {
        ["http", "https"].contains(url.scheme?.lowercased() ?? "") &&
            !(url.host ?? "").isEmpty && url.user == nil && url.password == nil &&
            url.absoluteString.utf8.count <= 16_384 &&
            !url.absoluteString.unicodeScalars.contains { CharacterSet.controlCharacters.contains($0) }
    }
    func receive(_ urls: [URL]) {
        guard urls.allSatisfy(Self.accepts) else {
            report("Sliccy opens HTTP and HTTPS web links only, without embedded credentials.")
            return
        }
        guard pending.count + (inFlight ? 1 : 0) + urls.count <= 32 else {
            report("Too many links arrived at once. Open them in smaller groups.")
            return
        }
        pending.append(contentsOf: urls)
        guard task == nil else { return }
        task = Task { [weak self] in
            guard let self else { return }
            defer { self.task = nil; self.inFlight = false }
            while !self.pending.isEmpty, !Task.isCancelled {
                let url = self.pending.removeFirst()
                self.inFlight = true
                do { try await self.open(url) }
                catch {
                    self.pending.removeAll()
                    if !Task.isCancelled { self.report("The link could not be opened in the selected SLICC browser. Check its connection and try the link again. It was not sent to another browser.") }
                    return
                }
                self.inFlight = false
            }
        }
    }
    func cancel() { pending.removeAll(); task?.cancel() }
    func waitUntilIdle() async { await task?.value }
}
