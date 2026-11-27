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
    nonisolated static func accepts(_ url: URL, applicationSupport: URL = .applicationSupportDirectory) -> Bool {
        guard url.absoluteString.utf8.count <= 16_384, url.user == nil, url.password == nil,
              !url.absoluteString.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { return false }
        if url.isFileURL { return isGlobalProtectForm(url, in: applicationSupport) }
        return ["http", "https"].contains(url.scheme?.lowercased() ?? "") && !(url.host ?? "").isEmpty
    }

    /// GlobalProtect's SAML POST binding opens an auto-submitting HTML file, not a web URL.
    /// Check its location and metadata only. Let the browser submit the original form.
    private nonisolated static func isGlobalProtectForm(_ url: URL, in applicationSupport: URL) -> Bool {
        let name = url.lastPathComponent
        guard name.wholeMatch(of: /_samlpost_[0-9]+\.html/) != nil else { return false }
        let path = "PaloAltoNetworks/GlobalProtect/\(name)"
        let expected = applicationSupport.appending(path: path, directoryHint: .notDirectory)
        // Compare the whole URL: no other authority, path, query or fragment may reach the browser.
        let localhostURL = "file://localhost" + expected.path(percentEncoded: true)
        guard url.absoluteString == expected.absoluteString || url.absoluteString == localhostURL else { return false }
        let resolvedBase = applicationSupport.resolvingSymlinksInPath()
        guard expected.resolvingSymlinksInPath().path == resolvedBase.appending(path: path, directoryHint: .notDirectory).path else { return false }
        return (try? expected.resourceValues(forKeys: [.isRegularFileKey]))?.isRegularFile == true
    }

    func receive(_ urls: [URL]) {
        guard pending.count + (inFlight ? 1 : 0) + urls.count <= 32 else {
            report("Too many links arrived at once. Open them in smaller groups.")
            return
        }
        guard urls.allSatisfy({ Self.accepts($0) }) else {
            report("Sliccy can open HTTP and HTTPS links without embedded credentials, or a GlobalProtect sign-in form from its application support folder.")
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
