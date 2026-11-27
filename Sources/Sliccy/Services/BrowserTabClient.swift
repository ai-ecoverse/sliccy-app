import Foundation

/// Uses only the loopback endpoint reported by our local CLI.
/// Activates a SLICC tab or opens an explicitly delivered web or file URL in that profile; never evaluates JavaScript.
enum BrowserTabClient {
    struct Target: Decodable, Sendable { var id: String; var type: String; var url: String }
    enum Failure: LocalizedError {
        case missing, ambiguous, invalid
        var errorDescription: String? {
            switch self {
            case .missing: "The connected SLICC tab is no longer available. Reconnect and try again."
            case .ambiguous: "More than one matching SLICC tab is open. Close the duplicate before trying again."
            case .invalid: "Chrome did not confirm that the SLICC tab was activated."
            }
        }
    }
    static func isSLICCTab(_ value: String) -> Bool {
        guard let url = URL(string: value), url.scheme == "https", url.host == "www.sliccy.ai",
              url.user == nil, url.password == nil, url.port == nil || url.port == 443 else { return false }
        return ["", "/", "/7", "/7/", "/os", "/os/"].contains(url.path)
    }
    static func endpointURL(_ value: String) throws -> URL {
        guard let url = URL(string: value), url.scheme == "http",
              ["localhost", "127.0.0.1", "[::1]"].contains(url.host ?? ""),
              let port = url.port, (1...65535).contains(port), url.user == nil, url.password == nil,
              ["", "/"].contains(url.path), url.query == nil, url.fragment == nil else { throw Failure.invalid }
        return url
    }
    static func target(in data: Data, matching tabURL: String) throws -> Target {
        guard isSLICCTab(tabURL) else { throw Failure.invalid }
        let targets = try JSONDecoder().decode([Target].self, from: data)
        // Released CLI redacts the tab URL to its origin. Match only the known app
        // routes on that origin, and refuse duplicates rather than guessing a window.
        let matches = targets.filter { $0.type == "page" && isSLICCTab($0.url) && URL(string: $0.url)?.host == URL(string: tabURL)?.host }
        guard let target = matches.first else { throw Failure.missing }
        guard matches.count == 1 else { throw Failure.ambiguous }
        guard !target.id.isEmpty, target.id.utf8.count <= 128,
              target.id.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }) else { throw Failure.invalid }
        return target
    }
    static func activate(endpoint: String, tabURL: String) async throws {
        let root = try endpointURL(endpoint)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 4
        configuration.timeoutIntervalForResource = 6
        let session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(from: root.appending(path: "json/list"))
        guard (response as? HTTPURLResponse)?.statusCode == 200, data.count <= 2 * 1024 * 1024 else { throw Failure.invalid }
        let target = try target(in: data, matching: tabURL)
        let (_, activated) = try await session.data(from: root.appending(path: "json/activate/\(target.id)"))
        guard (activated as? HTTPURLResponse)?.statusCode == 200 else { throw Failure.invalid }
    }
    static func openRequest(_ url: URL, endpoint: String) throws -> URLRequest {
        guard IncomingWebLinks.accepts(url) else { throw Failure.invalid }
        let root = try endpointURL(endpoint)
        var components = URLComponents(url: root.appending(path: "json/new"), resolvingAgainstBaseURL: false)!
        // The CDP endpoint uses the entire query as the target URL, not key/value pairs.
        components.percentEncodedQuery = url.absoluteString.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        guard let destination = components.url else { throw Failure.invalid }
        var request = URLRequest(url: destination)
        request.httpMethod = "PUT"
        return request
    }
    static func open(_ url: URL, endpoint: String) async throws {
        let request = try openRequest(url, endpoint: endpoint)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 4
        configuration.timeoutIntervalForResource = 6
        let session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200, data.count <= 2 * 1024 * 1024,
              let target = try? JSONDecoder().decode(Target.self, from: data), target.type == "page", !target.id.isEmpty else { throw Failure.invalid }
    }
    private final class NoRedirect: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }
}
