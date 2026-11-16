import Foundation

/// Deliberately small, one-request HTTP/1.1 transport for the CLI's proxied fetch.
/// No CORS, redirects, chunked requests, request pipelining, or non-loopback Host values.
enum CuaHTTP {
    static let maximumHeader = 8 * 1024
    static let maximumBody = 1024 * 1024
    struct Request { let body: Data }
    struct Rejection: Error { let status: Int }

    static func parse(_ data: Data, port: UInt16, token: String) throws -> Request? {
        guard let separator = data.range(of: Data("\r\n\r\n".utf8)) else {
            if data.count > maximumHeader { throw Rejection(status: 431) }
            return nil
        }
        guard separator.lowerBound <= maximumHeader,
              let header = String(data: data[..<separator.lowerBound], encoding: .utf8) else { throw Rejection(status: 400) }
        let lines = header.components(separatedBy: "\r\n")
        guard lines.first == "POST /mcp/\(token) HTTP/1.1" else { throw Rejection(status: 404) }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), !line.hasPrefix(" "), !line.hasPrefix("\t") else { throw Rejection(status: 400) }
            let name = line[..<colon].lowercased()
            guard headers[name] == nil else { throw Rejection(status: 400) }
            headers[name] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard headers["host"] == "127.0.0.1:\(port)", headers["origin"] == nil,
              headers["transfer-encoding"] == nil, headers["expect"] == nil,
              headers["content-type"]?.split(separator: ";").first?.lowercased() == "application/json" else { throw Rejection(status: 403) }
        guard let raw = headers["content-length"], !raw.isEmpty, raw.allSatisfy(\.isASCII),
              raw.utf8.allSatisfy({ (48...57).contains($0) }), let length = Int(raw),
              length > 0, length <= maximumBody else { throw Rejection(status: 413) }
        let count = data.count - separator.upperBound
        guard count <= length else { throw Rejection(status: 400) }
        guard count == length else { return nil }
        return Request(body: Data(data[separator.upperBound...]))
    }

    static func response(status: Int, body: Data = Data()) -> Data {
        var output = Data("HTTP/1.1 \(status) \(status == 200 ? "OK" : "Response")\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".utf8)
        output.append(body)
        return output
    }
}
