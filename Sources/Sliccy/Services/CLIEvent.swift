import Foundation

/// The CLI has two event families: lifecycle `event` and agent `t`.
/// Transcript entry IDs are opaque strings, not run IDs. Unknown events are retained.
struct CLIEvent: Decodable, Equatable, Sendable {
    var schema: Int?
    var event: String?
    var t: String?
    var id: String?
    var text: String?
    var delta: String?
    var message: String?
    var state: String?
    var reason: String?
    var gap: Bool?
    var head: String?
    var busy: Bool?
    var wait: CLIRetryDelay?
    var caps: [String]?
    var retryable: Bool?
    var code: String?
    var attempt: Int?
    var summary: String?
    var name: String?
    var resources: CLIResources?
    var op: String?
    var provider: String?
    var leaseId: String?
    var expiresAt: String?
    var by: String?
    var upstream: Bool?
    var v: Int?
    var agents: [InventoryAgent]?
    var instance: InventoryInstance?
    var counts: [String: Int]?
    var seq: UInt64?
    var reportedAt: InventoryTime?
    var receivedAt: InventoryTime?
    var kind: String { event ?? t ?? "unknown" }
}

/// Accepts arbitrary pipe boundaries and UTF-8 splits, not just one read per line.
struct NDJSONDecoder {
    private var buffer = Data()
    private let limit = 16 * 1024 * 1024
    enum Failure: Error { case lineTooLong }

    mutating func append(_ data: Data) throws -> [CLIEvent] {
        buffer.append(data)
        var events: [CLIEvent] = []
        while let end = buffer.firstIndex(of: 10) {
            guard buffer.distance(from: buffer.startIndex, to: end) <= limit else { throw Failure.lineTooLong }
            let line = buffer[..<end]
            if !line.allSatisfy({ $0 == 13 || $0 == 32 || $0 == 9 }) {
                events.append(try JSONDecoder().decode(CLIEvent.self, from: Data(line)))
            }
            buffer.removeSubrange(...end)
        }
        guard buffer.count <= limit else { throw Failure.lineTooLong }
        return events
    }

    mutating func finish() throws -> [CLIEvent] {
        guard !buffer.isEmpty else { return [] }
        return try append(Data([10]))
    }
}

struct CLIResources: Codable, Equatable, Sendable {
    struct Browser: Codable, Equatable, Sendable { var id: String; var name: String; var role: String; var owned: Bool }
    struct Mount: Codable, Equatable, Sendable { var name: String; var path: String; var readOnly: Bool }
    struct Rejection: Codable, Equatable, Sendable { var path: String; var reason: String }
    struct Network: Codable, Equatable, Sendable { var exit: Bool; var policy: String }
    struct Compute: Codable, Equatable, Sendable { var ssh: Bool; var sftp: Bool }
    struct Broker: Codable, Equatable, Sendable { var offered: Bool; var seal: Bool }
    var jerk: Broker?
    var browsers: [Browser]
    var mounts: [Mount]
    var rejectedMounts: [Rejection]
    var network: Network
    var compute: Compute

    var access: SessionAccess {
        .init(browser: browsers.isEmpty ? nil : browsers.map(\.name).joined(separator: ", "),
              folders: mounts.map { .init(name: $0.name, path: $0.path, readOnly: $0.readOnly) },
              network: network.exit, shell: compute.ssh, sftp: compute.sftp)
    }
}

/// Released events carry milliseconds. Golden fixtures replace timing with "<ms>".
/// Unknown future representations don't make the rest of the event undecodable.
struct CLIRetryDelay: Decodable, Equatable, Sendable {
    var milliseconds: Double?
    init(from decoder: any Decoder) throws {
        let value = try decoder.singleValueContainer()
        let number = (try? value.decode(Double.self)) ?? (try? value.decode(String.self)).flatMap(Double.init)
        milliseconds = number.flatMap { $0.isFinite && $0 >= 0 ? $0 : nil }
    }
}
