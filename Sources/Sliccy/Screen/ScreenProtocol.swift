import Foundation
import Security

enum ScreenID {
    static func make(bytes count: Int = 16) throws -> String {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        return encode(Data(bytes))
    }
    static func encode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    static func decode(_ string: String, bytes: Int) throws -> Data {
        let base = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard let data = Data(base64Encoded: base + String(repeating: "=", count: (4 - base.count % 4) % 4)),
              data.count == bytes, encode(data) == string else { throw ScreenFailure.incompatible }
        return data
    }
    static func counter(_ string: String) throws -> UInt64 {
        guard !string.isEmpty, string.utf8.count <= 20, string.utf8.allSatisfy({ (48...57).contains($0) }),
              string == "0" || !string.hasPrefix("0"), let value = UInt64(string) else { throw ScreenFailure.incompatible }
        return value
    }
}

struct ScreenBinding: Codable, Equatable, Sendable {
    var link: String
    var session: String
    var source: String
    var grantEpoch: String
    var sourceEpoch: String
    var protectionEpoch: String
    func validate() throws {
        for value in [link, session, source] { _ = try ScreenID.decode(value, bytes: 16) }
        for value in [grantEpoch, sourceEpoch, protectionEpoch] {
            guard try ScreenID.counter(value) > 0 else { throw ScreenFailure.incompatible }
        }
    }
}

struct ScreenLimits: Codable, Equatable, Sendable {
    var headerBytes = 4096
    var frameBytes = 2_097_152
    var longEdge = 2560
    var pixels = 4_000_000
    var defaultFps = 5
    var maxFps = 10
    var bytesPerSecond = 8_388_608
    func validate() throws {
        guard (1...4096).contains(headerBytes), (1...2_097_152).contains(frameBytes),
              (1...2560).contains(longEdge), (1...4_000_000).contains(pixels),
              (1...10).contains(maxFps), (1...maxFps).contains(defaultFps),
              (1...8_388_608).contains(bytesPerSecond) else { throw ScreenFailure.incompatible }
    }
}

struct ScreenBootstrap: Codable, Sendable {
    var v = 1
    var launch: String
    var safetyPath: String
    var framesPath: String
    var challenge: String
    var parentAuditToken: String
}

struct ScreenHello: Codable, Sendable {
    var v: Int
    var lane: String
    var launch: String
    var challenge: String
    var clientNonce: String
    var serverNonce: String?
    var connection: String?
}

struct ScreenBrowserEvidence: Codable, Sendable {
    struct Host: Codable, Sendable { var auditToken: String; var bundleIdentifier: String }
    var location: String
    var provenance: String
    var hosts: [Host]
}
struct ScreenRecipient: Codable, Equatable, Sendable { var fingerprint: String; var setup: String }

struct ScreenSafety: Codable, Sendable {
    var type: String
    var v = 1
    var launch: String
    var connection: String
    var seq: String?
    var echo: String?
    var link: String?
    var session: String?
    var recipient: ScreenRecipient?
    var browserEvidence: ScreenBrowserEvidence?
    var request: String?
    var binding: ScreenBinding?
    var scope: String?
    var limits: ScreenLimits?
    var reason: String?

    func data() throws -> Data {
        var object = try ScreenJSON.object(JSONEncoder().encode(self))
        if type == "revoke" || type == "revoked" {
            object["link"] = link as Any? ?? NSNull()
            object["session"] = session as Any? ?? NSNull()
        }
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }

    static func decode(_ data: Data) throws -> Self {
        let object = try ScreenJSON.object(data)
        guard let type = object["type"] as? String else { throw ScreenFailure.incompatible }
        let extra: [String]
        switch type {
        case "heartbeat": extra = ["seq", "echo"]
        case "link": extra = ["link", "recipient", "browserEvidence"]
        case "grant": extra = ["request", "binding", "scope", "limits"]
        case "granted": extra = ["request", "binding"]
        case "revoke": extra = ["request", "link", "session", "reason"]
        case "revoked": extra = ["request", "link", "session"]
        default: throw ScreenFailure.incompatible
        }
        try ScreenJSON.keys(object, exact: ["type", "v", "launch", "connection"] + extra)
        if let binding = object["binding"] as? [String: Any] {
            try ScreenJSON.keys(binding, exact: ["link", "session", "source", "grantEpoch", "sourceEpoch", "protectionEpoch"])
        }
        if let limits = object["limits"] as? [String: Any] {
            try ScreenJSON.keys(limits, exact: ["headerBytes", "frameBytes", "longEdge", "pixels", "defaultFps", "maxFps", "bytesPerSecond"])
        }
        if let recipient = object["recipient"] as? [String: Any] { try ScreenJSON.keys(recipient, exact: ["fingerprint", "setup"]) }
        if let evidence = object["browserEvidence"] as? [String: Any] {
            try ScreenJSON.keys(evidence, exact: ["location", "provenance", "hosts"])
            guard let hosts = evidence["hosts"] as? [[String: Any]], hosts.count <= 8 else { throw ScreenFailure.incompatible }
            for host in hosts { try ScreenJSON.keys(host, exact: ["auditToken", "bundleIdentifier"]) }
        }
        let result = try JSONDecoder().decode(Self.self, from: data)
        guard result.v == 1 else { throw ScreenFailure.incompatible }
        _ = try ScreenID.decode(result.launch, bytes: 32)
        _ = try ScreenID.decode(result.connection, bytes: 32)
        if let request = result.request { _ = try ScreenID.decode(request, bytes: 16) }
        if let link = result.link { _ = try ScreenID.decode(link, bytes: 16) }
        if let session = result.session { _ = try ScreenID.decode(session, bytes: 16) }
        try result.binding?.validate(); try result.limits?.validate()
        switch type {
        case "heartbeat":
            guard let seq = result.seq, let echo = result.echo, try ScreenID.counter(seq) > 0 else { throw ScreenFailure.incompatible }
            _ = try ScreenID.counter(echo)
        case "link":
            guard result.link != nil, let recipient = result.recipient, let evidence = result.browserEvidence,
                  recipient.fingerprint.utf8.count == 64,
                  recipient.fingerprint.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  ["cdp", "loopback", "hub"].contains(recipient.setup) else { throw ScreenFailure.incompatible }
            switch evidence.location {
            case "local":
                guard !evidence.hosts.isEmpty, ["cdp-owner", "loopback-owner", "native-verified"].contains(evidence.provenance) else { throw ScreenFailure.incompatible }
            case "remote":
                guard evidence.hosts.isEmpty, evidence.provenance == "native-verified" else { throw ScreenFailure.incompatible }
            case "unknown":
                guard evidence.hosts.isEmpty, evidence.provenance == "unresolved" else { throw ScreenFailure.incompatible }
            default: throw ScreenFailure.incompatible
            }
            for host in evidence.hosts {
                _ = try ScreenAuditIdentity(encoded: host.auditToken)
                guard !host.bundleIdentifier.isEmpty, host.bundleIdentifier.utf8.count <= 255,
                      host.bundleIdentifier.utf8.allSatisfy({ (33...126).contains($0) }) else { throw ScreenFailure.incompatible }
            }
        case "grant":
            guard result.request != nil, result.binding != nil, result.limits != nil,
                  ["window", "display"].contains(result.scope ?? "") else { throw ScreenFailure.incompatible }
        case "granted":
            guard result.request != nil, result.binding != nil else { throw ScreenFailure.incompatible }
        case "revoke":
            guard result.request != nil, let reason = result.reason,
                  ScreenFailure(rawValue: reason) != nil || ["awaiting-consent", "paused"].contains(reason) else { throw ScreenFailure.incompatible }
        case "revoked":
            guard result.request != nil else { throw ScreenFailure.incompatible }
        default: throw ScreenFailure.incompatible
        }
        return result
    }
}

struct ScreenFrameHeader: Codable, Sendable {
    var type = "frame"
    var v = 1
    var binding: ScreenBinding
    var frameSeq: String
    var capturedMonoMs: String
    var width: Int
    var height: Int
    var codec = "jpeg"
    var launch: String
    var connection: String
}
