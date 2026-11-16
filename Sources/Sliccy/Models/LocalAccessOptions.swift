import Foundation

/// Requested settings, distinct from the live capability report. No automatic reconnect on launch.
struct LocalAccessOptions: Codable, Equatable, Sendable {
    var network = true
    var shell = false
    var sftp = false

    // The CLI uses longest-prefix policy matching. Override its more-specific local
    // allow rules as well as the two default routes; /0 alone does NOT block LAN access.
    static let blockedNetworks = ["0.0.0.0/0", "::/0", "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
    static let localPolicy = "every public address, this machine, and the local network"
    static let blockedPolicy = localPolicy + "; also denies " + blockedNetworks.joined(separator: ", ")

    func resources(from event: CLIEvent, browser: CLIResources.Browser?) -> CLIResources? {
        guard event.kind == "linked", let caps = event.caps, let policy = event.policy else { return nil }
        // Only report a policy state understood by this adapter. Never show a requested
        // reduction as effective just because we passed a command-line flag.
        guard policy == Self.localPolicy || policy == Self.blockedPolicy else { return nil }
        return .init(jerk: .init(offered: caps.contains("jerk"), seal: caps.contains("jerk-seal")),
                     browsers: caps.contains("cdp") ? browser.map { [$0] } ?? [] : [],
                     mounts: [], rejectedMounts: [],
                     network: .init(exit: caps.contains("net") && policy == Self.localPolicy, policy: policy),
                     compute: .init(ssh: caps.contains("ssh"), sftp: caps.contains("ssh") && shell && sftp))
    }
}
