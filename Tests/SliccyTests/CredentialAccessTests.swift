import Foundation
import Testing
import Darwin
@testable import Sliccy

@MainActor
struct CredentialAccessTests {
    func fixture() throws -> [String: Data] {
        let data = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/credential.ndjson"))
        return try Dictionary(uniqueKeysWithValues: data.split(separator: 10).map { line in
            let object = try #require(JSONSerialization.jsonObject(with: Data(line)) as? [String: Any])
            return (try #require(object["step"] as? String), try JSONSerialization.data(withJSONObject: #require(object["line"])))
        })
    }

    @Test func releasedLeaseEventsPreserveRevocationMeaning() throws {
        let lines = try fixture()
        var state = CredentialAccess()
        state.apply(try JSONDecoder().decode(CLIEvent.self, from: #require(lines["seal github"])))
        #expect(state.leases.map(\.provider) == ["github"])
        #expect(!state.complete)
        state.apply(try JSONDecoder().decode(CLIEvent.self, from: #require(lines["unseal by seven"])))
        #expect(state.leases.isEmpty)
        #expect(state.message?.contains("remains valid until expiry") == true)
        state.apply(try JSONDecoder().decode(CLIEvent.self, from: #require(lines["revoked"])))
        #expect(state.message?.contains("confirmed provider revocation") == true)
        #expect(state.message?.contains("not confirmed") == true)
        #expect(CredentialAccess.revocationMessage(upstream: nil).contains("unconfirmed"))
    }

    @Test func unknownCredentialEventsCannotWithdrawKnownLeases() throws {
        var state = CredentialAccess()
        let seal = try JSONDecoder().decode(CLIEvent.self, from: Data(#"{"schema":1,"event":"credential","op":"seal","by":"seven","provider":"github","leaseId":"one"}"#.utf8))
        state.apply(seal)
        var future = seal; future.op = "unknown"
        state.apply(future)
        future.op = "revoked"; future.schema = 2
        state.apply(future)
        #expect(state.leases.count == 1)
        #expect(state.revision == 1)
    }

    @Test func releasedControlsSeparateIssuanceAndExistingLeases() throws {
        let lines = try fixture()
        let snapshot = try JSONDecoder().decode(CLIControlReply.self, from: #require(lines["leases"]))
        #expect(snapshot.leases?.count == 2)
        #expect(snapshot.sealing == true)
        let disabled = try JSONDecoder().decode(CLIControlReply.self, from: #require(lines["seal-off"]))
        #expect(disabled.ok == true)
        #expect(disabled.sealing == false)
        #expect(disabled.revoked == nil)
        let failed = try JSONDecoder().decode(CLIControlReply.self, from: #require(lines["unseal that jerk fails"]))
        #expect(failed.ok == false)
        #expect(failed.error == "EIO")
    }

    @Test func brokerRequiresExplicitOptInAndMetadataIsNotPersisted() throws {
        let capabilitiesData = try Data(contentsOf: Bundle.module.resourceURL!.appending(path: "Fixtures/capabilities.json"))
        var capabilities = try JSONDecoder().decode(CLICapabilities.self, from: capabilitiesData)
        #expect(capabilities.supportsCredentialLeases)
        capabilities.control.ops.removeAll { $0 == "unseal" }
        #expect(!capabilities.supportsCredentialLeases)
        #expect(!CLIInvocation.follow(join: "secret").arguments.contains("--jerk-seal"))
        #expect(CLIInvocation.follow(join: "secret", offerCredentials: true).arguments.contains("--jerk-seal"))
        let store = WorkspaceStore(defaults: nil)
        let id = store.sessions[0].id
        store.update(id) { $0.usesLiveRuntime = true }
        store.credentialAccess[id] = .init(leases: [.init(provider: "github", leaseId: "metadata-only")], ops: ["unseal"], sealing: true)
        let encoded = try JSONEncoder().encode(store.sessions)
        #expect(!String(decoding: encoded, as: UTF8.self).contains("metadata-only"))
        store.disconnectLive(id)
        #expect(store.credentialAccess[id]?.ops.isEmpty == true)
        #expect(store.credentialAccess[id]?.leases.count == 1)
        #expect(store.credentialAccess[id]?.message?.contains("may still be valid") == true)
        #expect(store.credentialOffers.isEmpty)
    }

    @Test func staleSnapshotCannotRestoreAConfirmedRevokedLease() throws {
        let reply = try JSONDecoder().decode(CLIControlReply.self, from: #require(fixture()["leases"]))
        var state = CredentialAccess()
        let leases = try #require(reply.leases)
        state.replaceSnapshot(leases, sealing: true)
        state.released("jerk-github-1", upstream: true)
        state.replaceSnapshot(leases, sealing: false)
        #expect(state.leases.map(\.leaseId) == ["jerk-minted-1"])
        #expect(state.sealing == false)
        #expect(state.complete)
    }

    @Test(arguments: ["leases", "unseal that jerk fails"])
    func socketClientReadsReleasedReplyWithoutTouchingARealCLI(step: String) async throws {
        let reply = try #require(fixture()[step])
        let op = step == "leases" ? "leases" : "unseal"
        let directory = "/private/tmp/sliccy-test-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let path = "\(directory)/\(getpid()).sock"
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(listener >= 0)
        defer { close(listener) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { target in
            for (index, byte) in path.utf8CString.enumerated() { target[index] = UInt8(bitPattern: byte) }
        }
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        try #require(bound == 0 && listen(listener, 1) == 0)
        let server = Task.detached {
            var ready = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            try #require(poll(&ready, 1, 5000) > 0)
            let connection = accept(listener, nil, nil)
            try #require(connection >= 0)
            defer { close(connection) }
            var timeout = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
            var buffer = [UInt8](repeating: 0, count: 4096)
            let count = recv(connection, &buffer, buffer.count, 0)
            try #require(count > 0)
            let request = try JSONSerialization.jsonObject(with: Data(buffer.prefix(count))) as? [String: Any]
            #expect(request?["op"] as? String == op)
            let bytes = reply + Data([10])
            let sent = bytes.withUnsafeBytes { send(connection, $0.baseAddress, bytes.count, 0) }
            #expect(sent == bytes.count)
        }
        do {
            let received = try await Task.detached {
                try CLIControlClient.exchange(pid: getpid(), request: .init(op: op, leaseId: op == "unseal" ? "sample" : nil), socketDirectory: directory)
            }.value
            #expect(step == "leases")
            #expect(received.leases?.count == 2)
            #expect(received.sealing == true)
        } catch CLIControlError.refused {
            #expect(step == "unseal that jerk fails")
        }
        try await server.value
    }
}
