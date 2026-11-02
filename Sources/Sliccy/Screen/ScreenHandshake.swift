import Foundation
import Darwin

/// Private listener allocation and exact two-lane handshake. No public socket is
/// involved. The launcher must supply the deadline recorded BEFORE posix_spawn.
final class ScreenHandshake: @unchecked Sendable {
    struct Pair: Sendable {
        let safety: ScreenSocket
        let frames: ScreenSocket
        let identity: ScreenAuditIdentity
        let launch: String
        let connection: String
        let authenticatedAt: ContinuousClock.Instant
        let readyDeadline: ContinuousClock.Instant
    }
    let bootstrap: ScreenBootstrap
    private let safety: ScreenSocket
    private let frames: ScreenSocket
    private let directory: String
    init() throws {
        var template = Array("/private/tmp/sliccy-screen.XXXXXXXX".utf8CString)
        guard mkdtemp(&template) != nil else { throw ScreenFailure.peerLost }
        directory = String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        do {
            guard chmod(directory, 0o700) == 0 else { throw ScreenFailure.peerLost }
            safety = try .listener(path: directory + "/s")
            frames = try .listener(path: directory + "/f")
            bootstrap = .init(launch: try ScreenID.make(bytes: 32), safetyPath: directory + "/s",
                framesPath: directory + "/f", challenge: try ScreenID.make(bytes: 32),
                parentAuditToken: try ScreenAuditIdentity.current().encoded)
        } catch {
            unlink(directory + "/s"); unlink(directory + "/f"); rmdir(directory)
            throw error
        }
    }
    deinit { unlink(directory + "/s"); unlink(directory + "/f"); rmdir(directory) }
    func bootstrapRecord() throws -> Data {
        let header = try JSONEncoder().encode(bootstrap)
        guard header.count <= 4096 else { throw ScreenFailure.incompatible }
        return ScreenSocket.prefix(header.count) + header
    }
    func authenticate(pid: pid_t, until deadline: ContinuousClock.Instant, verifier: ScreenPeerVerifier,
                      childAlive: @Sendable () -> Bool) throws -> Pair {
        // Policy cannot be overridden by argv, defaults, an environment variable or peer JSON.
        guard ScreenReleasePolicy.identityProofApproved, !verifier.approvedHashes.isEmpty else { throw ScreenFailure.peerUntrusted }
        try ScreenPeerVerifier.verifySelf()
        var attempts = 0
        func accept(_ listener: ScreenSocket, lane: String, connection: String?, previousNonce: String?, identity: ScreenAuditIdentity?) throws -> (ScreenSocket, ScreenAuditIdentity, ScreenHello) {
            while attempts < 8 {
                attempts += 1
                guard childAlive(), ContinuousClock.now < deadline else { throw ScreenFailure.peerLost }
                let socket = try listener.accept(until: deadline)
                do {
                    let verified = try verifier.verifyCLI(socket: socket.fd, expectedPID: pid, expectedIdentity: identity)
                    let bytes = try socket.readHello(until: deadline)
                    let fields = try ScreenJSON.object(bytes)
                    try ScreenJSON.keys(fields, exact: ["v", "lane", "launch", "challenge", "clientNonce"] + (lane == "frames" ? ["connection"] : []))
                    let hello = try JSONDecoder().decode(ScreenHello.self, from: bytes)
                    guard hello.v == 1, hello.lane == lane, hello.launch == bootstrap.launch,
                          hello.challenge == bootstrap.challenge, hello.connection == connection,
                          hello.clientNonce != previousNonce else { throw ScreenFailure.incompatible }
                    _ = try ScreenID.decode(hello.clientNonce, bytes: 32)
                    guard childAlive() else { throw ScreenFailure.peerLost }
                    _ = try verifier.verifyCLI(socket: socket.fd, expectedPID: pid, expectedIdentity: verified)
                    return (socket, verified, hello)
                } catch { socket.stop() }
            }
            throw ScreenFailure.peerUntrusted
        }
        let first = try accept(safety, lane: "safety", connection: nil, previousNonce: nil, identity: nil)
        let connection = try ScreenID.make(bytes: 32)
        var reply = first.2; reply.connection = connection; reply.serverNonce = try ScreenID.make(bytes: 32)
        try first.0.writeHello(JSONEncoder().encode(reply), until: deadline)
        let second = try accept(frames, lane: "frames", connection: connection, previousNonce: first.2.clientNonce, identity: first.1)
        reply = second.2; reply.serverNonce = try ScreenID.make(bytes: 32)
        try second.0.writeHello(JSONEncoder().encode(reply), until: deadline)
        guard childAlive(), ContinuousClock.now < deadline else { throw ScreenFailure.peerLost }
        _ = try verifier.verifyCLI(socket: first.0.fd, expectedPID: pid, expectedIdentity: first.1)
        _ = try verifier.verifyCLI(socket: second.0.fd, expectedPID: pid, expectedIdentity: first.1)
        safety.stop(); frames.stop()
        unlink(bootstrap.safetyPath); unlink(bootstrap.framesPath)
        return Pair(safety: first.0, frames: second.0, identity: first.1,
                    launch: bootstrap.launch, connection: connection, authenticatedAt: .now, readyDeadline: deadline)
    }
}
