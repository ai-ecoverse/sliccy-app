#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security
import Darwin
import ScreenSystem

struct ScreenRunnerKernelSample: Equatable, Codable, Sendable {
    let pid: pid_t, parent: pid_t, uid: uid_t, seconds: UInt64, microseconds: UInt64
    static func read(_ pid: pid_t) -> (Self?, Int32) {
        var raw = sliccy_screen_process_identity()
        let status = sliccy_runner_identity(pid, &raw)
        guard status == 0 else { return (nil, status) }
        return (.init(pid: raw.pid, parent: raw.parent, uid: raw.uid, seconds: raw.seconds, microseconds: raw.microseconds), 0)
    }
    static func path(_ pid: pid_t) throws -> String {
        var buffer = [CChar](repeating: 0, count: 4096)
        guard sliccy_runner_path(pid, &buffer, 4096) == 0 else { throw ScreenFailure.peerUntrusted }
        return String(cString: buffer)
    }
    static func hash(_ pid: pid_t) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 20)
        guard sliccy_runner_hash(pid, &bytes) == 0 else { throw ScreenFailure.peerUntrusted }
        return Data(bytes)
    }
}

enum ScreenRunnerSystemOwner {
    struct Code: Equatable, Sendable { let identifier: String, path: String, hash: Data }
    static func identifier(_ pid: pid_t) throws -> String {
        var guest: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &guest) == errSecSuccess,
              let guest, SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
              let value = (info as? [String: Any])?[kSecCodeInfoIdentifier as String] as? String,
              !value.isEmpty else { throw ScreenRunnerInventoryIssue.ownerAttribution }
        return value
    }
    static func own(_ pid: pid_t, sliceRecord: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in }) throws -> ScreenRunnerInventoryBoundary.Identity {
        guard pid == getpid(), let before = ScreenRunnerKernelSample.read(pid).0 else { throw ScreenFailure.peerUntrusted }
        let value = try code(pid: pid, identifier: "ai.sliccy.mac", app: true, sliceRecord: sliceRecord)
        guard try ScreenRunnerKernelSample.path(pid) == value.path,
              try ScreenRunnerKernelSample.hash(pid) == value.hash,
              ScreenRunnerKernelSample.read(pid).0 == before else { throw ScreenFailure.peerUntrusted }
        return .init(pid: pid, parent: before.parent, uid: before.uid, seconds: before.seconds, microseconds: before.microseconds,
                     identifier: value.identifier, path: value.path, hash: value.hash, appleAnchored: false, verified: true, sysctlBound: false)
    }
    static func code(pid: pid_t, identifier: String, app: Bool = false,
                     sliceRecord: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in }) throws -> Code {
        try code(pid: pid, identifier: identifier, app: app,
            calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native, sliceRecord: sliceRecord)
    }
    static func code<S, G, R>(pid: pid_t, identifier: String, app: Bool = false, calls: ScreenRunnerSecurityCalls<S, G, R>,
                              sliceRecord: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in }) throws -> Code {
        guard ScreenRunnerInventoryBoundary.systemRoles.contains(identifier) || identifier == "com.apple.SecurityAgent" || (app && identifier == "ai.sliccy.mac"),
              let operations = calls.slices else { throw ScreenFailure.peerUntrusted }
        let policy = try ScreenRunnerSliceBinding.Policy.make(identifier, team: app ? "S8LB56P782" : nil)
        let kernel = try operations.kernel(pid)
        let bound = try ScreenRunnerSliceBinding.bind(pid: pid, path: kernel.path, expected: kernel.hash, policy: policy,
            site: app ? "self" : "system-owner", calls: calls, record: sliceRecord)
        return .init(identifier: identifier, path: kernel.path.path, hash: bound.identity.hash)
    }
    static func verify(_ pid: pid_t, identifier: String, identityRecord: @Sendable (ScreenRunnerBSD.Evidence) -> Void,
                       sliceRecord: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void = { _ in }) throws -> ScreenRunnerInventoryBoundary.Identity {
        try verifyIdentity(pid, identifier: identifier, observe: { phase in try ScreenRunnerBSD.observe(pid, phase: phase, role: identifier, record: identityRecord) },
            check: { try code(pid: pid, identifier: identifier, sliceRecord: sliceRecord) },
            kernel: { (try ScreenRunnerKernelSample.path(pid), try ScreenRunnerKernelSample.hash(pid)) })
    }
    static func verifyIdentity(_ pid: pid_t, identifier: String, observe: (String) throws -> ScreenRunnerBSD.Resolved,
                               check: () throws -> Code, kernel: () throws -> (String, Data)) throws -> ScreenRunnerInventoryBoundary.Identity {
        let before = try observe("before"), (path, hash) = try kernel()
        let verified = try check()
        let after = try observe("after"), (afterPath, afterHash) = try kernel()
        guard verified.identifier == identifier, before.sample.pid == pid, after.sample.pid == pid,
              path == verified.path, hash == verified.hash, afterPath == path, afterHash == hash else { throw ScreenFailure.peerUntrusted }
        let isWindowServer = identifier == "com.apple.WindowServer"
        let identity = try ScreenRunnerBSD.bind(before, after, windowServer: isWindowServer)
        return .init(pid: pid, parent: identity.parent, uid: identity.effectiveUID, seconds: identity.seconds, microseconds: identity.microseconds,
            identifier: identifier, path: verified.path, hash: verified.hash, appleAnchored: true, verified: true, sysctlBound: isWindowServer,
            realUID: identity.realUID, savedUID: identity.savedUID)
    }
}
#endif
