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
    static func own(_ pid: pid_t) throws -> ScreenRunnerInventoryBoundary.Identity {
        guard pid == getpid(), let before = ScreenRunnerKernelSample.read(pid).0 else { throw ScreenFailure.peerUntrusted }
        let value = try code(pid: pid, identifier: "ai.sliccy.mac", app: true)
        guard try ScreenRunnerKernelSample.path(pid) == value.path,
              try ScreenRunnerKernelSample.hash(pid) == value.hash,
              ScreenRunnerKernelSample.read(pid).0 == before else { throw ScreenFailure.peerUntrusted }
        return .init(pid: pid, parent: before.parent, uid: before.uid, seconds: before.seconds, microseconds: before.microseconds,
                     identifier: value.identifier, path: value.path, hash: value.hash, appleAnchored: false, verified: true, sysctlBound: false)
    }
    static func code(pid: pid_t, identifier: String, app: Bool = false) throws -> Code {
        guard ScreenRunnerInventoryBoundary.systemRoles.contains(identifier) || identifier == "com.apple.SecurityAgent" || (app && identifier == "ai.sliccy.mac") else { throw ScreenFailure.peerUntrusted }
        let text = app ? "anchor apple generic and identifier \"ai.sliccy.mac\" and certificate leaf[subject.OU] = \"S8LB56P782\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" : "anchor apple and identifier \"\(identifier)\""
        var rule: SecRequirement?, guest: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        guard SecRequirementCreateWithString(text as CFString, [], &rule) == errSecSuccess, let rule,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &guest) == errSecSuccess, let guest,
              SecCodeCheckValidity(guest, SecCSFlags(rawValue: kSecCSStrictValidate), rule) == errSecSuccess,
              SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode,
              SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode), rule) == errSecSuccess,
              SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
              let values = info as? [String: Any], values[kSecCodeInfoIdentifier as String] as? String == identifier,
              let path = values[kSecCodeInfoMainExecutable as String] as? URL,
              let hash = values[kSecCodeInfoUnique as String] as? Data, hash.count == 20,
              SecCodeCheckValidity(guest, SecCSFlags(rawValue: kSecCSStrictValidate), rule) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        return .init(identifier: identifier, path: path.path, hash: hash)
    }
    static func verify(_ pid: pid_t, identifier: String, identityRecord: @Sendable (ScreenRunnerBSD.Evidence) -> Void) throws -> ScreenRunnerInventoryBoundary.Identity {
        let before = try ScreenRunnerBSD.observe(pid, phase: "before", record: identityRecord)
        let path = try ScreenRunnerKernelSample.path(pid), hash = try ScreenRunnerKernelSample.hash(pid)
        let verified = try code(pid: pid, identifier: identifier)
        let after = try ScreenRunnerBSD.observe(pid, phase: "after", record: identityRecord)
        guard path == verified.path, hash == verified.hash,
              try ScreenRunnerKernelSample.path(pid) == path, try ScreenRunnerKernelSample.hash(pid) == hash else { throw ScreenFailure.peerUntrusted }
        let isWindowServer = identifier == "com.apple.WindowServer"
        let identity = try ScreenRunnerBSD.bind(before, after, windowServer: isWindowServer)
        return .init(pid: pid, parent: identity.parent, uid: identity.effectiveUID, seconds: identity.seconds, microseconds: identity.microseconds,
            identifier: identifier, path: verified.path, hash: verified.hash, appleAnchored: true, verified: true, sysctlBound: isWindowServer,
            realUID: identity.realUID, savedUID: identity.savedUID)
    }
}
#endif
