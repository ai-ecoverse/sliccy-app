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
    struct Observation: Equatable {
        let before: ScreenRunnerKernelSample?, beforeError: Int32
        let after: ScreenRunnerKernelSample?, afterError: Int32
        let code: Code, kernelPath: String, kernelHash: Data
    }
    static func identifier(_ pid: pid_t) throws -> String {
        var guest: SecCode?, info: CFDictionary?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &guest) == errSecSuccess,
              let guest, SecCodeCopySigningInformation(guest, [], &info) == errSecSuccess,
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
                     identifier: value.identifier, path: value.path, hash: value.hash, appleAnchored: false, verified: true, privilegedBracket: false)
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
    static func observe(_ pid: pid_t, identifier: String) throws -> Observation {
        let before = ScreenRunnerKernelSample.read(pid)
        let path = try ScreenRunnerKernelSample.path(pid), hash = try ScreenRunnerKernelSample.hash(pid)
        let verified = try code(pid: pid, identifier: identifier)
        let after = ScreenRunnerKernelSample.read(pid)
        guard path == verified.path, hash == verified.hash,
              try ScreenRunnerKernelSample.path(pid) == path, try ScreenRunnerKernelSample.hash(pid) == hash else { throw ScreenFailure.peerUntrusted }
        return .init(before: before.0, beforeError: before.1, after: after.0, afterError: after.1, code: verified, kernelPath: path, kernelHash: hash)
    }
    static func bind(_ sample: Observation, pid: pid_t, privileged: ScreenRunnerKernelSample? = nil) throws -> ScreenRunnerKernelSample {
        for (value, error) in [(sample.before, sample.beforeError), (sample.after, sample.afterError)] {
            if let value {
                guard error == 0, value.pid == pid, privileged == nil || value == privileged else { throw ScreenFailure.peerUntrusted }
            } else {
                guard error == EPERM, sample.code.identifier == "com.apple.WindowServer", privileged != nil else { throw ScreenFailure.peerUntrusted }
            }
        }
        guard let value = privileged ?? sample.before, value.pid == pid,
              privileged != nil || sample.before == sample.after else { throw ScreenFailure.peerUntrusted }
        return value
    }
    static func verify(_ pid: pid_t, identifier: String, kernelRecord: @Sendable (ScreenRunnerKernelChild.Evidence) -> Void) throws -> ScreenRunnerInventoryBoundary.Identity {
        let original = try observe(pid, identifier: identifier)
        let identity: ScreenRunnerKernelSample
        let privileged: Bool
        if identifier == "com.apple.WindowServer" {
            let first = try ScreenRunnerKernelChild.query(pid, expected: original.code, record: kernelRecord)
            let current = try observe(pid, identifier: identifier)
            let last = try ScreenRunnerKernelChild.query(pid, expected: original.code, record: kernelRecord)
            guard first == last, original.code == current.code, original.kernelPath == current.kernelPath,
                  original.kernelHash == current.kernelHash else { throw ScreenFailure.peerUntrusted }
            _ = try bind(original, pid: pid, privileged: first)
            identity = try bind(current, pid: pid, privileged: last); privileged = true
        } else { identity = try bind(original, pid: pid); privileged = false }
        return .init(pid: pid, parent: identity.parent, uid: identity.uid, seconds: identity.seconds, microseconds: identity.microseconds,
            identifier: identifier, path: original.code.path, hash: original.code.hash, appleAnchored: true, verified: true, privilegedBracket: privileged)
    }
}
#endif
