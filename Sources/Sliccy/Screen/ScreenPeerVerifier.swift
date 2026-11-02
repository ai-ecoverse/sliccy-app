import Foundation
import Security
import Darwin
import ScreenSystem

/// Release engineering fills these only from an approved, checksum-verified signed
/// CLI artifact and reviewed native evidence. Development builds have no screen grant.
enum ScreenReleasePolicy {
    static let cliCodeDirectoryHashes: Set<Data> = []
    static let identityProofApproved = false
    static let provenScopes: Set<String> = []
}

struct ScreenAuditIdentity: Equatable, Sendable {
    let native: Data
    var words: [UInt32] { native.withUnsafeBytes { bytes in (0..<8).map { bytes.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self) } } }
    var pid: pid_t { pid_t(bitPattern: words[5]) }
    var uid: uid_t { words[1] }
    var encoded: String {
        var data = Data()
        for word in words { var value = word.bigEndian; withUnsafeBytes(of: &value) { data.append(contentsOf: $0) } }
        return ScreenID.encode(data)
    }
    init(native: Data) throws {
        guard native.count == 32 else { throw ScreenFailure.peerUntrusted }
        self.native = native
    }
    init(encoded: String) throws {
        let data = try ScreenID.decode(encoded, bytes: 32)
        var native = Data()
        for index in stride(from: 0, to: 32, by: 4) {
            var value = data[index..<index + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            withUnsafeBytes(of: &value) { native.append(contentsOf: $0) }
        }
        try self.init(native: native)
    }
    static func current() throws -> Self {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &token) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard result == KERN_SUCCESS, count == 8 else { throw ScreenFailure.peerUntrusted }
        return try withUnsafeBytes(of: token) { try Self(native: Data($0)) }
    }
    static func peer(_ fd: Int32) throws -> Self {
        var token = audit_token_t()
        var size = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0, size == 32 else { throw ScreenFailure.peerUntrusted }
        return try withUnsafeBytes(of: token) { try Self(native: Data($0)) }
    }
}

struct ScreenPeerVerifier: Sendable {
    let approvedHashes: Set<Data>
    static let team = "S8LB56P782"

    func verifyCLI(socket: Int32, expectedPID: pid_t, expectedIdentity: ScreenAuditIdentity? = nil) throws -> ScreenAuditIdentity {
        let before = try ScreenAuditIdentity.peer(socket)
        guard before.pid == expectedPID, before.uid == getuid(),
              expectedIdentity == nil || before == expectedIdentity, !approvedHashes.isEmpty else { throw ScreenFailure.peerUntrusted }
        var uid: uid_t = 0, gid: gid_t = 0
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getpeereid(socket, &uid, &gid) == 0, uid == getuid(),
              getsockopt(socket, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0, pid == expectedPID else { throw ScreenFailure.peerUntrusted }
        let info = try Self.verify(identity: before, identifier: "ai.sliccy.slicc")
        guard let hash = info[kSecCodeInfoUnique as String] as? Data, approvedHashes.contains(hash),
              try ScreenAuditIdentity.peer(socket) == before else { throw ScreenFailure.peerUntrusted }
        return before
    }

    static func verifySelf() throws {
        _ = try verify(identity: ScreenAuditIdentity.current(), identifier: "ai.sliccy.mac")
    }

    static func verify(identity: ScreenAuditIdentity, identifier: String) throws -> [String: Any] {
        var guest: SecCode?
        let attributes = [kSecGuestAttributeAudit as String: identity.native] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest) == errSecSuccess, let guest else { throw ScreenFailure.peerUntrusted }
        let requirement = try requirement(identifier)
        guard SecCodeCheckValidity(guest, [], requirement) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        var code: SecStaticCode?
        guard SecCodeCopyStaticCode(guest, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        var information: CFDictionary?
        var status: UInt32 = 0
        guard sliccy_screen_dynamic_status(guest, &status) == errSecSuccess,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              let flags = info[kSecCodeInfoFlags as String] as? UInt32, flags & 0x10000 != 0, flags & 2 == 0,
              status & 1 != 0, status & 0x10000000 == 0 else { throw ScreenFailure.peerUntrusted }
        let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        for key in ["com.apple.security.get-task-allow", "com.apple.security.cs.disable-library-validation", "com.apple.security.cs.allow-dyld-environment-variables", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.cs.allow-jit", "com.apple.security.cs.disable-executable-page-protection"] {
            if let value = entitlements[key], (value as? Bool) != false { throw ScreenFailure.peerUntrusted }
        }
        guard SecCodeCheckValidity(guest, [], requirement) == errSecSuccess,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        return info
    }

    static func requirement(_ identifier: String) throws -> SecRequirement {
        guard ["ai.sliccy.mac", "ai.sliccy.slicc"].contains(identifier) else { throw ScreenFailure.peerUntrusted }
        let text = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[subject.OU] = \"S8LB56P782\" and identifier \"\(identifier)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else { throw ScreenFailure.peerUntrusted }
        return requirement
    }
}
