#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security
import ScreenSystem

struct ScreenRunnerProcessSample: Equatable, Sendable {
    let pid: pid_t, parent: pid_t, uid: uid_t
    let seconds: UInt64, microseconds: UInt64
    static func read(_ pid: pid_t) throws -> Self {
        var value = sliccy_screen_process_identity()
        guard sliccy_screen_proof_process_identity(pid, &value) == 0 else { throw ScreenFailure.peerLost }
        return .init(pid: value.pid, parent: value.parent, uid: value.uid, seconds: value.seconds, microseconds: value.microseconds)
    }
    func requireChild(parent: pid_t, uid: uid_t) throws {
        guard pid > 0, self.parent == parent, self.uid == uid, seconds > 0, microseconds < 1_000_000 else { throw ScreenFailure.peerUntrusted }
    }
}

struct ScreenRunnerProcessIdentity: Sendable {
    enum Role: String, Sendable { case cli, surface, chrome, authorizationRequester = "authorization-requester" }
    let sample: ScreenRunnerProcessSample
    let role: Role
    let hash: Data
    func requireMatch(sample read: () throws -> ScreenRunnerProcessSample, role check: () throws -> Void) throws {
        guard try read() == sample else { throw ScreenFailure.peerUntrusted }
        try check()
        guard try read() == sample else { throw ScreenFailure.peerUntrusted }
    }
    @discardableResult
    func signal(_ signal: Int32, owned: Bool, reaped: Bool, sample read: () throws -> ScreenRunnerProcessSample,
                role check: () throws -> Void, send: (pid_t, Int32) -> Int32) -> Bool {
        guard owned, !reaped else { return false }
        do { try requireMatch(sample: read, role: check) } catch { return false }
        return send(sample.pid, signal) == 0
    }
    static func capture(pid: pid_t, role: Role, hash: Data, identifier: String, team: String?) throws -> Self {
        let sample = try ScreenRunnerProcessSample.read(pid)
        try sample.requireChild(parent: getpid(), uid: geteuid())
        let record = Self(sample: sample, role: role, hash: hash)
        try record.verify(identifier: identifier, team: team)
        return record
    }
    func verify(identifier: String, team: String?) throws {
        try requireMatch(sample: { try ScreenRunnerProcessSample.read(sample.pid) }, role: {
            try Self.verifyRole(pid: sample.pid, identifier: identifier, team: team, hash: hash)
        })
    }
    static func verifyRole(pid: pid_t, identifier: String, team: String?, hash: Data) throws {
        var requirement: SecRequirement?, guest: SecCode?, staticCode: SecStaticCode?, info: CFDictionary?
        var text = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"" + identifier + "\""
        if identifier == "com.apple.osascript" { text = "anchor apple and identifier \"com.apple.osascript\"" }
        if let team { text += " and certificate leaf[subject.OU] = \"" + team + "\"" }
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &guest) == errSecSuccess,
              let guest, SecCodeCheckValidity(guest, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
              SecCodeCopyStaticCode(guest, [], &staticCode) == errSecSuccess, let staticCode,
              SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess,
              SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
              (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data == hash else { throw ScreenFailure.peerUntrusted }
    }
}
#endif
