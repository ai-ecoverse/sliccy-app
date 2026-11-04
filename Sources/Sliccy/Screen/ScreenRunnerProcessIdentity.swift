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
    static func capture(pid: pid_t, role: Role, hash: Data, identifier: String, team: String?, chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void = { _ in }) throws -> Self {
        try capture(pid: pid, role: role, hash: hash, identifier: identifier, team: team,
                    calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
                    read: ScreenRunnerProcessSample.read, parent: getpid(), uid: geteuid(), chromeEvidence: chromeEvidence)
    }
    static func capture<Static, Guest, Rule>(pid: pid_t, role: Role, hash: Data, identifier: String, team: String?,
                                            calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                            read: (pid_t) throws -> ScreenRunnerProcessSample, parent: pid_t, uid: uid_t,
                                            chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void) throws -> Self {
        let sample = try read(pid)
        try sample.requireChild(parent: parent, uid: uid)
        let record = Self(sample: sample, role: role, hash: hash)
        try record.verify(identifier: identifier, team: team, site: .initialLive, calls: calls, read: { try read(sample.pid) }, chromeEvidence: chromeEvidence)
        return record
    }
    func verify(identifier: String, team: String?, site: ScreenRunnerChromePolicy.Site = .live, chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void = { _ in }) throws {
        try verify(identifier: identifier, team: team, site: site,
                   calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
                   read: { try ScreenRunnerProcessSample.read(sample.pid) }, chromeEvidence: chromeEvidence)
    }
    func verify<Static, Guest, Rule>(identifier: String, team: String?, site: ScreenRunnerChromePolicy.Site = .live,
                                    calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>, read: () throws -> ScreenRunnerProcessSample,
                                    chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void) throws {
        try requireMatch(sample: read, role: {
            try Self.verifyRole(pid: sample.pid, identifier: identifier, team: team, hash: hash, site: site, calls: calls, chromeEvidence: chromeEvidence)
        })
    }
    static func verifyRole(pid: pid_t, identifier: String, team: String?, hash: Data, site: ScreenRunnerChromePolicy.Site = .live, chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void = { _ in }) throws {
        try verifyRole(pid: pid, identifier: identifier, team: team, hash: hash, site: site,
                       calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native, chromeEvidence: chromeEvidence)
    }
    static func verifyRole<Static, Guest, Rule>(pid: pid_t, identifier: String, team: String?, hash: Data,
                                              site: ScreenRunnerChromePolicy.Site = .live, calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                              chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void) throws {
        var text = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"" + identifier + "\""
        if identifier == "com.apple.osascript" { text = "anchor apple and identifier \"com.apple.osascript\"" }
        if let team { text += " and certificate leaf[subject.OU] = \"" + team + "\"" }
        let chrome = identifier == ScreenRunnerChromePolicy.identifier
        if chrome { text = ScreenRunnerChromePolicy.requirementText }
        let requirement = try calls.makeRule(text), guest = try calls.guest(pid)
        guard calls.checkGuest(guest, chrome ? [] : SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        let staticCode = try calls.copyStatic(guest)
        try ScreenRunnerChromePolicy.verify(staticCode, identifier: identifier, site: site, ordinary: requirement, calls: calls, record: chromeEvidence)
        guard try calls.information(staticCode).hash == hash else { throw ScreenFailure.peerUntrusted }
    }
}
#endif
