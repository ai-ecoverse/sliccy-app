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
    static func capture(pid: pid_t, role: Role, hash: Data?, catalogue: ScreenRunnerSliceBinding.Catalogue? = nil, identifier: String, team: String?, chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void = { _ in }, sliceEvidence: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void) throws -> Self {
        try capture(pid: pid, role: role, hash: hash, catalogue: catalogue, identifier: identifier, team: team,
                    calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
                    read: ScreenRunnerProcessSample.read, parent: getpid(), uid: geteuid(), chromeEvidence: chromeEvidence, sliceEvidence: sliceEvidence)
    }
    static func capture<Static, Guest, Rule>(pid: pid_t, role: Role, hash: Data?, catalogue: ScreenRunnerSliceBinding.Catalogue? = nil, identifier: String, team: String?,
                                            calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                            read: (pid_t) throws -> ScreenRunnerProcessSample, parent: pid_t, uid: uid_t,
                                            chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void, sliceEvidence: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void) throws -> Self {
        let sample = try read(pid)
        try sample.requireChild(parent: parent, uid: uid)
        let live = try Self.verifyRole(pid: pid, identifier: identifier, team: team, hash: hash, catalogue: catalogue, site: .initialLive, calls: calls, chromeEvidence: chromeEvidence, sliceEvidence: sliceEvidence)
        guard try read(pid) == sample else { throw ScreenFailure.peerUntrusted }
        return Self(sample: sample, role: role, hash: live)
    }
    func verify(identifier: String, team: String?, site: ScreenRunnerChromePolicy.Site = .live, chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void = { _ in }, sliceEvidence: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void) throws {
        try verify(identifier: identifier, team: team, site: site,
                   calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native,
                   read: { try ScreenRunnerProcessSample.read(sample.pid) }, chromeEvidence: chromeEvidence, sliceEvidence: sliceEvidence)
    }
    func verify<Static, Guest, Rule>(identifier: String, team: String?, site: ScreenRunnerChromePolicy.Site = .live,
                                    calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>, read: () throws -> ScreenRunnerProcessSample,
                                    chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void, sliceEvidence: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void) throws {
        try requireMatch(sample: read, role: {
            try Self.verifyRole(pid: sample.pid, identifier: identifier, team: team, hash: hash, site: site, calls: calls, chromeEvidence: chromeEvidence, sliceEvidence: sliceEvidence)
        })
    }
    @discardableResult
    static func verifyRole(pid: pid_t, identifier: String, team: String?, hash: Data?, catalogue: ScreenRunnerSliceBinding.Catalogue? = nil,
                           site: ScreenRunnerChromePolicy.Site = .live, chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void = { _ in },
                           sliceEvidence: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void) throws -> Data {
        try verifyRole(pid: pid, identifier: identifier, team: team, hash: hash, catalogue: catalogue, site: site,
                       calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native, chromeEvidence: chromeEvidence, sliceEvidence: sliceEvidence)
    }
    @discardableResult
    static func verifyRole<Static, Guest, Rule>(pid: pid_t, identifier: String, team: String?, hash: Data?, catalogue: ScreenRunnerSliceBinding.Catalogue? = nil,
                                              site: ScreenRunnerChromePolicy.Site = .live, calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                              chromeEvidence: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void,
                                              sliceEvidence: @Sendable (ScreenRunnerSliceBinding.Evidence) -> Void) throws -> Data {
        let policy = try ScreenRunnerSliceBinding.Policy.make(identifier, team: team)
        let rule = try calls.makeRule(policy.requirement), guest = try calls.guest(pid)
        guard calls.checkGuest(guest, SecCSFlags(rawValue: policy.chrome ? 0 : 16), rule) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        try ScreenRunnerChromePolicy.verify(calls.copyStatic(guest), identifier: identifier, site: site, ordinary: rule, calls: calls, record: chromeEvidence)
        let bound = try ScreenRunnerSliceBinding.bind(pid: pid, path: catalogue?.path, expected: hash, catalogue: catalogue,
            policy: policy, site: site.rawValue, calls: calls, record: sliceEvidence)
        return bound.identity.hash
    }
}
#endif
