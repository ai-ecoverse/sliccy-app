#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security

enum ScreenRunnerSliceBinding {
    struct Identity: Equatable, Sendable {
        let type: Int, hash: Data, full: Data
        func requireValid() throws {
            guard (1...4).contains(type), hash.count == 20, (20...64).contains(full.count), full.prefix(20) == hash else { throw ScreenFailure.peerUntrusted }
        }
    }
    struct Slice: Equatable, Sendable {
        let cpu: Int32, subtype: Int32, offset: UInt64, size: UInt64
    }
    struct Member: Equatable, Sendable {
        let slice: Slice, identity: Identity
    }
    struct Catalogue: Equatable, Sendable {
        let path: URL, members: [Member]
    }
    struct Kernel: Equatable, Sendable {
        let path: URL, hash: Data, flags: UInt32
    }
    struct Policy: Equatable, Sendable {
        let identifier: String, requirement: String, chrome: Bool, platform: Bool
        static func make(_ identifier: String, team: String?) throws -> Self {
            if identifier == ScreenRunnerChromePolicy.identifier {
                guard team == ScreenRunnerChromePolicy.team else { throw ScreenFailure.peerUntrusted }
                return .init(identifier: identifier, requirement: ScreenRunnerChromePolicy.requirementText, chrome: true, platform: false)
            }
            if ScreenRunnerInventoryBoundary.systemRoles.contains(identifier) || ["com.apple.SecurityAgent", "com.apple.osascript"].contains(identifier) {
                guard team == nil else { throw ScreenFailure.peerUntrusted }
                return .init(identifier: identifier, requirement: "anchor apple and identifier \"\(identifier)\"", chrome: false, platform: true)
            }
            guard ["ai.sliccy.mac", "ai.sliccy.proof-helper", "ai.sliccy.slicc"].contains(identifier), team == "S8LB56P782" else { throw ScreenFailure.peerUntrusted }
            return .init(identifier: identifier, requirement: "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"S8LB56P782\"", chrome: false, platform: false)
        }
    }
    final class Snapshot {
        let path: URL, slices: [Slice]
        let metadata: [String]
        private let check: () throws -> Void, release: () -> Void
        init(path: URL, slices: [Slice], metadata: [String] = [], check: @escaping () throws -> Void, release: @escaping () -> Void = {}) {
            self.path = path; self.slices = slices; self.metadata = metadata; self.check = check; self.release = release
        }
        func recheck() throws { try check() }
        deinit { release() }
    }
    struct Operations<Static> {
        let open: (URL) throws -> Snapshot
        let explicit: (URL, Slice) throws -> Static
        let kernel: (pid_t) throws -> Kernel
        let incarnation: (pid_t) throws -> [String]
    }
    struct Evidence: @unchecked Sendable {
        let role: String, site: String, at: ContinuousClock.Instant
        let passed: Bool, step: String, selected: Member?, statuses: [[Int64]]
        var compared: [String: Any] = [:]
        var fields: [String: Any] {
            ["role": role, "site": site, "passed": passed, "step": step, "statuses": statuses, "compared": compared,
             "selected": selected.map { [$0.slice.cpu, $0.slice.subtype, String($0.slice.offset), String($0.slice.size), $0.identity.type,
                                          $0.identity.hash.base64EncodedString(), $0.identity.full.base64EncodedString()] as [Any] } as Any? ?? NSNull()]
        }
    }
    static func memberFields(_ member: Member) -> [Any] {
        [member.slice.cpu, member.slice.subtype, String(member.slice.offset), String(member.slice.size), member.identity.type,
         member.identity.hash.base64EncodedString(), member.identity.full.base64EncodedString()]
    }
    static func unique(_ live: Identity, _ members: [Member]) throws -> Int {
        try live.requireValid()
        guard (1...8).contains(members.count) else { throw ScreenFailure.peerUntrusted }
        for member in members { try member.identity.requireValid() }
        let matches = members.indices.filter { members[$0].identity.type == live.type && members[$0].identity.hash == live.hash }
        guard matches.count == 1, let index = matches.first else { throw ScreenFailure.peerUntrusted }
        return index
    }
    static func information<S, G, R>(_ code: S, path: URL, policy: Policy, slice: Slice?, calls: ScreenRunnerSecurityCalls<S, G, R>) throws -> Identity {
        let value = try calls.information(code)
        guard value.identifier == policy.identifier, value.path == path, let identity = value.identity else { throw ScreenFailure.peerUntrusted }
        try identity.requireValid()
        if let slice { guard value.offset == slice.offset else { throw ScreenFailure.peerUntrusted } }
        return identity
    }
    static func validate<S, G, R>(_ code: S, rule: R, policy: Policy, calls: ScreenRunnerSecurityCalls<S, G, R>, statuses: inout [[Int64]]) throws {
        if policy.chrome {
            let base = calls.checkStatic(code, SecCSFlags(rawValue: 9), rule)
            statuses.append([9, Int64(base)])
            guard base == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        }
        let strict = calls.checkStatic(code, SecCSFlags(rawValue: 25), rule)
        statuses.append([25, Int64(strict)])
        guard strict == errSecSuccess || (policy.chrome && strict == errSecCSInvalidAssociatedFileData) else { throw ScreenFailure.peerUntrusted }
    }
    static func catalogue<S, G, R>(_ snapshot: Snapshot, policy: Policy, rule: R, calls: ScreenRunnerSecurityCalls<S, G, R>,
                                   operations: Operations<S>, validateAll: Bool, statuses: inout [[Int64]]) throws -> ([S], Catalogue) {
        guard (1...8).contains(snapshot.slices.count) else { throw ScreenFailure.peerUntrusted }
        var objects: [S] = [], members: [Member] = []
        for slice in snapshot.slices {
            let object = try operations.explicit(snapshot.path, slice)
            let identity = try information(object, path: snapshot.path, policy: policy, slice: slice, calls: calls)
            if validateAll { try validate(object, rule: rule, policy: policy, calls: calls, statuses: &statuses) }
            objects.append(object); members.append(.init(slice: slice, identity: identity))
        }
        try snapshot.recheck()
        return (objects, .init(path: snapshot.path, members: members))
    }
    static func preflight<S, G, R>(path: URL, policy: Policy, calls: ScreenRunnerSecurityCalls<S, G, R>,
                                   record: @Sendable (Evidence) -> Void = { _ in }) throws -> Catalogue {
        let trace = ScreenRunnerSecurityCalls<S, G, R>.Trace(), calls = calls.recording(trace)
        var passed = false, step = "open", statuses: [[Int64]] = []
        var compared: [String: Any] = ["pid": NSNull(), "requirement": policy.requirement, "path": path.path]
        defer { compared["operations"] = trace.rows; compared["information"] = trace.values; compared["failure"] = trace.failure; record(.init(role: policy.identifier, site: "preflight", at: .now, passed: passed, step: step, selected: nil, statuses: statuses, compared: compared)) }
        guard let operations = calls.slices else { throw ScreenFailure.peerUntrusted }
        let snapshot = try operations.open(path), rule = try calls.makeRule(policy.requirement)
        guard snapshot.path == path else { throw ScreenFailure.peerUntrusted }
        compared["file"] = snapshot.metadata
        step = "catalogue"
        let (_, result) = try catalogue(snapshot, policy: policy, rule: rule, calls: calls, operations: operations, validateAll: true, statuses: &statuses)
        compared["members"] = result.members.map(memberFields)
        try snapshot.recheck(); passed = true; step = "complete"
        return result
    }
    static func bind<S, G, R>(pid: pid_t, path: URL?, expected: Data?, catalogue expectedCatalogue: Catalogue? = nil,
                             policy: Policy, site: String, calls: ScreenRunnerSecurityCalls<S, G, R>,
                             record: @Sendable (Evidence) -> Void = { _ in }) throws -> Member {
        let trace = ScreenRunnerSecurityCalls<S, G, R>.Trace(), calls = calls.recording(trace)
        var passed = false, step = "live", selected: Member?, statuses: [[Int64]] = []
        var compared: [String: Any] = ["pid": pid, "requirement": policy.requirement, "expected": expected?.base64EncodedString() as Any? ?? NSNull(),
            "expectedCatalogue": expectedCatalogue?.members.map(memberFields) as Any? ?? NSNull()]
        defer { compared["operations"] = trace.rows; compared["information"] = trace.values; compared["failure"] = trace.failure; record(.init(role: policy.identifier, site: site, at: .now, passed: passed, step: step, selected: selected, statuses: statuses, compared: compared)) }
        guard pid > 0, let operations = calls.slices else { throw ScreenFailure.peerUntrusted }
        let before = try operations.incarnation(pid)
        compared["incarnationBefore"] = before
        let rule = try calls.makeRule(policy.requirement), guest = try calls.guest(pid)
        let flags: UInt32 = policy.chrome ? 0 : 16
        let initial = calls.checkGuest(guest, SecCSFlags(rawValue: flags), rule); statuses.append([Int64(flags), Int64(initial)])
        guard initial == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        let kernel = try operations.kernel(pid)
        compared["kernelBefore"] = [kernel.path.path, kernel.hash.base64EncodedString(), String(kernel.flags)]
        step = "kernel-platform"
        guard kernel.hash.count == 20, path == nil || path == kernel.path,
              !policy.platform || kernel.flags & 0x04000000 != 0 else { throw ScreenFailure.peerUntrusted }
        let live = try information(calls.copyStatic(guest), path: kernel.path, policy: policy, slice: nil, calls: calls)
        compared["live"] = [live.type, live.hash.base64EncodedString(), live.full.base64EncodedString()]
        step = "live-kernel"
        guard live.hash == kernel.hash, expected == nil || live.hash == expected else { throw ScreenFailure.peerUntrusted }
        step = "catalogue"
        let snapshot = try operations.open(kernel.path)
        compared["file"] = snapshot.metadata
        guard snapshot.path == kernel.path else { throw ScreenFailure.peerUntrusted }
        let (objects, catalogue) = try catalogue(snapshot, policy: policy, rule: rule, calls: calls, operations: operations, validateAll: false, statuses: &statuses)
        compared["members"] = catalogue.members.map(memberFields)
        guard expectedCatalogue == nil || expectedCatalogue == catalogue else { throw ScreenFailure.peerUntrusted }
        step = "unique"
        let index = try unique(live, catalogue.members); selected = catalogue.members[index]
        step = "selected-validity"
        try validate(objects[index], rule: rule, policy: policy, calls: calls, statuses: &statuses)
        guard try information(objects[index], path: kernel.path, policy: policy, slice: catalogue.members[index].slice, calls: calls) == live else { throw ScreenFailure.peerUntrusted }
        step = "recheck"
        try snapshot.recheck()
        let final = calls.checkGuest(guest, SecCSFlags(rawValue: flags), rule); statuses.append([Int64(flags), Int64(final)])
        guard final == errSecSuccess,
              try information(calls.copyStatic(guest), path: kernel.path, policy: policy, slice: nil, calls: calls) == live else { throw ScreenFailure.peerUntrusted }
        let fresh = try operations.kernel(pid), after = try operations.incarnation(pid)
        compared["kernelAfter"] = [fresh.path.path, fresh.hash.base64EncodedString(), String(fresh.flags)]
        compared["incarnationAfter"] = after
        guard fresh == kernel, before == after else { throw ScreenFailure.peerUntrusted }
        try snapshot.recheck()
        passed = true; step = "complete"
        return catalogue.members[index]
    }
}
#endif
