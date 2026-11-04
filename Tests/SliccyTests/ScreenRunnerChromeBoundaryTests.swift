#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security
import Testing
@testable import Sliccy

struct ScreenRunnerChromeBoundaryTests {
    struct Call: Equatable { let code: String, flags: UInt32, rule: String }
    @Test func everyActualStaticSiteUsesPinnedBundleFlagsAndGoogleRequirement() throws {
        for site in ScreenRunnerChromePolicy.Site.allCases {
            for strict in [OSStatus(0), -66999] {
                var calls: [Call] = [], records = 0
                try ScreenRunnerChromePolicy.validate("guest", identifier: "com.google.Chrome", site: site, ordinary: "unused",
                    makeRule: { text in #expect(text == ScreenRunnerChromePolicy.requirementText); return text },
                    bundle: { path in #expect(path == "/Applications/Google Chrome.app"); return "bundle" },
                    check: { code, flags, rule in
                        calls.append(.init(code: code, flags: flags, rule: rule)); return flags == 25 ? strict : 0
                    }, record: { evidence in records += 1; #expect(evidence.accepted) })
                #expect(calls == [Call(code: "bundle", flags: 9, rule: ScreenRunnerChromePolicy.requirementText),
                                  Call(code: "bundle", flags: 25, rule: ScreenRunnerChromePolicy.requirementText),
                                  Call(code: "guest", flags: 0, rule: ScreenRunnerChromePolicy.requirementText)])
                #expect(records == 1)
            }
        }
    }
    @Test func noOtherRoleOrRequirementCanUseTheDetritusException() throws {
        for site in ScreenRunnerChromePolicy.Site.allCases {
            for role in ["ai.sliccy.mac", "ai.sliccy.proof-helper", "ai.sliccy.slicc", "com.apple.osascript", "com.google.Chrome.helper", ""] {
                var calls: [Call] = []
                #expect(throws: ScreenFailure.peerUntrusted) {
                    try ScreenRunnerChromePolicy.validate("guest", identifier: role, site: site, ordinary: "ordinary",
                        makeRule: { _ in Issue.record("unexpected Google requirement"); return "wrong" },
                        bundle: { _ in Issue.record("unexpected Chrome bundle"); return "wrong" },
                        check: { code, flags, rule in calls.append(.init(code: code, flags: flags, rule: rule)); return -66999 },
                        record: { _ in Issue.record("unexpected Chrome evidence") })
                }
                #expect(calls == [Call(code: "guest", flags: 16, rule: "ordinary")])
            }
        }
    }
    @Test func identityGuestAndEveryOtherStrictErrorRemainRefusals() {
        for (identity, strict, guest) in [(OSStatus(1), OSStatus(-66999), OSStatus(0)), (0, -66999, 1), (0, 1, 0), (0, -67050, 0)] {
            #expect(throws: ScreenFailure.peerUntrusted) {
                try ScreenRunnerChromePolicy.validate("guest", identifier: "com.google.Chrome", site: .live, ordinary: "unused",
                    makeRule: { $0 }, bundle: { _ in "bundle" },
                    check: { _, flags, _ in flags == 9 ? identity : flags == 25 ? strict : guest }, record: { #expect(!$0.accepted) })
            }
        }
    }
    @Test func realAdapterAndCallerRoutesForwardExactNativePolicy() throws {
        let requirement = #"anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier "com.google.Chrome" and certificate leaf[subject.OU] = "EQHXZ8M8AV""#
        let executable = URL(fileURLWithPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        let sample = ScreenRunnerProcessSample(pid: 42, parent: 7, uid: 501, seconds: 123, microseconds: 456)
        for site in ScreenRunnerChromePolicy.Site.allCases {
            for strict in [OSStatus(0), -66999] {
                let trace = ScreenRunnerSecurityTrace(executable: executable, strict: strict)
                let calls = trace.calls
                let record: @Sendable (ScreenRunnerChromePolicy.Evidence) -> Void = { trace.record($0) }
                switch site {
                case .preflight:
                    #expect(try ScreenRunnerOwnedProcess.preflight(executable: executable, identifier: "com.google.Chrome", team: "EQHXZ8M8AV", calls: calls, chromeEvidence: record).members.map(\.identity.hash) == [trace.hash])
                case .initialLive:
                    let identity = try ScreenRunnerProcessIdentity.capture(pid: 42, role: .chrome, hash: trace.hash, identifier: "com.google.Chrome", team: "EQHXZ8M8AV", calls: calls, read: { _ in sample }, parent: 7, uid: 501, chromeEvidence: record)
                    #expect(identity.sample == sample)
                case .live:
                    let identity = ScreenRunnerProcessIdentity(sample: sample, role: .chrome, hash: trace.hash)
                    try identity.verify(identifier: "com.google.Chrome", team: "EQHXZ8M8AV", calls: calls, read: { sample }, chromeEvidence: record)
                case .liveCopy:
                    try ScreenRunnerOwnedProcess.verifyLiveCopy(pid: 42, executable: executable, identifier: "com.google.Chrome", team: "EQHXZ8M8AV", hash: trace.hash, calls: calls, chromeEvidence: record)
                case .signal:
                    try ScreenRunnerOwnedProcess.verifySignalRole(pid: 42, identifier: "com.google.Chrome", team: "EQHXZ8M8AV", hash: trace.hash, calls: calls, chromeEvidence: record)
                }
                let staticCalls = trace.events.filter { $0.kind == "static-check" }
                #expect(Array(staticCalls.prefix(3)) == [.init(kind: "static-check", value: "bundle", flags: 9, rule: requirement),
                                        .init(kind: "static-check", value: "bundle", flags: 25, rule: requirement),
                                        .init(kind: "static-check", value: "guest-static", flags: 0, rule: requirement)])
                #expect(Array(staticCalls.dropFirst(3)) == [.init(kind: "static-check", value: "slice-0", flags: 9, rule: requirement),
                                        .init(kind: "static-check", value: "slice-0", flags: 25, rule: requirement)])
                #expect(trace.events.filter { $0.kind == "rule" }.allSatisfy { $0.value == requirement })
                #expect(trace.events.filter { $0.kind == "static-create" && $0.value == "/Applications/Google Chrome.app" }.count == 1)
                #expect(trace.sites == [site])
                #expect(trace.accepted == [true])
                let dynamic = trace.events.filter { $0.kind == "dynamic-check" }
                #expect(dynamic.count == (site == .preflight ? 0 : 3))
                #expect(dynamic.allSatisfy { $0.flags == 0 && $0.rule == requirement })
                if site != .preflight {
                    #expect(try #require(trace.events.firstIndex(where: { $0.kind == "dynamic-check" })) < #require(trace.events.firstIndex(where: { $0.kind == "static-check" })))
                }
            }
        }
    }
    @Test func actualCallerBoundariesKeepDynamicHashAndPathFailuresClosed() throws {
        let executable = URL(fileURLWithPath: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        for failure in ["dynamic", "hash", "path"] {
            let trace = ScreenRunnerSecurityTrace(executable: executable, failure: failure)
            #expect(throws: ScreenFailure.peerUntrusted) {
                try ScreenRunnerOwnedProcess.verifyLiveCopy(pid: 42, executable: executable, identifier: "com.google.Chrome", team: "EQHXZ8M8AV", hash: trace.hash, calls: trace.calls, chromeEvidence: { trace.record($0) })
            }
            if failure == "dynamic" { #expect(!trace.events.contains { $0.kind == "static-check" }) }
        }
        for role in ["ai.sliccy.mac", "ai.sliccy.proof-helper", "com.apple.osascript"] {
            let trace = ScreenRunnerSecurityTrace(executable: executable, identifier: role)
            #expect(try ScreenRunnerOwnedProcess.preflight(executable: executable, identifier: role, team: role == "com.apple.osascript" ? nil : "S8LB56P782", calls: trace.calls, chromeEvidence: { trace.record($0) }).members.map(\.identity.hash) == [trace.hash])
            #expect(trace.events.filter { $0.kind == "static-check" }.map(\.flags) == [16, 25])
            #expect(trace.sites.isEmpty)
        }
    }

}
final class ScreenRunnerSecurityTrace: @unchecked Sendable {
    struct Event: Equatable {
        let kind: String, value: String
        var flags: UInt32 = 0
        var rule = ""
    }
    private let lock = NSLock()
    private var recorded: [Event] = []
    private var evidence: [ScreenRunnerChromePolicy.Evidence] = []
    let hash = Data(repeating: 1, count: 20)
    let executable: URL
    let strict: OSStatus
    let failure: String?
    let identifier: String
    init(executable: URL, strict: OSStatus = 0, failure: String? = nil, identifier: String = "com.google.Chrome") {
        self.executable = executable; self.strict = strict; self.failure = failure; self.identifier = identifier
    }
    func add(_ value: Event) { lock.lock(); recorded.append(value); lock.unlock() }
    func record(_ value: ScreenRunnerChromePolicy.Evidence) { lock.lock(); evidence.append(value); lock.unlock() }
    var events: [Event] { lock.lock(); defer { lock.unlock() }; return recorded }
    var sites: [ScreenRunnerChromePolicy.Site?] { lock.lock(); defer { lock.unlock() }; return evidence.map(\.site) }
    var accepted: [Bool] { lock.lock(); defer { lock.unlock() }; return evidence.map(\.accepted) }
    var calls: ScreenRunnerSecurityCalls<String, String, String> {
        .init(makeRule: { text in self.add(.init(kind: "rule", value: text)); return text },
              staticCode: { path in
                  self.add(.init(kind: "static-create", value: path.path))
                  return path.path == "/Applications/Google Chrome.app" ? "bundle" : "guest-static"
              }, guest: { pid in self.add(.init(kind: "guest", value: String(pid))); return "guest" },
              copyStatic: { guest in self.add(.init(kind: "static-copy", value: guest)); return "guest-static" },
              checkStatic: { code, flags, rule in
                  self.add(.init(kind: "static-check", value: code, flags: flags.rawValue, rule: rule))
                  return flags.rawValue == 25 ? self.strict : 0
              }, checkGuest: { code, flags, rule in
                  self.add(.init(kind: "dynamic-check", value: code, flags: flags.rawValue, rule: rule))
                  return self.failure == "dynamic" ? -67050 : 0
              }, information: { code in
                  self.add(.init(kind: "information", value: code))
                  return .init(hash: self.failure == "hash" ? Data() : self.hash,
                               path: self.failure == "path" ? URL(fileURLWithPath: "/changed") : self.executable,
                               identifier: self.identifier,
                               identity: .init(type: 2, hash: self.failure == "hash" ? Data() : self.hash, full: self.hash + Data(repeating: 2, count: 12)),
                               offset: code == "slice-0" ? 0 : nil)
              }, slices: .init(open: { path in
                  ScreenRunnerSliceBinding.Snapshot(path: path, slices: [.init(cpu: 16777228, subtype: 0, offset: 0, size: 64)], check: {})
              }, explicit: { _, _ in "slice-0" }, kernel: { _ in
                  .init(path: self.executable, hash: self.hash, flags: self.identifier.hasPrefix("com.apple.") ? 0x04000000 : 0)
              }, incarnation: { _ in ["42", "7", "501", "501", "501", "123", "456", "proc", "fixed-control-record"] }))
    }
}
#endif
