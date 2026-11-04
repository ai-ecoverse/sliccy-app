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
}
#endif
