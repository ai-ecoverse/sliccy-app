#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security

struct ScreenRunnerChromePolicy {
    enum Site: String, CaseIterable, Sendable { case preflight, initialLive = "initial-live", live, liveCopy = "live-copy", signal }
    static let identifier = "com.google.Chrome"
    static let team = "EQHXZ8M8AV"
    static let requirementText = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\""
    struct Evidence: Sendable {
        let identityStatus: OSStatus, strictStatus: OSStatus, guestStatus: OSStatus
        let observedAt: ContinuousClock.Instant = .now
        let site: Site?
        init(identityStatus: OSStatus, strictStatus: OSStatus, guestStatus: OSStatus, site: Site? = nil) {
            self.identityStatus = identityStatus; self.strictStatus = strictStatus; self.guestStatus = guestStatus; self.site = site
        }
        var accepted: Bool {
            identityStatus == errSecSuccess && guestStatus == errSecSuccess &&
                (strictStatus == errSecSuccess || strictStatus == errSecCSInvalidAssociatedFileData)
        }
        var fields: [String: Any] {
            ["identityStatus": identityStatus, "strictStatus": strictStatus, "guestStatus": guestStatus,
             "identityFlags": 9, "strictFlags": 25,
             "detritusTolerated": identityStatus == errSecSuccess && guestStatus == errSecSuccess && strictStatus == errSecCSInvalidAssociatedFileData]
        }
    }
    static func requirement() throws -> SecRequirement {
        var value: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &value) == errSecSuccess, let value else { throw ScreenFailure.peerUntrusted }
        return value
    }
    static func validate<Code, Rule>(_ guest: Code, identifier: String, site: Site, ordinary: Rule,
                                    makeRule: (String) throws -> Rule, bundle: (String) throws -> Code,
                                    check: (Code, UInt32, Rule) -> OSStatus, record: (Evidence) -> Void) throws {
        guard identifier == Self.identifier else {
            guard check(guest, 16, ordinary) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
            return
        }
        let requirement = try makeRule(requirementText)
        let all = try bundle("/Applications/Google Chrome.app")
        let evidence = Evidence(identityStatus: check(all, 9, requirement), strictStatus: check(all, 25, requirement),
                                guestStatus: check(guest, 0, requirement), site: site)
        record(evidence)
        guard evidence.accepted else { throw ScreenFailure.peerUntrusted }
    }
    static func verify(_ guest: SecStaticCode, identifier: String, site: Site, ordinary: SecRequirement,
                       record: @Sendable (Evidence) -> Void) throws {
        try verify(guest, identifier: identifier, site: site, ordinary: ordinary,
                   calls: ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>.native, record: record)
    }
    static func verify<Static, Guest, Rule>(_ guest: Static, identifier: String, site: Site, ordinary: Rule,
                                          calls: ScreenRunnerSecurityCalls<Static, Guest, Rule>,
                                          record: @Sendable (Evidence) -> Void) throws {
        guard (kSecCSCheckAllArchitectures | kSecCSCheckNestedCode) == 9,
              kSecCSStrictValidate == 16 else { throw ScreenFailure.incompatible }
        try validate(guest, identifier: identifier, site: site, ordinary: ordinary, makeRule: calls.makeRule,
                     bundle: { try calls.staticCode(URL(fileURLWithPath: $0)) },
                     check: { code, flags, rule in calls.checkStatic(code, SecCSFlags(rawValue: flags), rule) }, record: record)
    }
}
#endif
