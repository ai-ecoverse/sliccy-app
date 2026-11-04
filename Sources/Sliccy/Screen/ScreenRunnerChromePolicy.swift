#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security

struct ScreenRunnerChromePolicy {
    static let identifier = "com.google.Chrome"
    static let team = "EQHXZ8M8AV"
    static let requirementText = "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate 1[field.1.2.840.113635.100.6.2.6] exists and identifier \"com.google.Chrome\" and certificate leaf[subject.OU] = \"EQHXZ8M8AV\""
    struct Evidence: Sendable {
        let identityStatus: OSStatus, strictStatus: OSStatus, guestStatus: OSStatus
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
    static func verify(_ guest: SecStaticCode, record: @Sendable (Evidence) -> Void) throws {
        let requirement = try requirement()
        var bundle: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: "/Applications/Google Chrome.app") as CFURL, [], &bundle) == errSecSuccess, let bundle else { throw ScreenFailure.peerUntrusted }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        let evidence = Evidence(identityStatus: SecStaticCodeCheckValidity(bundle, flags, requirement),
            strictStatus: SecStaticCodeCheckValidity(bundle, SecCSFlags(rawValue: flags.rawValue | kSecCSStrictValidate), requirement),
            guestStatus: SecStaticCodeCheckValidity(guest, [], requirement))
        record(evidence)
        guard evidence.accepted else { throw ScreenFailure.peerUntrusted }
    }
}
#endif
