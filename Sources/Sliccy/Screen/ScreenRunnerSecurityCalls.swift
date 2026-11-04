#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security

struct ScreenRunnerSecurityCalls<Static, Guest, Rule> {
    struct Information {
        let hash: Data?
        let path: URL?
    }
    let makeRule: (String) throws -> Rule
    let staticCode: (URL) throws -> Static
    let guest: (pid_t) throws -> Guest
    let copyStatic: (Guest) throws -> Static
    let checkStatic: (Static, SecCSFlags, Rule) -> OSStatus
    let checkGuest: (Guest, SecCSFlags, Rule) -> OSStatus
    let information: (Static) throws -> Information
}

extension ScreenRunnerSecurityCalls where Static == SecStaticCode, Guest == SecCode, Rule == SecRequirement {
    static var native: Self {
        .init(makeRule: { text in
            var rule: SecRequirement?
            guard SecRequirementCreateWithString(text as CFString, [], &rule) == errSecSuccess, let rule else { throw ScreenFailure.peerUntrusted }
            return rule
        }, staticCode: { path in
            var code: SecStaticCode?
            guard SecStaticCodeCreateWithPath(path as CFURL, [], &code) == errSecSuccess, let code else { throw ScreenFailure.peerUntrusted }
            return code
        }, guest: { pid in
            var code: SecCode?
            guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &code) == errSecSuccess, let code else { throw ScreenFailure.peerUntrusted }
            return code
        }, copyStatic: { guest in
            var code: SecStaticCode?
            guard SecCodeCopyStaticCode(guest, [], &code) == errSecSuccess, let code else { throw ScreenFailure.peerUntrusted }
            return code
        }, checkStatic: SecStaticCodeCheckValidity, checkGuest: SecCodeCheckValidity, information: { code in
            var info: CFDictionary?
            guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
            let values = info as? [String: Any]
            return .init(hash: values?[kSecCodeInfoUnique as String] as? Data,
                         path: values?[kSecCodeInfoMainExecutable as String] as? URL)
        })
    }
}
#endif
