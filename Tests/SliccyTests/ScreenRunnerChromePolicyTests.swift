#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security
import Testing
@testable import Sliccy

struct ScreenRunnerChromePolicyTests {
    @Test func exactDetritusRequiresValidGoogleIdentityAndGuest() {
        for strict in [errSecSuccess, errSecCSInvalidAssociatedFileData] {
            let value = ScreenRunnerChromePolicy.Evidence(identityStatus: errSecSuccess, strictStatus: strict, guestStatus: errSecSuccess)
            #expect(value.accepted)
            #expect(value.fields["detritusTolerated"] as? Bool == (strict == errSecCSInvalidAssociatedFileData))
        }
        for error in [errSecCSReqFailed, errSecCSBadResource, errSecCSResourcesInvalid, errSecCSUnsigned, errSecParam] {
            #expect(!ScreenRunnerChromePolicy.Evidence(identityStatus: error, strictStatus: errSecCSInvalidAssociatedFileData, guestStatus: errSecSuccess).accepted)
            #expect(!ScreenRunnerChromePolicy.Evidence(identityStatus: errSecSuccess, strictStatus: error, guestStatus: errSecSuccess).accepted)
            #expect(!ScreenRunnerChromePolicy.Evidence(identityStatus: errSecSuccess, strictStatus: errSecCSInvalidAssociatedFileData, guestStatus: error).accepted)
        }
        #expect(ScreenRunnerChromePolicy.requirementText.contains("identifier \"com.google.Chrome\""))
        #expect(ScreenRunnerChromePolicy.requirementText.contains("certificate leaf[subject.OU] = \"EQHXZ8M8AV\""))
        #expect(ScreenRunnerChromePolicy.requirementText.contains("anchor apple generic"))
    }
}
#endif
