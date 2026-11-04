#if SLICCY_CAPTURE_RUNNER_PROOF
import Darwin
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerKernelBoundaryTests {
    let original = ScreenRunnerKernelSample(pid: 42, parent: 1, uid: 88, seconds: 123, microseconds: 456)
    func observation(_ before: ScreenRunnerKernelSample?, _ after: ScreenRunnerKernelSample?) -> ScreenRunnerSystemOwner.Observation {
        let code = ScreenRunnerSystemOwner.Code(identifier: "com.apple.WindowServer", path: "/fixed/WindowServer", hash: Data(repeating: 1, count: 20))
        return .init(before: before, beforeError: before == nil ? EPERM : 0, after: after, afterError: after == nil ? EPERM : 0,
                     code: code, kernelPath: code.path, kernelHash: code.hash)
    }
    @Test func everyAvailableBSDFieldMustMatchPrivilegedBrackets() throws {
        let conflicts: [ScreenRunnerKernelSample] = [
            .init(pid: 43, parent: 1, uid: 88, seconds: 123, microseconds: 456),
            .init(pid: 42, parent: 2, uid: 88, seconds: 123, microseconds: 456),
            .init(pid: 42, parent: 1, uid: 89, seconds: 123, microseconds: 456),
            .init(pid: 42, parent: 1, uid: 88, seconds: 124, microseconds: 456),
            .init(pid: 42, parent: 1, uid: 88, seconds: 123, microseconds: 457)]
        for conflict in conflicts {
            for pair in [(Optional(conflict), nil), (nil, Optional(conflict)), (Optional(original), Optional(conflict)), (Optional(conflict), Optional(original))] {
                #expect(throws: ScreenFailure.peerUntrusted) {
                    try ScreenRunnerSystemOwner.bind(observation(pair.0, pair.1), pid: 42, privileged: original)
                }
            }
        }
        for pair in [(nil, nil), (Optional(original), nil), (nil, Optional(original)), (Optional(original), Optional(original))] {
            #expect(try ScreenRunnerSystemOwner.bind(observation(pair.0, pair.1), pid: 42, privileged: original) == original)
        }
    }
    @Test func deniedOrUnavailableDoesNotCreateNormalIdentity() {
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerSystemOwner.bind(observation(nil, nil), pid: 42) }
        let normal = observation(original, original)
        let other = ScreenRunnerSystemOwner.Observation(before: nil, beforeError: ESRCH, after: original, afterError: 0,
            code: normal.code, kernelPath: normal.kernelPath, kernelHash: normal.kernelHash)
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerSystemOwner.bind(other, pid: 42, privileged: original) }
    }
    @Test func onlyCanonicalNumericTargetAndRootAreAcceptedByEntryParser() throws {
        #expect(try ScreenRunnerKernelChild.parse(["--runner-kernel", "42"], uid: 0) == 42)
        for arguments in [["--runner-kernel", "0"], ["--runner-kernel", "-1"], ["--runner-kernel", "042"],
                          ["--runner-kernel", "+42"], ["--runner-kernel", "42", "other"], ["--runner-kernel", "/path"],
                          ["--runner-kernel", "2147483648"], ["--other", "42"]] {
            #expect(throws: ScreenFailure.incompatible) { try ScreenRunnerKernelChild.parse(arguments, uid: 0) }
        }
        #expect(throws: ScreenFailure.incompatible) { try ScreenRunnerKernelChild.parse(["--runner-kernel", "42"], uid: 501) }
    }
    @Test func stagedExecutableHasOneFixedNamespaceAndNoOverride() throws {
        let valid = "/Library/SliccyProof-123/Sliccy.app/Contents/MacOS/Sliccy"
        #expect(try ScreenRunnerKernelChild.stagedComponents(valid).count == 7)
        for path in ["/tmp/SliccyProof-123/Sliccy.app/Contents/MacOS/Sliccy", valid + "/extra",
                     "/Library/SliccyProof-0/Sliccy.app/Contents/MacOS/Sliccy",
                     "/Library/SliccyProof-0123/Sliccy.app/Contents/MacOS/Sliccy",
                     "/Library/SliccyProof-123/../SliccyProof-456/Sliccy.app/Contents/MacOS/Sliccy",
                     "/Library/SliccyProof-123/Sliccy.app/Contents/MacOS/Other"] {
            #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerKernelChild.stagedComponents(path) }
        }
    }
}
#endif
