import Foundation

/// Launch permission is separate from permission to grant a capture source.
enum ScreenLaunchPolicy: Sendable {
    case production
#if SLICCY_NATIVE_SCREEN_PROOF
    case noCaptureProof(root: URL)
#endif

    var hashes: Set<Data> {
        switch self {
        case .production: return ScreenReleasePolicy.cliCodeDirectoryHashes
#if SLICCY_NATIVE_SCREEN_PROOF
        case .noCaptureProof:
            // Exact checksum-verified v1.59.0 release slices; diagnostic IPC only.
#if arch(arm64)
            let hex = "5da1a3199bd3f895bce2e53023c28ca1c33d249e"
#elseif arch(x86_64)
            let hex = "bf246edfa276fa4242db674e139a872270633673"
#else
            return []
#endif
            return [Data(stride(from: 0, to: hex.count, by: 2).map {
                let start = hex.index(hex.startIndex, offsetBy: $0)
                return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
            })]
#endif
        }
    }
    var allowsIPC: Bool {
        switch self {
        case .production: ScreenReleasePolicy.identityProofApproved && !hashes.isEmpty
#if SLICCY_NATIVE_SCREEN_PROOF
        case .noCaptureProof: !hashes.isEmpty
#endif
        }
    }
    var environment: [String] {
        switch self {
        case .production:
            return ["PATH=/usr/bin:/bin", "HOME=" + FileManager.default.homeDirectoryForCurrentUser.path,
                    "TMPDIR=" + NSTemporaryDirectory(), "LANG=en_US.UTF-8"]
#if SLICCY_NATIVE_SCREEN_PROOF
        case .noCaptureProof(let root):
            return ["PATH=/usr/bin:/bin", "HOME=" + root.path, "TMPDIR=" + root.appending(path: "tmp").path + "/",
                    "SLICC_USER_DATA_DIR=" + root.appending(path: "config").path,
                    "SLICC_NO_TELEMETRY=1", "SLICC_NO_UPDATE_CHECK=1", "LANG=en_US.UTF-8"]
#endif
        }
    }
}
