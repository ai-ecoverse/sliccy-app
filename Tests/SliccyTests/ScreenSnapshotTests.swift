#if SLICCY_SNAPSHOT_PROOF
import Foundation
import CryptoKit
import Testing
@testable import Sliccy

struct ScreenSnapshotTests {
    private func fixture() -> Data {
        var bytes = Data(repeating: 0, count: 8448)
        func put(_ value: UInt32, _ offset: Int, big: Bool = false) {
            var n = big ? value.bigEndian : value.littleEndian
            withUnsafeBytes(of: &n) { bytes.replaceSubrange(offset..<offset + 4, with: $0) }
        }
        put(0xfeedfacf, 0); put(0x0100000c, 4); put(2, 12); put(2, 16); put(88, 20)
        put(0x19, 32); put(72, 36)
        bytes.replaceSubrange(40..<50, with: "__LINKEDIT".utf8)
        put(4096, 72); put(4352, 80); put(1, 92)
        put(0x1d, 104); put(16, 108); put(8192, 112); put(256, 116)
        put(0xfade0cc0, 8192, big: true); put(244, 8196, big: true); put(1, 8200, big: true)
        put(0, 8204, big: true); put(20, 8208, big: true)
        let cd = 8212
        put(0xfade0c02, cd, big: true); put(224, cd + 4, big: true); put(0x20500, cd + 8, big: true)
        put(160, cd + 16, big: true); put(2, cd + 24, big: true); put(2, cd + 28, big: true); put(8192, cd + 32, big: true)
        bytes[cd + 36] = 32; bytes[cd + 37] = 2; bytes[cd + 39] = 12
        for slot in 0..<2 {
            let start = cd + 160 + slot * 32
            let pageStart = slot * 4096
            let digest = Data(SHA256.hash(data: bytes[pageStart..<(pageStart + 4096)]))
            bytes.replaceSubrange(start..<(start + 32), with: digest)
        }
        return bytes
    }
    @Test func coveredPageChangeIsDetectedWithoutChangingSignature() throws {
        let original = fixture()
        let map = try ScreenSnapshotRecipe.mapping(original)
        #expect(map.codeLimit == 8192 && map.mismatchedPages == 0)
        var changed = original; changed[8191] ^= 1
        #expect(throws: ScreenFailure.incompatible) { try ScreenSnapshotRecipe.mapping(changed) }
        let observed = try ScreenSnapshotRecipe.mapping(changed, requirePageMatch: false)
        #expect(observed.mismatchedPages == 1 && observed.lastPageMismatched)
        #expect(observed.codeDirectorySHA == map.codeDirectorySHA)
        #expect(throws: ScreenFailure.incompatible) { try ScreenSnapshotRecipe.validate(original) }
    }
    @Test func malformedRangesVersionsAndPageParametersFail() {
        let source = fixture()
        for offset in [0, 4, 12, 16, 20, 36, 80, 92, 112, 116, 8196, 8200, 8208,
                       8212 + 4, 8212 + 8, 8212 + 16, 8212 + 28, 8212 + 32, 8212 + 36, 8212 + 37, 8212 + 39, 8212 + 44] {
            var bad = source; bad[offset] ^= 0xff
            #expect(throws: ScreenFailure.incompatible) { try ScreenSnapshotRecipe.mapping(bad) }
        }
        for size in [0, 31, 127, 4096, 8192, 8220, 8435] {
            #expect(throws: ScreenFailure.incompatible) { try ScreenSnapshotRecipe.mapping(Data(source.prefix(size))) }
        }
    }
    @Test func snapshotCasesAreClosedAndCannotChoosePaths() throws {
        #expect(try ScreenSnapshotCase.parse(["--screen-proof", "--case", "snapshot-mutation"]) == .mutation)
        #expect(try ScreenSnapshotCase.parse(["--screen-proof", "--case", "snapshot-replacement"]) == .replacement)
        for args in [["--screen-proof"], ["--screen-proof", "--case", "/tmp/file"],
                     ["--screen-proof", "--case", "snapshot-mutation", "--offset", "1"]] {
            #expect(throws: ScreenFailure.incompatible) { try ScreenSnapshotCase.parse(args) }
        }
    }
    @Test func verifierResultsAreUniquePerComponent() throws {
        var results = ScreenSnapshotResults()
        #expect(throws: ScreenFailure.incompatible) { try results.end(.guest) }
        try results.start(.guest); try results.end(.guest)
        #expect(!results.complete)
        #expect(throws: ScreenFailure.incompatible) { try results.start(.guest) }
        #expect(throws: ScreenFailure.incompatible) { try results.end(.guest) }
        try results.start(.endpoint); try results.end(.endpoint)
        #expect(results.complete)
    }
}
#endif
