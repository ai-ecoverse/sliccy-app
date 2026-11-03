#if SLICCY_SNAPSHOT_PROOF
import Foundation
import CryptoKit

/// Closed byte recipe for exactly the approved arm64 release. No caller offset.
/// Parsing is pure; executing this type never writes or launches anything.
struct ScreenSnapshotRecipe {
    static let armSHA = "0055c051f48364dbf6d3744c637a06353305a392d06edbedd96bd6764adb5a73"
    static let intelSHA = "9ff520697095ce930cc25d4a5e208a72eb82a072211fd7b9bbd6da2b9b78278e"
    static let armCD = "5da1a3199bd3f895bce2e53023c28ca1c33d249e2cf402c81cb1ad0bb4666eb9"
    static let intelCD = "bf246edfa276fa4242db674e139a8722706336734919f42ffe71ade12adfb762"
    static let offset = 17_947_039
    static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    static func validate(_ data: Data) throws {
        guard digest(data) == armSHA else { throw ScreenFailure.incompatible }
        let map = try mapping(data)
        guard map.signature == offset + 1, map.codeLimit == offset + 1,
              map.linkOffset == 17_514_496, map.linkSize == 589_216, map.linkProtection == 1,
              map.codeDirectorySHA == armCD, data[offset] == 0 else { throw ScreenFailure.incompatible }
    }
    static func validateChanged(_ data: Data, original: Data) throws {
        try validate(original)
        guard data.count == original.count, data[offset] == 1,
              data.prefix(offset) == original.prefix(offset), data.suffix(from: offset + 1) == original.suffix(from: offset + 1) else {
            throw ScreenFailure.incompatible
        }
        // The fixed last partial page must now disagree with its unchanged slot.
        let map = try mapping(data, requirePageMatch: false)
        guard map.mismatchedPages == 1, map.lastPageMismatched, map.codeDirectorySHA == armCD else { throw ScreenFailure.incompatible }
    }
    struct Mapping {
        let signature: Int, codeLimit: Int, linkOffset: Int, linkSize: Int, linkProtection: UInt32
        let codeDirectorySHA: String, mismatchedPages: Int, lastPageMismatched: Bool
    }
    /// Internal pure parser also accepts bounded synthetic fixtures for tests.
    /// Only validate() above authorizes the release-specific mutation recipe.
    static func mapping(_ data: Data, requirePageMatch: Bool = true) throws -> Mapping {
        func require(_ condition: Bool) throws { guard condition else { throw ScreenFailure.incompatible } }
        func u32(_ offset: Int, big: Bool = false) throws -> UInt32 {
            try require(offset >= 0 && offset <= data.count - 4)
            let bytes = data[offset..<offset + 4]
            return (big ? Array(bytes) : Array(bytes.reversed())).reduce(0) { ($0 << 8) | UInt32($1) }
        }
        func u64(_ offset: Int) throws -> UInt64 {
            try require(offset >= 0 && offset <= data.count - 8)
            return data[offset..<offset + 8].reversed().reduce(0) { ($0 << 8) | UInt64($1) }
        }
        try require(data.count >= 128 && data.count <= 32 * 1024 * 1024)
        try require(try u32(0) == 0xfeedfacf && u32(4) == 0x0100000c && u32(8) == 0 && u32(12) == 2)
        let commands = Int(try u32(16)), commandBytes = Int(try u32(20))
        try require(commands <= 4096 && commandBytes <= 1024 * 1024 && commandBytes <= data.count - 32)
        var cursor = 32, signature: (Int, Int)?, link: (Int, Int, UInt32)?
        for _ in 0..<commands {
            try require(cursor <= 32 + commandBytes - 8)
            let command = try u32(cursor), size = Int(try u32(cursor + 4))
            try require(size >= 8 && size % 8 == 0 && size <= 32 + commandBytes - cursor)
            if command == 0x1d {
                try require(size == 16 && signature == nil)
                signature = (Int(try u32(cursor + 8)), Int(try u32(cursor + 12)))
            }
            if command == 0x19 {
                try require(size >= 72)
                let name = data[(cursor + 8)..<(cursor + 24)]
                if Array(name) == Array("__LINKEDIT".utf8) + [UInt8](repeating: 0, count: 6) {
                    try require(link == nil)
                    let start = try u64(cursor + 40), length = try u64(cursor + 48)
                    try require(start <= UInt64(data.count) && length <= UInt64(data.count) - start)
                    link = (Int(start), Int(length), try u32(cursor + 60))
                }
            }
            cursor += size
        }
        try require(cursor == 32 + commandBytes)
        guard let (sig, sigSize) = signature, let (linkStart, linkSize, protection) = link else { throw ScreenFailure.incompatible }
        try require(sig >= cursor && sig <= data.count - 12 && sigSize >= 12 && sigSize <= data.count - sig)
        try require(try u32(sig, big: true) == 0xfade0cc0)
        let superSize = Int(try u32(sig + 4, big: true)), count = Int(try u32(sig + 8, big: true))
        try require(superSize >= 12 && superSize <= sigSize && count <= 32 && count * 8 <= superSize - 12)
        var codeDirectory: Range<Int>?, ranges: [Range<Int>] = [], types = Set<UInt32>()
        for index in 0..<count {
            let type = try u32(sig + 12 + index * 8, big: true), relative = Int(try u32(sig + 16 + index * 8, big: true))
            try require(types.insert(type).inserted && relative >= 12 + count * 8 && relative <= superSize - 8)
            let start = sig + relative, length = Int(try u32(start + 4, big: true))
            try require(length >= 8 && length <= superSize - relative)
            let range = start..<start + length
            try require(!ranges.contains { $0.overlaps(range) }); ranges.append(range)
            if try u32(start, big: true) == 0xfade0c02 {
                try require(type == 0 && codeDirectory == nil); codeDirectory = range
            }
        }
        guard let cd = codeDirectory else { throw ScreenFailure.incompatible }
        let base = cd.lowerBound
        try require(cd.count >= 96 && u32(base + 8, big: true) == 0x20500)
        let hashOffset = Int(try u32(base + 16, big: true)), special = Int(try u32(base + 24, big: true))
        let slots = Int(try u32(base + 28, big: true)), codeLimit = Int(try u32(base + 32, big: true))
        try require(data[base + 36] == 32 && data[base + 37] == 2 && data[base + 39] == 12)
        try require(try u32(base + 44, big: true) == 0 && u32(base + 52, big: true) == 0 && u32(base + 56, big: true) == 0 && u32(base + 60, big: true) == 0 && u32(base + 92, big: true) == 0)
        try require(codeLimit == sig && codeLimit > cursor && codeLimit > linkStart && codeLimit <= linkStart + linkSize && protection == 1)
        try require(slots == (codeLimit + 4095) / 4096 && special <= 32 && hashOffset >= 96 + special * 32 && hashOffset <= cd.count && slots <= (cd.count - hashOffset) / 32)
        var mismatches = 0, lastMismatch = false
        for slot in 0..<slots {
            let start = slot * 4096, end = min(start + 4096, codeLimit)
            let hash = Data(SHA256.hash(data: data[start..<end])), expected = data[(base + hashOffset + slot * 32)..<(base + hashOffset + (slot + 1) * 32)]
            if hash != expected { mismatches += 1; if slot == slots - 1 { lastMismatch = true } }
        }
        try require(!requirePageMatch || mismatches == 0)
        return Mapping(signature: sig, codeLimit: codeLimit, linkOffset: linkStart, linkSize: linkSize,
                       linkProtection: protection, codeDirectorySHA: digest(data[cd]), mismatchedPages: mismatches, lastPageMismatched: lastMismatch)
    }
}
#endif
