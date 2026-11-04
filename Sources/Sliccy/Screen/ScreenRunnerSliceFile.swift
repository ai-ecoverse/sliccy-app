#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Darwin

enum ScreenRunnerSliceFile {
    static func slices(_ data: Data) throws -> [ScreenRunnerSliceBinding.Slice] {
        guard data.startIndex == 0, (28...(128 * 1024 * 1024)).contains(data.count) else { throw ScreenFailure.peerUntrusted }
        func u32(_ p: Int, _ big: Bool) throws -> UInt32 {
            guard p >= 0, p <= data.count - 4 else { throw ScreenFailure.peerUntrusted }
            let a = Array(data[p..<(p + 4)])
            return big ? UInt32(a[0]) << 24 | UInt32(a[1]) << 16 | UInt32(a[2]) << 8 | UInt32(a[3]) :
                UInt32(a[3]) << 24 | UInt32(a[2]) << 16 | UInt32(a[1]) << 8 | UInt32(a[0])
        }
        func u64(_ p: Int, _ big: Bool) throws -> UInt64 {
            let a = try u32(p, big), b = try u32(p + 4, big)
            return big ? UInt64(a) << 32 | UInt64(b) : UInt64(b) << 32 | UInt64(a)
        }
        let magic = try u32(0, true)
        let fat = [0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].contains(magic)
        let big = [0xcafebabe, 0xcafebabf].contains(magic), wide = [0xcafebabf, 0xbfbafeca].contains(magic)
        let count = fat ? Int(try u32(4, big)) : 1, stride = wide ? 32 : 20
        guard (1...8).contains(count), !fat || 8 + count * stride <= data.count else { throw ScreenFailure.peerUntrusted }
        var result: [ScreenRunnerSliceBinding.Slice] = []
        for index in 0..<count {
            let entry = fat ? 8 + index * stride : 0
            let offset: UInt64 = fat ? (wide ? try u64(entry + 8, big) : UInt64(try u32(entry + 8, big))) : 0
            let size: UInt64 = fat ? (wide ? try u64(entry + 16, big) : UInt64(try u32(entry + 12, big))) : UInt64(data.count)
            let alignment = fat ? try u32(entry + (wide ? 24 : 16), big) : 0
            guard alignment <= 30, offset % (UInt64(1) << alignment) == 0, size >= 28,
                  offset <= UInt64(data.count), size <= UInt64(data.count) - offset,
                  !fat || offset >= UInt64(8 + count * stride) else { throw ScreenFailure.peerUntrusted }
            if fat && wide { guard try u32(entry + 28, big) == 0 else { throw ScreenFailure.peerUntrusted } }
            let thin = try u32(Int(offset), true), thinBig = [UInt32(0xfeedface), 0xfeedfacf].contains(thin)
            guard thinBig || [UInt32(0xcefaedfe), 0xcffaedfe].contains(thin),
                  ![UInt32(0xfeedfacf), 0xcffaedfe].contains(thin) || size >= 32 else { throw ScreenFailure.peerUntrusted }
            let cpu = Int32(bitPattern: try u32(Int(offset) + 4, thinBig)), subtype = Int32(bitPattern: try u32(Int(offset) + 8, thinBig))
            if fat {
                guard cpu == Int32(bitPattern: try u32(entry, big)), subtype == Int32(bitPattern: try u32(entry + 4, big)) else { throw ScreenFailure.peerUntrusted }
            }
            guard !result.contains(where: { (offset < $0.offset + $0.size && $0.offset < offset + size) || ($0.cpu == cpu && $0.subtype == subtype) }) else { throw ScreenFailure.peerUntrusted }
            result.append(.init(cpu: cpu, subtype: subtype, offset: offset, size: size))
        }
        return result
    }
    static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_mode & S_IFMT == S_IFREG && b.st_mode & S_IFMT == S_IFREG && a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
            a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
            a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    static func open(_ path: URL) throws -> ScreenRunnerSliceBinding.Snapshot {
        guard path.isFileURL, let canonical = realpath(path.path, nil) else { throw ScreenFailure.peerUntrusted }
        defer { free(canonical) }
        guard String(cString: canonical) == path.path else { throw ScreenFailure.peerUntrusted }
        let fd = Darwin.open(path.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw ScreenFailure.peerUntrusted }
        var retained = false
        defer { if !retained { close(fd) } }
        var first = stat(), current = stat()
        guard fstat(fd, &first) == 0, stat(path.path, &current) == 0, same(first, current),
              first.st_size >= 28, first.st_size <= 128 * 1024 * 1024 else { throw ScreenFailure.peerUntrusted }
        var data = Data(count: Int(first.st_size))
        let count = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        guard count == data.count, fstat(fd, &current) == 0, same(first, current) else { throw ScreenFailure.peerUntrusted }
        let parsed = try slices(data)
        let original = first
        let metadata = [String(first.st_dev), String(first.st_ino), String(first.st_size), String(first.st_mode), String(first.st_mtimespec.tv_sec), String(first.st_mtimespec.tv_nsec), String(first.st_ctimespec.tv_sec), String(first.st_ctimespec.tv_nsec)]
        let snapshot = ScreenRunnerSliceBinding.Snapshot(path: path, slices: parsed, metadata: metadata, check: {
            var observed = stat(), name = stat()
            guard fstat(fd, &observed) == 0, stat(path.path, &name) == 0, same(original, observed), same(original, name) else { throw ScreenFailure.peerUntrusted }
        }, release: { close(fd) })
        try snapshot.recheck(); retained = true
        return snapshot
    }
}
#endif
