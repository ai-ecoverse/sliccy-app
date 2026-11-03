#if SLICCY_SNAPSHOT_PROOF
import Foundation
import Darwin
import Testing
@testable import Sliccy

struct ScreenSnapshotCleanupTests {
    private func temporary() throws -> URL {
        var template = Array("/private/tmp/sliccy-cleanup-test.XXXXXXXX".utf8CString)
        guard mkdtemp(&template) != nil else { throw ScreenFailure.audit }
        return URL(fileURLWithPath: String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
    }
    private func directory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    private func populated(_ base: URL) throws -> URL {
        let root = base.appending(path: "home")
        for path in ["tmp/slicc-501", "config", "Library/Application Support/slicc/audit", "Library/Application Support/ai.sliccy.mac/Audit"] {
            try directory(root.appending(path: path))
        }
        for path in ["candidate", "replacement", "tmp/slicc-501/test-state", "config/state", "Library/Application Support/slicc/cert.pem", "Library/Application Support/slicc/state.json", "Library/Application Support/slicc/audit/broker-20261103-test.jsonl", "Library/Application Support/ai.sliccy.mac/Audit/quota.lock"] {
            try Data("test-owned fixture".utf8).write(to: root.appending(path: path))
        }
        guard link(root.appending(path: "candidate").path, root.appending(path: "baseline").path) == 0 else { throw ScreenFailure.audit }
        return root
    }
    private func clean(_ root: URL) throws {
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ScreenFailure.audit }; defer { close(fd) }
        var expected = stat()
        guard fstat(fd, &expected) == 0 else { throw ScreenFailure.audit }
        try ScreenSnapshotCleanup.removeContents(directory: fd, expected: expected)
        guard rmdir(root.path) == 0 else { throw ScreenFailure.audit }
    }
    @Test func actualDarwinConfigFootprintIsRemovedWithoutTouchingOutsideSentinel() throws {
        let base = try temporary(); defer { try? FileManager.default.removeItem(at: base) }
        let root = try populated(base), sentinel = base.appending(path: "outside-sentinel")
        let expected = Data("outside content remains".utf8)
        try expected.write(to: sentinel)
        try clean(root)
        #expect(!FileManager.default.fileExists(atPath: root.path))
        #expect(try Data(contentsOf: sentinel) == expected)
    }
    @Test func symlinksAtRootAndInsideAuditRefuseBeforeAnyDeletion() throws {
        for linkPath in ["Library", "Library/Application Support/slicc/audit/escape", "candidate"] {
            let base = try temporary(); defer { try? FileManager.default.removeItem(at: base) }
            let root = try populated(base), outside = base.appending(path: "outside")
            try directory(outside)
            let sentinel = outside.appending(path: "sentinel"), expected = Data("not touched".utf8)
            try expected.write(to: sentinel)
            let linkURL = root.appending(path: linkPath)
            if FileManager.default.fileExists(atPath: linkURL.path) { try FileManager.default.removeItem(at: linkURL) }
            guard symlink(outside.path, linkURL.path) == 0 else { throw ScreenFailure.audit }
            #expect(throws: ScreenFailure.audit) { try clean(root) }
            #expect(try Data(contentsOf: sentinel) == expected)
            #expect(FileManager.default.fileExists(atPath: root.appending(path: "replacement").path))
            var value = stat()
            #expect(lstat(linkURL.path, &value) == 0 && value.st_mode & S_IFMT == S_IFLNK)
        }
    }
    @Test func outsideHardlinkAndUnexpectedLibrarySubtreeRefuse() throws {
        for hardlink in [false, true] {
            let base = try temporary(); defer { try? FileManager.default.removeItem(at: base) }
            let root = try populated(base), sentinel = base.appending(path: "outside-sentinel")
            let expected = Data("keep".utf8); try expected.write(to: sentinel)
            if hardlink {
                guard link(sentinel.path, root.appending(path: "Library/Application Support/slicc/audit/escape").path) == 0 else { throw ScreenFailure.audit }
            } else { try directory(root.appending(path: "Library/Unrelated")) }
            #expect(throws: ScreenFailure.audit) { try clean(root) }
            #expect(try Data(contentsOf: sentinel) == expected)
            #expect(FileManager.default.fileExists(atPath: root.appending(path: "candidate").path))
        }
    }
}
#endif
