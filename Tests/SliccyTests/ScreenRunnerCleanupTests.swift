#if SLICCY_CAPTURE_RUNNER_PROOF
import Darwin
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerCleanupTests {
    private func fixture() throws -> URL {
        var name = Array("/private/tmp/sliccy-runner-cleanup-test.XXXXXXXX".utf8CString)
        guard mkdtemp(&name) != nil else { throw ScreenFailure.audit }
        return URL(fileURLWithPath: String(decoding: name.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
    }
    private func populate(_ base: URL) throws -> URL {
        let root = base.appending(path: "home")
        for path in ["tmp", "config/chrome-a", "config/browser-home/Library/Caches", "Library/Application Support/slicc/audit", "Library/Application Support/ai.sliccy.mac/Audit"] {
            try FileManager.default.createDirectory(at: root.appending(path: path), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        for path in ["config/chrome-a/Preferences", "Library/Application Support/slicc/cert.pem", "Library/Application Support/slicc/audit/broker-test.jsonl", "Library/Application Support/ai.sliccy.mac/Audit/quota.lock"] {
            try Data("owned fixture".utf8).write(to: root.appending(path: path))
            guard chmod(root.appending(path: path).path, 0o600) == 0 else { throw ScreenFailure.audit }
        }
        return root
    }
    private func clean(_ root: URL) throws {
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ScreenFailure.audit }; defer { close(fd) }
        var expected = stat()
        guard fstat(fd, &expected) == 0 else { throw ScreenFailure.audit }
        try ScreenRunnerCleanup.removeContents(directory: fd, expected: expected)
        guard rmdir(root.path) == 0 else { throw ScreenFailure.audit }
    }
    @Test func profileSymlinksAreUnlinkedWithoutFollowingOutsideTargets() throws {
        let base = try fixture(); defer { try? FileManager.default.removeItem(at: base) }
        let root = try populate(base), outside = base.appending(path: "outside")
        try Data("sentinel".utf8).write(to: outside)
        #expect(symlink(outside.path, root.appending(path: "config/chrome-a/SingletonCookie").path) == 0)
        #expect(symlink("/unresolved/not-owned", root.appending(path: "tmp/SingletonSocket").path) == 0)
        try clean(root)
        #expect(try Data(contentsOf: outside) == Data("sentinel".utf8))
        #expect(!FileManager.default.fileExists(atPath: root.path))
    }
    @Test func externalHardlinkRefusesEntireTreeBeforeDeletion() throws {
        let base = try fixture(); defer { try? FileManager.default.removeItem(at: base) }
        let root = try populate(base), outside = base.appending(path: "outside")
        try Data("sentinel".utf8).write(to: outside)
        #expect(chmod(outside.path, 0o600) == 0)
        #expect(link(outside.path, root.appending(path: "config/chrome-a/linked").path) == 0)
        #expect(throws: ScreenFailure.audit) { try clean(root) }
        #expect(FileManager.default.fileExists(atPath: root.appending(path: "config/chrome-a/Preferences").path))
        #expect(try Data(contentsOf: outside) == Data("sentinel".utf8))
    }
    @Test func unknownRootAndLibrarySymlinkRefuseWithoutTraversal() throws {
        for path in ["unexpected", "Library/Application Support/slicc/link"] {
            let base = try fixture(); defer { try? FileManager.default.removeItem(at: base) }
            let root = try populate(base), outside = base.appending(path: "outside")
            try Data("sentinel".utf8).write(to: outside)
            #expect(symlink(outside.path, root.appending(path: path).path) == 0)
            #expect(throws: ScreenFailure.audit) { try clean(root) }
            #expect(try Data(contentsOf: outside) == Data("sentinel".utf8))
        }
    }
}
#endif
