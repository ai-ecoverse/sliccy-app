#if SLICCY_SNAPSHOT_PROOF
import Foundation
import Darwin
import Security

enum ScreenSnapshotCase: String, Sendable {
    case mutation = "snapshot-mutation", replacement = "snapshot-replacement"
    static func parse(_ arguments: [String]) throws -> Self {
        guard arguments.count == 3, arguments[0] == "--screen-proof", arguments[1] == "--case",
              let value = Self(rawValue: arguments[2]) else { throw ScreenFailure.incompatible }
        return value
    }
}

/// Opaque, fixed provenance. The sole factory accepts only a closed case enum.
/// A disposable copy is the ONLY file this object can authorize for launch.
final class ScreenSnapshotSubject: @unchecked Sendable {
    enum Change { case completed, denied(String) }
    let root: URL
    let selected: ScreenSnapshotCase
    private let directory: Int32, retained: Int32
    private let original: Data
    private let originalStat: stat
    private let directoryStat: stat
    private var replacementStat: stat?
    private var attempted = false, launchClaimed = false, cleaned = false
    private let lock = NSLock()

    static func prepare(_ selected: ScreenSnapshotCase) throws -> ScreenSnapshotSubject {
        let resources = Bundle.main.bundleURL.appending(path: "Contents/Resources")
        let bytes = try Self.resource(resources.appending(path: "slicc"), hash: ScreenSnapshotRecipe.armSHA)
        try ScreenSnapshotRecipe.validate(bytes)
        var other: Data?
        if selected == .replacement {
            other = try Self.resource(resources.appending(path: "slicc-snapshot-amd64"), hash: ScreenSnapshotRecipe.intelSHA)
        }
        var template = Array("/private/tmp/sliccy-snapshot.XXXXXXXX".utf8CString)
        guard mkdtemp(&template) != nil else { throw ScreenFailure.audit }
        let localRoot = URL(fileURLWithPath: String(decoding: template.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self))
        var directory = open(localRoot.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        var keep: Int32 = -1
        var success = false
        var cleanupIdentity: stat?
        defer {
            if !success {
                if keep >= 0 { close(keep) }; if directory >= 0 { close(directory) }
                // Even partial preparation never falls back to path-recursive
                // removal. Preserve an unverified tree instead of following it.
                if let cleanupIdentity { Self.cleanupPreparation(localRoot, expected: cleanupIdentity) }
            }
        }
        guard directory >= 0 else { throw ScreenFailure.audit }
        let directoryStat = try Self.info(directory, isDirectory: true)
        cleanupIdentity = directoryStat
        try Self.create(bytes, at: directory, name: "candidate")
        keep = openat(directory, "candidate", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard keep >= 0 else { throw ScreenFailure.audit }
        let originalStat = try Self.info(keep)
        var replacementStat: stat?
        guard linkat(directory, "candidate", directory, "baseline", 0) == 0 else { throw ScreenFailure.audit }
        if let other {
            try Self.create(other, at: directory, name: "replacement")
            let fd = openat(directory, "replacement", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw ScreenFailure.audit }; defer { close(fd) }
            replacementStat = try Self.info(fd)
            try Self.staticCheck(localRoot.appending(path: "replacement"), expectedCD: ScreenSnapshotRecipe.intelCD)
        }
        for name in ["tmp", "config"] {
            guard mkdirat(directory, name, 0o700) == 0 else { throw ScreenFailure.audit }
        }
        guard fsync(directory) == 0 else { throw ScreenFailure.audit }
        let result = Self(selected: selected, root: localRoot, directory: directory, retained: keep,
                          original: bytes, originalStat: originalStat, directoryStat: directoryStat,
                          replacementStat: replacementStat)
        // Transfer ownership exactly once before any throwing method call.
        // Failed initialization must not close descriptors again in deinit.
        directory = -1; keep = -1
        try result.verifyOriginalFiles()
        success = true
        return result
    }
    private init(selected: ScreenSnapshotCase, root: URL, directory: Int32, retained: Int32,
                 original: Data, originalStat: stat, directoryStat: stat, replacementStat: stat?) {
        self.selected = selected; self.root = root; self.directory = directory; self.retained = retained
        self.original = original; self.originalStat = originalStat; self.directoryStat = directoryStat
        self.replacementStat = replacementStat
    }
    /// Called only by the private ScreenChild source factory, once immediately
    /// before spawn. A post-change file can never become a new launch subject.
    func claimLaunchPath() throws -> String {
        lock.lock(); defer { lock.unlock() }
        guard !launchClaimed, !attempted, !cleaned else { throw ScreenFailure.incompatible }
        try verifyOriginalFiles(); launchClaimed = true
        return root.appending(path: "candidate").path
    }
    func change() throws -> Change {
        lock.lock(); defer { lock.unlock() }
        guard launchClaimed, !attempted, !cleaned else { throw ScreenFailure.incompatible }
        attempted = true
        try verifyOriginalFiles()
        if selected == .mutation {
            let fd = openat(directory, "candidate", O_WRONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { return .denied(Self.denial(errno)) }
            defer { close(fd) }
            guard Self.same(try Self.info(fd), originalStat) else { throw ScreenFailure.incompatible }
            var byte: UInt8 = 1
            let written = pwrite(fd, &byte, 1, off_t(ScreenSnapshotRecipe.offset))
            if written < 0 { return .denied(Self.denial(errno)) }
            guard written == 1, fsync(fd) == 0 else { throw ScreenFailure.incompatible }
            let changed = try Self.read(retained)
            try ScreenSnapshotRecipe.validateChanged(changed, original: original)
            try checkAlias("candidate", inode: originalStat, bytes: changed)
            try checkAlias("baseline", inode: originalStat, bytes: changed)
        } else {
            guard let other = replacementStat else { throw ScreenFailure.incompatible }
            try checkAliasHash("replacement", inode: other, hash: ScreenSnapshotRecipe.intelSHA)
            guard renameat(directory, "replacement", directory, "candidate") == 0 else { return .denied(Self.denial(errno)) }
            guard fsync(directory) == 0 else { throw ScreenFailure.incompatible }
            try checkAliasHash("candidate", inode: other, hash: ScreenSnapshotRecipe.intelSHA)
            guard try Self.read(retained) == original else { throw ScreenFailure.incompatible }
            try checkAlias("baseline", inode: originalStat, bytes: original)
            try Self.staticCheck(root.appending(path: "baseline"), expectedCD: ScreenSnapshotRecipe.armCD)
            try Self.staticCheck(root.appending(path: "candidate"), expectedCD: ScreenSnapshotRecipe.intelCD)
        }
        return .completed
    }
    /// Caller may use this only after actual child reaping. No unowned cleanup.
    func cleanup() throws {
        lock.lock(); defer { lock.unlock() }
        guard !cleaned else { return }
        try checkDirectory()
        // Go's Darwin UserConfigDir uses HOME/Library/Application Support,
        // including both screen journals. SLICC_USER_DATA_DIR does not move it.
        try ScreenSnapshotCleanup.removeContents(directory: directory, expected: directoryStat)
        try checkDirectory()
        guard rmdir(root.path) == 0 else { throw ScreenFailure.audit }
        cleaned = true
    }
    deinit { close(retained); close(directory) }
    private static func cleanupPreparation(_ root: URL, expected: stat) {
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { return }; defer { close(fd) }
        do {
            try ScreenSnapshotCleanup.removeContents(directory: fd, expected: expected)
            var current = stat()
            guard lstat(root.path, &current) == 0, same(current, expected) else { return }
            _ = rmdir(root.path)
        } catch { return }
    }
    private func verifyOriginalFiles() throws {
        try checkDirectory()
        let retainedInfo = try Self.info(retained)
        guard Self.same(retainedInfo, originalStat), retainedInfo.st_nlink == 2, try Self.read(retained) == original else { throw ScreenFailure.incompatible }
        try checkAlias("candidate", inode: originalStat, bytes: original)
        try checkAlias("baseline", inode: originalStat, bytes: original)
        try Self.staticCheck(root.appending(path: "candidate"), expectedCD: ScreenSnapshotRecipe.armCD)
        try Self.staticCheck(root.appending(path: "baseline"), expectedCD: ScreenSnapshotRecipe.armCD)
    }
    private func checkDirectory() throws {
        let fd = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw ScreenFailure.audit }; defer { close(fd) }
        guard Self.same(try Self.info(fd, isDirectory: true), directoryStat), Self.same(try Self.info(directory, isDirectory: true), directoryStat) else { throw ScreenFailure.audit }
    }
    private func checkAlias(_ name: String, inode: stat, bytes: Data) throws {
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ScreenFailure.incompatible }; defer { close(fd) }
        guard Self.same(try Self.info(fd), inode), try Self.read(fd) == bytes else { throw ScreenFailure.incompatible }
    }
    private func checkAliasHash(_ name: String, inode: stat, hash: String) throws {
        let fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ScreenFailure.incompatible }; defer { close(fd) }
        guard Self.same(try Self.info(fd), inode), ScreenSnapshotRecipe.digest(try Self.read(fd)) == hash else { throw ScreenFailure.incompatible }
    }
    private static func same(_ a: stat, _ b: stat) -> Bool { a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_mode == b.st_mode }
    private static func info(_ fd: Int32, isDirectory: Bool = false) throws -> stat {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == (isDirectory ? S_IFDIR : S_IFREG),
              info.st_mode & 0o077 == 0, fcntl(fd, F_GETFD) & FD_CLOEXEC != 0 else { throw ScreenFailure.incompatible }
        if isDirectory { guard info.st_mode & 0o777 == 0o700 else { throw ScreenFailure.incompatible } }
        else { guard info.st_size > 0 && info.st_size <= 32 * 1024 * 1024 else { throw ScreenFailure.incompatible } }
        return info
    }
    private static func create(_ data: Data, at dir: Int32, name: String) throws {
        let fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o700)
        guard fd >= 0 else { throw ScreenFailure.audit }; defer { close(fd) }
        var offset = 0
        while offset < data.count {
            let n = data.withUnsafeBytes { pwrite(fd, $0.baseAddress!.advanced(by: offset), data.count - offset, off_t(offset)) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw ScreenFailure.audit }; offset += n
        }
        guard fsync(fd) == 0 else { throw ScreenFailure.audit }
    }
    private static func read(_ fd: Int32) throws -> Data {
        let before = try info(fd), count = Int(before.st_size)
        var data = Data(count: count), offset = 0
        while offset < count {
            let n = data.withUnsafeMutableBytes { pread(fd, $0.baseAddress!.advanced(by: offset), count - offset, off_t(offset)) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw ScreenFailure.incompatible }; offset += n
        }
        let after = try info(fd)
        guard same(before, after), before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw ScreenFailure.incompatible }
        return data
    }
    private static func resource(_ url: URL, hash: String) throws -> Data {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true, let count = values.fileSize, count > 0 && count <= 32 * 1024 * 1024 else { throw ScreenFailure.incompatible }
        let data = try Data(contentsOf: url)
        guard data.count == count, ScreenSnapshotRecipe.digest(data) == hash else { throw ScreenFailure.incompatible }
        return data
    }
    private static func staticCheck(_ url: URL, expectedCD: String) throws {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { throw ScreenFailure.peerUntrusted }
        let requirement = try ScreenPeerVerifier.requirement("ai.sliccy.slicc")
        guard SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let hash = (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data,
              hash.map({ String(format: "%02x", $0) }).joined() == String(expectedCD.prefix(40)) else { throw ScreenFailure.peerUntrusted }
    }
    private static func denial(_ value: Int32) -> String {
        if value == ETXTBSY || value == EBUSY { return "busy" }
        if value == EPERM || value == EACCES { return "permission" }
        return "io"
    }
}
#endif
