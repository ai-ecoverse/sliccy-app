#if SLICCY_CAPTURE_RUNNER_PROOF
import Darwin
import Foundation

enum ScreenRunnerCleanup {
    private struct Node {
        let name: String, metadata: stat, children: [Node]?
    }
    private struct Budget {
        var entries = 0
        var fileLinks: [String: (observed: Int, expected: Int)] = [:]
    }
    static func removeContents(directory: Int32, expected: stat) throws {
        try checkRoot(directory, expected)
        var budget = Budget()
        let tree = try inspect(directory, path: [], device: expected.st_dev, budget: &budget)
        guard budget.fileLinks.values.allSatisfy({ $0.observed == $0.expected }) else { throw ScreenFailure.audit }
        try checkRoot(directory, expected)
        try erase(tree, at: directory)
        try checkRoot(directory, expected)
    }
    private static func checkRoot(_ fd: Int32, _ expected: stat) throws {
        var value = stat()
        guard fstat(fd, &value) == 0, same(value, expected), value.st_uid == getuid(),
              value.st_mode & S_IFMT == S_IFDIR, value.st_mode & 0o777 == 0o700 else { throw ScreenFailure.audit }
    }
    private static func names(_ fd: Int32) throws -> [String] {
        let reader = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard reader >= 0 else { throw ScreenFailure.audit }
        guard let stream = fdopendir(reader) else { close(reader); throw ScreenFailure.audit }
        defer { closedir(stream) }
        var result: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw ScreenFailure.audit }; break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { value in
                value.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: entry.pointee.d_name)) { String(validatingCString: $0) }
            }
            guard let name, !name.contains("/"), name.utf8.count <= 255 else { throw ScreenFailure.audit }
            if name == "." || name == ".." { continue }
            guard result.count < 8192 else { throw ScreenFailure.audit }
            result.append(name)
        }
        return result.sorted()
    }
    private static func permitted(_ name: String, at path: [String], isDirectory: Bool) -> Bool {
        if path.isEmpty {
            return isDirectory && ["tmp", "config", "Library"].contains(name)
        }
        if path == ["Library"] { return isDirectory && name == "Application Support" }
        if path == ["Library", "Application Support"] { return isDirectory && ["slicc", "ai.sliccy.mac"].contains(name) }
        if path == ["Library", "Application Support", "ai.sliccy.mac"] { return isDirectory && name == "Audit" }
        return true
    }
    private static func inspect(_ fd: Int32, path: [String], device: dev_t, budget: inout Budget) throws -> [Node] {
        guard path.count <= 24 else { throw ScreenFailure.audit }
        var result: [Node] = []
        for name in try names(fd) {
            budget.entries += 1
            guard budget.entries <= 8192 else { throw ScreenFailure.audit }
            var metadata = stat()
            guard fstatat(fd, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0,
                  metadata.st_uid == getuid(), metadata.st_dev == device else { throw ScreenFailure.audit }
            let kind = metadata.st_mode & S_IFMT
            let ownedProfileLeaf = ["config", "tmp"].contains(path.first ?? "") && (kind == S_IFLNK || kind == S_IFSOCK)
            guard (kind == S_IFREG || kind == S_IFDIR || ownedProfileLeaf),
                  kind == S_IFLNK || metadata.st_mode & 0o022 == 0,
                  permitted(name, at: path, isDirectory: kind == S_IFDIR) else { throw ScreenFailure.audit }
            var children: [Node]?
            if kind == S_IFDIR {
                let nested = try openDirectory(fd, name: name, expected: metadata)
                defer { close(nested) }
                children = try inspect(nested, path: path + [name], device: device, budget: &budget)
            } else if kind == S_IFREG {
                let key = String(metadata.st_dev) + ":" + String(metadata.st_ino)
                let value = budget.fileLinks[key] ?? (observed: 0, expected: Int(metadata.st_nlink))
                guard value.expected > 0, value.expected == Int(metadata.st_nlink) else { throw ScreenFailure.audit }
                budget.fileLinks[key] = (value.observed + 1, value.expected)
            }
            result.append(Node(name: name, metadata: metadata, children: children))
        }
        return result
    }
    private static func openDirectory(_ parent: Int32, name: String, expected: stat) throws -> Int32 {
        let fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ScreenFailure.audit }
        var value = stat()
        guard fstat(fd, &value) == 0, same(value, expected) else { close(fd); throw ScreenFailure.audit }
        return fd
    }
    private static func erase(_ nodes: [Node], at fd: Int32) throws {
        guard try names(fd) == nodes.map(\.name) else { throw ScreenFailure.audit }
        for node in nodes {
            var current = stat()
            guard fstatat(fd, node.name, &current, AT_SYMLINK_NOFOLLOW) == 0, same(current, node.metadata) else { throw ScreenFailure.audit }
            if let children = node.children {
                let nested = try openDirectory(fd, name: node.name, expected: node.metadata)
                defer { close(nested) }
                try erase(children, at: nested)
                guard fstatat(fd, node.name, &current, AT_SYMLINK_NOFOLLOW) == 0, same(current, node.metadata),
                      unlinkat(fd, node.name, AT_REMOVEDIR) == 0 else { throw ScreenFailure.audit }
            } else {
                guard current.st_size == node.metadata.st_size,
                      current.st_mtimespec.tv_sec == node.metadata.st_mtimespec.tv_sec,
                      current.st_mtimespec.tv_nsec == node.metadata.st_mtimespec.tv_nsec,
                      unlinkat(fd, node.name, 0) == 0 else { throw ScreenFailure.audit }
            }
        }
    }
    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_mode == b.st_mode
    }
}
#endif
