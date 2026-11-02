import Foundation
import Darwin

/// Content-free local audit. The CLI and app share Audit/quota.lock and one budget.
final class ScreenAudit: @unchecked Sendable {
    enum Event: String, Codable { case consent, grantIntent = "grant-intent", grant, stop, refusal }
    private struct Row: Encodable {
        var minute: String; var event: Event; var reason: String; var scope: String?; var session: String?
    }
    private let lock = NSLock()
    private let appDirectory: String
    private let cliDirectory: String
    private var filename: String
    init(base: URL = FileManager.default.homeDirectoryForCurrentUser.appending(path: "Library/Application Support")) throws {
        appDirectory = base.appending(path: "ai.sliccy.mac/Audit").path
        cliDirectory = base.appending(path: "slicc/audit").path
        filename = "app-\(try ScreenID.make()).jsonl"
    }

    func record(_ event: Event, reason: String, scope: String?, session: String?, now: Date = Date()) throws {
        guard ScreenFailure(rawValue: reason) != nil || ["active", "awaiting-consent", "paused"].contains(reason),
              scope == nil || ["window", "display"].contains(scope!) else { throw ScreenFailure.audit }
        if let session { _ = try ScreenID.decode(session, bytes: 16) }
        guard try withQuota({ app, cli in
            try append(event, reason: reason, scope: scope, session: session, now: now, app: app, cli: cli)
        }) else { throw ScreenFailure.audit }
    }

    /// Sweeps both writers without appending an event. False means another writer
    /// owns the shared lock; maintenance retries on its next scheduled sweep.
    @discardableResult
    func sweep(now: Date = Date()) throws -> Bool {
        try withQuota { app, cli in
            try Self.prune(app: app, cli: cli, now: now, reserving: 0)
        }
    }

    private func withQuota(_ body: (Int32, Int32) throws -> Void) throws -> Bool {
        lock.lock(); defer { lock.unlock() }
        let app = try Self.openDirectory(appDirectory)
        defer { close(app) }
        let cli = try Self.openDirectory(cliDirectory)
        defer { close(cli) }
        let quota = try Self.openFile(app, name: "quota.lock")
        defer { close(quota) }
        guard flock(quota, LOCK_EX | LOCK_NB) == 0 else {
            if errno == EWOULDBLOCK { return false }
            throw ScreenFailure.audit
        }
        defer { flock(quota, LOCK_UN) }
        var held = stat(), disk = stat()
        guard fstat(quota, &held) == 0, fstatat(app, "quota.lock", &disk, AT_SYMLINK_NOFOLLOW) == 0,
              held.st_ino == disk.st_ino, held.st_dev == disk.st_dev else { throw ScreenFailure.audit }
        try body(app, cli)
        return true
    }

    private func append(_ event: Event, reason: String, scope: String?, session: String?, now: Date, app: Int32, cli: Int32) throws {
        let bucket = Self.dayFormatter().string(from: now)
        let prefix = "app-\(bucket)-"
        if !filename.hasPrefix(prefix) { filename = "\(prefix)\(try ScreenID.make()).jsonl" }
        let formatter = ISO8601DateFormatter()
        let minute = Date(timeIntervalSince1970: floor(now.timeIntervalSince1970 / 60) * 60)
        var data = try JSONEncoder().encode(Row(minute: formatter.string(from: minute), event: event, reason: reason, scope: scope, session: session))
        data.append(10)
        try Self.prune(app: app, cli: cli, now: now, reserving: Int64(data.count))
        var current = stat()
        if fstatat(app, filename, &current, AT_SYMLINK_NOFOLLOW) == 0, current.st_size + Int64(data.count) > 10 * 1024 * 1024 {
            filename = "\(prefix)\(try ScreenID.make()).jsonl"
        }
        let file = try Self.openFile(app, name: filename)
        defer { close(file) }
        guard lseek(file, 0, SEEK_END) >= 0 else { throw ScreenFailure.audit }
        var position = 0
        while position < data.count {
            let written = data.withUnsafeBytes { Darwin.write(file, $0.baseAddress!.advanced(by: position), data.count - position) }
            if written < 0 && errno == EINTR { continue }
            guard written > 0 else { throw ScreenFailure.audit }
            position += written
        }
        guard fsync(file) == 0 else { throw ScreenFailure.audit }
    }

    private static func prune(app: Int32, cli: Int32, now: Date, reserving bytes: Int64) throws {
        var files = try Self.files(app, now: now) + Self.files(cli, now: now)
        var total = files.reduce(Int64(0)) { $0 + $1.size }
        files.sort { $0.retentionStart < $1.retentionStart }
        for file in files where total + bytes > 100 * 1024 * 1024 {
            guard unlinkat(file.directory, file.name, 0) == 0 else { throw ScreenFailure.audit }
            total -= file.size
        }
        guard total + bytes <= 100 * 1024 * 1024 else { throw ScreenFailure.audit }
    }

    private struct Entry { var directory: Int32; var name: String; var size: Int64; var retentionStart: TimeInterval }

    private static func dayFormatter() -> DateFormatter {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd"
        formatter.isLenient = false
        return formatter
    }

    private static func bucketStart(_ name: String) -> Date? {
        let prefix = name.hasPrefix("app-") ? "app-" : "broker-"
        let remainder = name.dropFirst(prefix.count)
        guard remainder.count > 9, remainder.dropFirst(8).first == "-" else { return nil }
        let day = String(remainder.prefix(8))
        guard day.utf8.allSatisfy({ (48...57).contains($0) }) else { return nil }
        let formatter = dayFormatter()
        guard let date = formatter.date(from: day), formatter.string(from: date) == day else { return nil }
        return date
    }
    private static func files(_ fd: Int32, now: Date) throws -> [Entry] {
        let duplicate = dup(fd)
        guard duplicate >= 0 else { throw ScreenFailure.audit }
        guard let directory = fdopendir(duplicate) else { close(duplicate); throw ScreenFailure.audit }
        defer { closedir(directory) }
        var entries: [Entry] = []
        var count = 0
        while let pointer = readdir(directory) {
            count += 1
            guard count <= 1026 else { throw ScreenFailure.audit }
            let name = withUnsafePointer(to: &pointer.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(pointer.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if [".", "..", "quota.lock"].contains(name) { continue }
            guard name.hasSuffix(".jsonl"), name.hasPrefix("app-") || name.hasPrefix("broker-") else { throw ScreenFailure.audit }
            var info = stat()
            guard fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
                  info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_mode & 0o777 == 0o600,
                  info.st_size >= 0 else { throw ScreenFailure.audit }
            // Undated prototype journals have no reliable earliest-record date.
            // Retire them instead of extending retention through a refreshed mtime.
            let bucket = bucketStart(name)
            let retentionStart = min(bucket?.timeIntervalSince1970 ?? -.infinity, Double(info.st_mtimespec.tv_sec))
            if now.timeIntervalSince1970 - retentionStart >= 30 * 86400 {
                guard unlinkat(fd, name, 0) == 0 else { throw ScreenFailure.audit }
            } else { entries.append(.init(directory: fd, name: name, size: info.st_size, retentionStart: retentionStart)) }
        }
        return entries
    }

    private static func openDirectory(_ path: String) throws -> Int32 {
        var fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw ScreenFailure.audit }
        do {
            for component in path.split(separator: "/").map(String.init) {
                if mkdirat(fd, component, 0o700) != 0 && errno != EEXIST { throw ScreenFailure.audit }
                let next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw ScreenFailure.audit }
                close(fd); fd = next
            }
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o777 == 0o700 else { throw ScreenFailure.audit }
            return fd
        } catch { close(fd); throw error }
    }
    private static func openFile(_ directory: Int32, name: String) throws -> Int32 {
        let fd = openat(directory, name, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw ScreenFailure.audit }
        var info = stat(), disk = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o777 == 0o600, info.st_nlink == 1,
              fstatat(directory, name, &disk, AT_SYMLINK_NOFOLLOW) == 0,
              disk.st_ino == info.st_ino, disk.st_dev == info.st_dev else { close(fd); throw ScreenFailure.audit }
        return fd
    }
}
