#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security
import Darwin
import ScreenSystem

enum ScreenRunnerKernelChild {
    struct Evidence: Sendable {
        enum Stage: String, Sendable { case started, verified, acknowledged, reaped, refused, unreaped }
        let stage: Stage
        let target: pid_t
        let sudoPID: pid_t
        let root: ScreenRunnerKernelSample?
        let hash: Data?
        var exitStatus: Int32? = nil
        var rootGone: Bool? = nil
        let at: ContinuousClock.Instant = .now
        var fields: [String: Any] {
            var result: [String: Any] = ["phase": stage.rawValue, "targetPID": target, "sudoPID": sudoPID]
            if let root {
                result["rootPID"] = root.pid; result["rootParent"] = root.parent; result["rootUID"] = root.uid
                result["rootStartSeconds"] = String(root.seconds); result["rootStartMicroseconds"] = root.microseconds
            }
            if let hash { result["rootCDHash"] = hash.map { String(format: "%02x", $0) }.joined() }
            if let exitStatus { result["exitStatus"] = exitStatus }
            if let rootGone { result["rootGone"] = rootGone }
            return result
        }
    }
    private final class Owned: @unchecked Sendable {
        let pid: pid_t
        private let lock = NSLock()
        private let ended = DispatchSemaphore(value: 0)
        private var result: (kind: Int32, status: Int32, error: Int32)?
        init(_ pid: pid_t) {
            self.pid = pid
            Thread { [self] in
                var kind: Int32 = -1, status: Int32 = -1
                let error = sliccy_runner_wait_kernel(pid, &kind, &status)
                lock.lock(); result = (kind, status, error); lock.unlock()
                ended.signal()
            }.start()
        }
        var snapshot: (kind: Int32, status: Int32, error: Int32)? { lock.lock(); defer { lock.unlock() }; return result }
        var isRunning: Bool { snapshot == nil }
        func reap(until: DispatchTime) -> Bool {
            if let result = snapshot { return result.error == 0 }
            guard ended.wait(timeout: until) == .success else { return false }
            return snapshot?.error == 0
        }
    }
    private final class Children: @unchecked Sendable {
        private let lock = NSLock()
        private var owned: [Owned] = []
        func insert(_ value: Owned) { lock.lock(); owned.append(value); lock.unlock() }
        func remove(_ value: Owned) { lock.lock(); owned.removeAll { $0 === value }; lock.unlock() }
        func finish(until: DispatchTime) -> Bool {
            lock.lock(); let snapshot = owned; lock.unlock()
            var complete = true
            for value in snapshot {
                if value.reap(until: until) { remove(value) } else { complete = false }
            }
            return complete
        }
    }
    private static let children = Children()
    static func finishOwned(until: DispatchTime) -> Bool { children.finish(until: until) }
    struct Facts: Codable {
        let schema: Int
        let sample: ScreenRunnerKernelSample
        let path: String
        let hash: Data
    }
    static func placement() throws {
#if arch(arm64)
        let arm = true
#else
        let arm = false
#endif
        _ = try ScreenRunnerHost.validate(arguments: ["--screen-runner-proof", "--case", "selected-window"],
            environment: ProcessInfo.processInfo.environment, major: ProcessInfo.processInfo.operatingSystemVersion.majorVersion, arm: arm)
    }
    static func parse(_ arguments: [String], uid: uid_t) throws -> pid_t {
        guard uid == 0, arguments.count == 2, arguments[0] == "--runner-kernel",
              let pid = Int32(arguments[1]), pid > 0, String(pid) == arguments[1] else { throw ScreenFailure.incompatible }
        return pid
    }
    static func stagedComponents(_ path: String) throws -> [String] {
        let url = URL(fileURLWithPath: path)
        guard url.standardizedFileURL.path == path else { throw ScreenFailure.peerUntrusted }
        let parts = url.pathComponents
        guard parts.count == 7, parts[0] == "/", parts[1] == "Library", parts[2].hasPrefix("SliccyProof-"),
              let run = UInt64(parts[2].dropFirst("SliccyProof-".count)), run > 0,
              parts[2] == "SliccyProof-" + String(run), Array(parts[3...]) == ["Sliccy.app", "Contents", "MacOS", "Sliccy"] else { throw ScreenFailure.peerUntrusted }
        return parts
    }
    static func immutableExecutable(_ path: String) throws {
        let parts = try stagedComponents(path)
        var prefix = ""
        for (index, part) in parts.enumerated() {
            prefix = index == 0 ? "/" : (prefix == "/" ? "/" + part : prefix + "/" + part)
            var value = stat()
            guard lstat(prefix, &value) == 0, value.st_uid == 0, value.st_gid == 0,
                  value.st_mode & 0o022 == 0, value.st_mode & S_IFMT == (index == parts.count - 1 ? S_IFREG : S_IFDIR),
                  sliccy_runner_no_acl(prefix) == 0 else { throw ScreenFailure.peerUntrusted }
        }
    }
    static func line(_ fd: Int32, deadline: ContinuousClock.Instant) throws -> Data {
        var data = Data()
        while data.count < 4096, .now < deadline {
            var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let result = poll(&item, 1, 10)
            if result == 0 || (result < 0 && errno == EINTR) { continue }
            var byte: UInt8 = 0
            guard result > 0, read(fd, &byte, 1) == 1 else { throw ScreenFailure.peerUntrusted }
            if byte == 10 { return data }
            data.append(byte)
        }
        throw ScreenFailure.stalled
    }
    static func emit<T: Encodable>(_ value: T) throws {
        var data = try JSONEncoder().encode(value)
        guard data.count < 4095 else { throw ScreenFailure.resourceLimit }
        data.append(10)
        guard data.withUnsafeBytes({ write(STDOUT_FILENO, $0.baseAddress, $0.count) }) == data.count else { throw ScreenFailure.peerLost }
    }
    static func run() -> Never {
        signal(SIGPIPE, SIG_IGN); alarm(2)
        do {
            try placement()
            let pid = try parse(Array(CommandLine.arguments.dropFirst()), uid: geteuid())
            let ownPath = try ScreenRunnerKernelSample.path(getpid())
            _ = try stagedComponents(ownPath)
            let beforeCode = try ScreenRunnerSystemOwner.code(pid: pid, identifier: "com.apple.WindowServer")
            guard let before = ScreenRunnerKernelSample.read(pid).0,
                  try ScreenRunnerKernelSample.path(pid) == beforeCode.path else { throw ScreenFailure.peerUntrusted }
            try emit(["schema": 1, "pid": Int(getpid())])
            var byte: UInt8 = 0
            guard read(STDIN_FILENO, &byte, 1) == 1, byte == 1 else { throw ScreenFailure.peerUntrusted }
            guard let after = ScreenRunnerKernelSample.read(pid).0, before == after,
                  try ScreenRunnerSystemOwner.code(pid: pid, identifier: "com.apple.WindowServer") == beforeCode,
                  try ScreenRunnerKernelSample.path(pid) == beforeCode.path else { throw ScreenFailure.peerUntrusted }
            try emit(Facts(schema: 1, sample: after, path: beforeCode.path, hash: beforeCode.hash))
            exit(0)
        } catch { exit(2) }
    }
    static func query(_ pid: pid_t, expected: ScreenRunnerSystemOwner.Code,
                      record: @Sendable (Evidence) -> Void) throws -> ScreenRunnerKernelSample {
        try Task.checkCancellation()
        try placement()
        guard geteuid() != 0, expected.identifier == "com.apple.WindowServer",
              try ScreenRunnerSystemOwner.code(pid: pid, identifier: expected.identifier) == expected else { throw ScreenFailure.peerUntrusted }
        let ownPath = try ScreenRunnerKernelSample.path(getpid())
        try immutableExecutable(ownPath)
        let own = try ScreenRunnerSystemOwner.code(pid: getpid(), identifier: "ai.sliccy.mac", app: true)
        guard own.path == ownPath, try ScreenRunnerKernelSample.hash(getpid()) == own.hash else { throw ScreenFailure.peerUntrusted }
        var selfCode: SecCode?, selfStaticCode: SecStaticCode?, designated: SecRequirement?
        guard SecCodeCopySelf([], &selfCode) == errSecSuccess, let selfCode,
              SecCodeCopyStaticCode(selfCode, [], &selfStaticCode) == errSecSuccess, let selfStaticCode,
              SecCodeCopyDesignatedRequirement(selfStaticCode, [], &designated) == errSecSuccess, let designated else { throw ScreenFailure.peerUntrusted }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2)), began = Date().timeIntervalSince1970
        try Task.checkCancellation()
        var child: pid_t = 0, input: Int32 = -1, output: Int32 = -1
        guard sliccy_runner_spawn_kernel(ownPath, String(pid), &child, &input, &output) == 0, child > 0 else { throw ScreenFailure.peerLost }
        let ownership = Owned(child)
        children.insert(ownership)
        record(.init(stage: .started, target: pid, sudoPID: child, root: nil, hash: nil))
        defer { close(output) }
        var rootIdentity: ScreenRunnerKernelSample?
        let result: Result<ScreenRunnerKernelSample, any Error> = Result {
        guard fcntl(output, F_SETFL, O_NONBLOCK) == 0 else { throw ScreenFailure.peerLost }
        let helloData = try line(output, deadline: deadline)
        let hello = try ScreenJSON.object(helloData)
        try ScreenJSON.keys(hello, exact: ["schema", "pid"])
        struct Hello: Decodable { let schema: Int, pid: pid_t }
        let value = try JSONDecoder().decode(Hello.self, from: helloData)
        guard value.schema == 1, let before = ScreenRunnerKernelSample.read(value.pid).0, before.uid == 0 else { throw ScreenFailure.peerUntrusted }
        rootIdentity = before
        let start = Double(before.seconds) + Double(before.microseconds) / 1_000_000
        guard start >= began, start <= Date().timeIntervalSince1970 else { throw ScreenFailure.peerUntrusted }
        var parent = value.pid, seen = Set<pid_t>(), chain: [ScreenRunnerKernelSample] = []
        while parent != child, seen.count < 4 {
            guard seen.insert(parent).inserted, let sample = ScreenRunnerKernelSample.read(parent).0 else { throw ScreenFailure.peerUntrusted }
            chain.append(sample)
            parent = sample.parent
        }
        var liveRoot: SecCode?
        guard parent == child, ownership.isRunning,
              try ScreenRunnerSystemOwner.code(pid: value.pid, identifier: "ai.sliccy.mac", app: true) == own,
              try ScreenRunnerKernelSample.hash(value.pid) == own.hash, ScreenRunnerKernelSample.read(value.pid).0 == before,
              chain.allSatisfy({ ScreenRunnerKernelSample.read($0.pid).0 == $0 }),
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: value.pid] as CFDictionary, [], &liveRoot) == errSecSuccess,
              let liveRoot, SecCodeCheckValidity(liveRoot, SecCSFlags(rawValue: kSecCSStrictValidate), designated) == errSecSuccess else { throw ScreenFailure.peerUntrusted }
        record(.init(stage: .verified, target: pid, sudoPID: child, root: before, hash: own.hash))
        var ack: UInt8 = 1
        guard .now < deadline, write(input, &ack, 1) == 1 else { throw ScreenFailure.stalled }
        record(.init(stage: .acknowledged, target: pid, sudoPID: child, root: before, hash: own.hash))
        let data = try line(output, deadline: deadline)
        let object = try ScreenJSON.object(data)
        try ScreenJSON.keys(object, exact: ["schema", "sample", "path", "hash"])
        guard let sampleObject = object["sample"] as? [String: Any] else { throw ScreenFailure.incompatible }
        try ScreenJSON.keys(sampleObject, exact: ["pid", "parent", "uid", "seconds", "microseconds"])
        let facts = try JSONDecoder().decode(Facts.self, from: data)
        guard facts.schema == 1, facts.sample.pid == pid, facts.sample.seconds > 0, facts.sample.microseconds < 1_000_000,
              facts.path == expected.path, facts.hash == expected.hash else { throw ScreenFailure.peerUntrusted }
        return facts.sample
        }
        close(input)
        let remaining = max(0, ScreenRunnerJournal.ms(ContinuousClock.now.duration(to: deadline)) / 1000)
        guard ownership.reap(until: .now() + remaining) else {
            record(.init(stage: .unreaped, target: pid, sudoPID: child, root: rootIdentity, hash: nil))
            throw ScreenFailure.stalled
        }
        children.remove(ownership)
        let rootGone: Bool
        if let rootIdentity {
            if rootIdentity.pid == child { rootGone = true }
            else {
                let after = ScreenRunnerKernelSample.read(rootIdentity.pid)
                rootGone = after.0 == nil && after.1 == ESRCH
            }
        } else { rootGone = false }
        record(.init(stage: .reaped, target: pid, sudoPID: child, root: rootIdentity, hash: nil,
                     exitStatus: (ownership.snapshot?.status ?? -1), rootGone: rootGone))
        guard !ownership.isRunning,
              ownership.snapshot?.kind == 0, (ownership.snapshot?.status ?? -1) == 0, rootGone else {
            record(.init(stage: .refused, target: pid, sudoPID: child, root: rootIdentity, hash: nil, exitStatus: (ownership.snapshot?.status ?? -1)))
            throw ScreenFailure.peerUntrusted
        }
        var extra: UInt8 = 0
        guard read(output, &extra, 1) == 0 else { throw ScreenFailure.incompatible }
        do { return try result.get() }
        catch {
            record(.init(stage: .refused, target: pid, sudoPID: child, root: rootIdentity, hash: nil))
            throw error
        }
    }
}
#endif
