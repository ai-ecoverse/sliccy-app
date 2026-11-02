import Foundation
import Darwin

struct CLIControlRequest: Encodable, Sendable {
    var v = 1
    var op: String
    var leaseId: String?
}

struct CLIControlReply: Decodable, Sendable {
    var v: Int
    var pid: Int32?
    var ops: [String]?
    var ok: Bool?
    var error: String?
    var sealing: Bool?
    var leases: [CredentialLease]?
    var revoked: Bool?
    var upstream: Bool?
}

enum CLIControlError: LocalizedError {
    case unavailable, timeout, invalid, refused
    var errorDescription: String? {
        switch self {
        case .unavailable: "The running CLI control socket is unavailable."
        case .timeout: "The CLI did not confirm the change. Refresh to check its current state."
        case .invalid: "The CLI returned an incompatible control response."
        case .refused: "The CLI could not complete the request. Refresh before trying again."
        }
    }
}

/// Public, same-user CLI control protocol; only addresses a child owned by Sliccy.
/// This is unrelated to the private, still-unimplemented screen transport.
enum CLIControlClient {
    static func request(pid: Int32, request: CLIControlRequest) async throws -> CLIControlReply {
        let worker = Task.detached { try exchange(pid: pid, request: request) }
        return try await withTaskCancellationHandler {
            try await worker.value
        } onCancel: { worker.cancel() }
    }

    static func exchange(pid: Int32, request: CLIControlRequest, socketDirectory: String? = nil) throws -> CLIControlReply {
        let root = ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp"
        var directory = URL(fileURLWithPath: root).appending(path: "slicc-\(getuid())").path
        if "\(directory)/\(pid).sock".utf8.count >= 104 { directory = "/tmp/slicc-\(getuid())" }
        if let socketDirectory { directory = socketDirectory }
        var info = stat()
        guard lstat(directory, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw CLIControlError.unavailable }
        let path = "\(directory)/\(pid).sock"
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw CLIControlError.unavailable }
        defer { close(fd) }
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw CLIControlError.unavailable }
        var one: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else { throw CLIControlError.unavailable }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let name = Array(path.utf8CString)
        guard name.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw CLIControlError.unavailable }
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            for index in name.indices { bytes[index] = UInt8(bitPattern: name[index]) }
        }
        let clock = ContinuousClock()
        let connectDeadline = clock.now.advanced(by: .seconds(3))
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if result != 0 {
            guard errno == EINPROGRESS else { throw CLIControlError.unavailable }
            try wait(fd, events: Int16(POLLOUT), until: connectDeadline)
            var failure: Int32 = 0
            var length = socklen_t(MemoryLayout.size(ofValue: failure))
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &failure, &length) == 0, failure == 0 else { throw CLIControlError.unavailable }
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        var peerPID: pid_t = 0
        var peerLength = socklen_t(MemoryLayout.size(ofValue: peerPID))
        guard getpeereid(fd, &uid, &gid) == 0, uid == getuid(),
              getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &peerPID, &peerLength) == 0, peerPID == pid else { throw CLIControlError.unavailable }
        let deadline = clock.now.advanced(by: .seconds(request.op == "unseal" ? 80 : 5))
        var payload = try JSONEncoder().encode(request)
        payload.append(10)
        var offset = 0
        while offset < payload.count {
            try wait(fd, events: Int16(POLLOUT), until: deadline)
            let count = payload.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), payload.count - offset, 0) }
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count > 0 else { throw CLIControlError.unavailable }
            offset += count
        }
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            try wait(fd, events: Int16(POLLIN), until: deadline)
            let count = recv(fd, &buffer, buffer.count, 0)
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count > 0 else { throw CLIControlError.unavailable }
            response.append(contentsOf: buffer.prefix(count))
            guard response.count <= 1024 * 1024 else { throw CLIControlError.invalid }
            if let end = response.firstIndex(of: 10) {
                let reply = try JSONDecoder().decode(CLIControlReply.self, from: response[..<end])
                guard reply.v == 1 else { throw CLIControlError.invalid }
                if reply.error != nil || reply.ok == false { throw CLIControlError.refused }
                if request.op == "status", reply.pid != pid { throw CLIControlError.invalid }
                return reply
            }
        }
    }

    private static func wait(_ fd: Int32, events: Int16, until deadline: ContinuousClock.Instant) throws {
        while ContinuousClock.now < deadline {
            try Task.checkCancellation()
            var descriptor = pollfd(fd: fd, events: events, revents: 0)
            let ready = poll(&descriptor, 1, 100)
            if ready < 0 && errno == EINTR { continue }
            guard ready >= 0 else { throw CLIControlError.unavailable }
            if ready > 0 { return }
        }
        throw CLIControlError.timeout
    }
}
