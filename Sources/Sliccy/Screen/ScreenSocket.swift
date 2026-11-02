import Foundation
import Darwin
import ScreenSystem

final class ScreenSocket: @unchecked Sendable {
    let fd: Int32
    init(_ fd: Int32) throws {
        self.fd = fd
        guard fd >= 0 else { throw ScreenFailure.peerLost }
        var one: Int32 = 1
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one))) == 0 else {
            close(fd); throw ScreenFailure.peerLost
        }
    }
    deinit { close(fd) }
    // Keep the descriptor allocated until every worker releases this object.
    func stop() { _ = shutdown(fd, SHUT_RDWR) }

    static func listener(path: String) throws -> ScreenSocket {
        let listener = try ScreenSocket(socket(AF_UNIX, SOCK_STREAM, 0))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let name = Array(path.utf8CString)
        guard name.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw ScreenFailure.incompatible }
        withUnsafeMutableBytes(of: &address.sun_path) { bytes in
            for index in name.indices { bytes[index] = UInt8(bitPattern: name[index]) }
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listener.fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard result == 0, chmod(path, 0o600) == 0, listen(listener.fd, 4) == 0 else { throw ScreenFailure.peerLost }
        return listener
    }

    func accept(until: ContinuousClock.Instant) throws -> ScreenSocket {
        try wait(Int16(POLLIN), until: until)
        return try ScreenSocket(Darwin.accept(fd, nil, nil))
    }

    func readHello(until: ContinuousClock.Instant) throws -> Data {
        let size = try length(read(4, until: until))
        guard (1...4096).contains(size) else { throw ScreenFailure.incompatible }
        return try read(size, until: until)
    }
    func writeHello(_ header: Data, until: ContinuousClock.Instant) throws {
        guard (1...4096).contains(header.count) else { throw ScreenFailure.incompatible }
        try write(Self.prefix(header.count) + header, until: until)
    }
    func readSafety() throws -> Data {
        let first = try read(1, until: .now.advanced(by: .milliseconds(1500)))
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        let size = try length(first + read(3, until: deadline))
        guard (1...4096).contains(size) else { throw ScreenFailure.incompatible }
        let header = try read(size, until: deadline)
        guard try length(read(4, until: deadline)) == 0 else { throw ScreenFailure.incompatible }
        return header
    }
    func writeRecord(header: Data, body: Data = Data(), until: ContinuousClock.Instant,
                     allowed: () -> Bool = { true }) throws {
        guard (1...4096).contains(header.count), body.count <= 2_097_152 else { throw ScreenFailure.resourceLimit }
        try write(Self.prefix(header.count) + header + Self.prefix(body.count), until: until, allowed: allowed)
        if !body.isEmpty { try write(body, until: until, allowed: allowed) }
    }
    private func read(_ count: Int, until: ContinuousClock.Instant) throws -> Data {
        var result = Data(count: count)
        var offset = 0
        while offset < count {
            try wait(Int16(POLLIN), until: until)
            let received = result.withUnsafeMutableBytes { sliccy_screen_recv(fd, $0.baseAddress!.advanced(by: offset), count - offset) }
            if received < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard received > 0 else { throw ScreenFailure.peerLost }
            offset += received
        }
        return result
    }
    private func write(_ data: Data, until: ContinuousClock.Instant, allowed: () -> Bool = { true }) throws {
        var offset = 0
        while offset < data.count {
            guard allowed() else { throw ScreenFailure.stopped }
            try wait(Int16(POLLOUT), until: until)
            guard allowed() else { throw ScreenFailure.stopped }
            let written = data.withUnsafeBytes { send(fd, $0.baseAddress!.advanced(by: offset), min(65536, data.count - offset), 0) }
            if written < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard written > 0 else { throw ScreenFailure.peerLost }
            offset += written
        }
    }
    private func wait(_ event: Int16, until: ContinuousClock.Instant) throws {
        while ContinuousClock.now < until {
            var descriptor = pollfd(fd: fd, events: event, revents: 0)
            let result = poll(&descriptor, 1, 25)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0 else { throw ScreenFailure.peerLost }
            if result > 0 { return }
        }
        throw ScreenFailure.stalled
    }
    private func length(_ data: Data) throws -> Int {
        guard data.count == 4 else { throw ScreenFailure.incompatible }
        return data.reduce(0) { ($0 << 8) | Int($1) }
    }
    static func prefix(_ length: Int) -> Data {
        var number = UInt32(length).bigEndian
        return withUnsafeBytes(of: &number) { Data($0) }
    }
}
