import Foundation
import Darwin
import Testing
@testable import Sliccy

struct ScreenSocketTests {
    func pair() throws -> (ScreenSocket, ScreenSocket) {
        var descriptors: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else { throw ScreenFailure.peerLost }
        return (try ScreenSocket(descriptors[0]), try ScreenSocket(descriptors[1]))
    }
    @Test func safetyEnvelopeRoundTripsAndRejectsImageBody() throws {
        let (writer, reader) = try pair()
        let header = Data(#"{"type":"test"}"#.utf8)
        try writer.writeRecord(header: header, until: .now.advanced(by: .seconds(1)))
        #expect(try reader.readSafety() == header)
        try writer.writeRecord(header: header, body: Data([1]), until: .now.advanced(by: .seconds(1)))
        #expect(throws: ScreenFailure.incompatible) { try reader.readSafety() }
    }
    @Test func stopInterruptsBlockedImageWriter() async throws {
        let (writer, reader) = try pair()
        var capacity: Int32 = 1024
        #expect(setsockopt(writer.fd, SOL_SOCKET, SO_SNDBUF, &capacity, socklen_t(MemoryLayout.size(ofValue: capacity))) == 0)
        let work = Task.detached { () -> Bool in
            do {
                try writer.writeRecord(header: Data(#"{"type":"frame"}"#.utf8), body: Data(repeating: 0, count: 2_097_152), until: .now.advanced(by: .seconds(2)))
                return false
            } catch { return true }
        }
        // No reader drains the image. Cancellation must not depend on its progress.
        writer.stop()
        #expect(await work.value)
        withExtendedLifetime(reader) {}
    }
    @Test func malformedAndPartialHelloCannotWaitIndefinitely() throws {
        let (writer, reader) = try pair()
        let oversized = ScreenSocket.prefix(4097)
        _ = oversized.withUnsafeBytes { send(writer.fd, $0.baseAddress, $0.count, 0) }
        #expect(throws: ScreenFailure.incompatible) { try reader.readHello(until: .now.advanced(by: .seconds(1))) }
        let (partialWriter, partialReader) = try pair()
        let partial = Data([0, 0])
        _ = partial.withUnsafeBytes { send(partialWriter.fd, $0.baseAddress, $0.count, 0) }
        #expect(throws: ScreenFailure.stalled) { try partialReader.readHello(until: .now.advanced(by: .milliseconds(30))) }
    }
    @Test func rateLimitHasBoundedBurstAndMonotonicRefill() throws {
        let now = ContinuousClock.now
        var rate = ScreenRate(capacity: 16, rate: 16, now: now)
        try rate.consume(16, now: now)
        #expect(throws: ScreenFailure.resourceLimit) { try rate.consume(1, now: now) }
        try rate.consume(8, now: now.advanced(by: .milliseconds(500)))
        #expect(throws: ScreenFailure.resourceLimit) { try rate.consume(1, now: now.advanced(by: .milliseconds(500))) }
    }
}
