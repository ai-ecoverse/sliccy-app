import Foundation
import Darwin
import Testing
@testable import Sliccy

struct ScreenAuditTests {
    @Test func auditIsPrivateContentFreeAndRejectsSymlinks() throws {
        let root = URL(fileURLWithPath: "/private/tmp").appending(path: "sliccy-audit-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let audit = try ScreenAudit(base: root)
        let session = try ScreenID.make()
        try audit.record(.grantIntent, reason: "awaiting-consent", scope: "window", session: session)
        #expect(throws: ScreenFailure.audit) { try audit.record(.grant, reason: "secret window title", scope: "window", session: session) }
        let directory = root.appending(path: "ai.sliccy.mac/Audit")
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        let journal = try #require(files.first { $0.pathExtension == "jsonl" })
        let rows = try String(contentsOf: journal, encoding: .utf8).split(separator: "\n")
        #expect(rows.count == 1)
        let json = try #require(JSONSerialization.jsonObject(with: Data(rows[0].utf8)) as? [String: Any])
        #expect(Set(json.keys) == ["minute", "event", "reason", "scope", "session"])
        let attributes = try FileManager.default.attributesOfItem(atPath: journal.path)
        #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        let victim = root.appending(path: "do-not-write")
        try Data("unchanged".utf8).write(to: victim)
        try FileManager.default.removeItem(at: directory.appending(path: "quota.lock"))
        try FileManager.default.createSymbolicLink(at: directory.appending(path: "quota.lock"), withDestinationURL: victim)
        #expect(throws: ScreenFailure.audit) { try audit.record(.stop, reason: "stopped", scope: "window", session: session) }
        #expect(try String(contentsOf: victim, encoding: .utf8) == "unchanged")
    }
    @Test func sharedQuotaRemovesExpiredBrokerLogs() throws {
        let root = URL(fileURLWithPath: "/private/tmp").appending(path: "sliccy-audit-age-" + UUID().uuidString)
        let audit = try ScreenAudit(base: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let old = Date(timeIntervalSince1970: 1_700_000_000)
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: old)
        let broker = root.appending(path: "slicc/audit/broker-20231114-fixture.jsonl")
        try Data("{}\n".utf8).write(to: broker)
        try FileManager.default.setAttributes([.posixPermissions: 0o600, .modificationDate: old], ofItemAtPath: broker.path)
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: old.addingTimeInterval(31 * 86400))
        #expect(!FileManager.default.fileExists(atPath: broker.path))
    }

    @Test func dailyRotationAndSharedExpiryIgnoreRefreshedModificationTimes() throws {
        let root = URL(fileURLWithPath: "/private/tmp").appending(path: "sliccy-audit-bucket-" + UUID().uuidString)
        let audit = try ScreenAudit(base: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let formatter = ISO8601DateFormatter()
        let firstDay = try #require(formatter.date(from: "2026-01-01T23:30:00Z"))
        let nextDay = try #require(formatter.date(from: "2026-01-02T00:00:00Z"))
        let expiry = try #require(formatter.date(from: "2026-01-31T00:00:00Z"))
        let directory = root.appending(path: "ai.sliccy.mac/Audit")
        func journals() throws -> [URL] {
            try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).filter { $0.pathExtension == "jsonl" }
        }
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: firstDay)
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: firstDay.addingTimeInterval(60))
        #expect(try journals().count == 1)
        let first = try #require(journals().first)
        #expect(first.lastPathComponent.hasPrefix("app-20260101-"))
        #expect(try String(contentsOf: first, encoding: .utf8).split(separator: "\n").count == 2)
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: nextDay)
        #expect(try journals().count == 2)
        #expect(try journals().contains { $0.lastPathComponent.hasPrefix("app-20260102-") })
        // Simulate appends/touches refreshing both writers' files long after creation.
        try FileManager.default.setAttributes([.modificationDate: expiry], ofItemAtPath: first.path)
        let broker = root.appending(path: "slicc/audit/broker-20260101-fixture.jsonl")
        try Data("{}\n".utf8).write(to: broker)
        try FileManager.default.setAttributes([.posixPermissions: 0o600, .modificationDate: expiry], ofItemAtPath: broker.path)
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: expiry.addingTimeInterval(-1))
        #expect(FileManager.default.fileExists(atPath: first.path))
        #expect(FileManager.default.fileExists(atPath: broker.path))
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: expiry)
        #expect(!FileManager.default.fileExists(atPath: first.path))
        #expect(!FileManager.default.fileExists(atPath: broker.path))
        #expect(try journals().contains { $0.lastPathComponent.hasPrefix("app-20260102-") })
    }

    @Test func earlierMtimeAndUndatedPrototypeFilesCannotExtendRetention() throws {
        let root = URL(fileURLWithPath: "/private/tmp").appending(path: "sliccy-audit-legacy-" + UUID().uuidString)
        let audit = try ScreenAudit(base: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let now = try #require(ISO8601DateFormatter().date(from: "2026-01-31T00:00:00Z"))
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: now)
        let directory = root.appending(path: "ai.sliccy.mac/Audit")
        let names = ["app-20260131-earlier.jsonl", "app-undated.jsonl", "app-20260230-invalid-date.jsonl"]
        for name in names {
            let file = directory.appending(path: name)
            try Data("{}\n".utf8).write(to: file)
            try FileManager.default.setAttributes([.posixPermissions: 0o600, .modificationDate: name.contains("earlier") ? now.addingTimeInterval(-31 * 86400) : now], ofItemAtPath: file.path)
        }
        try audit.record(.stop, reason: "stopped", scope: nil, session: nil, now: now)
        for name in names { #expect(!FileManager.default.fileExists(atPath: directory.appending(path: name).path)) }
    }
}
