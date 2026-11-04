#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security
import Testing
@testable import Sliccy

struct ScreenRunnerSliceTests {
    typealias B = ScreenRunnerSliceBinding
    func identity(_ byte: UInt8 = 1, type: Int = 2) -> B.Identity {
        .init(type: type, hash: Data(repeating: byte, count: 20), full: Data(repeating: byte, count: 32))
    }
    func member(_ byte: UInt8 = 1, type: Int = 2, offset: UInt64 = 0) -> B.Member {
        .init(slice: .init(cpu: 16777228, subtype: Int32(offset), offset: offset, size: 64), identity: identity(byte, type: type))
    }
    @Test func sameTypeUniqueSelectionAndFullHashPrefixAreMandatory() throws {
        #expect((try? B.unique(identity(), [member(2), member()])) == 1)
        #expect(throws: ScreenFailure.peerUntrusted) { try B.unique(identity(), [member(2)]) }
        #expect(throws: ScreenFailure.peerUntrusted) { try B.unique(identity(), [member(), member(offset: 128)]) }
        #expect(throws: ScreenFailure.peerUntrusted) { try B.unique(identity(), [member(type: 1)]) }
        let wrong = B.Identity(type: 2, hash: identity().hash, full: Data(repeating: 9, count: 32))
        #expect(throws: ScreenFailure.peerUntrusted) { try B.unique(wrong, [member()]) }
    }
    @Test func everyLiveRoleUsesUniqueSliceAndItsExactPolicy() throws {
        for role in ["ai.sliccy.mac", "ai.sliccy.proof-helper", "ai.sliccy.slicc", "com.apple.osascript", "com.google.Chrome", "com.apple.SecurityAgent"] + B.systemTestRoles {
            let trace = ScreenRunnerSecurityTrace(executable: URL(fileURLWithPath: "/fixed/" + role), identifier: role)
            let team = role == "com.google.Chrome" ? "EQHXZ8M8AV" : role.hasPrefix("ai.sliccy.") ? "S8LB56P782" : nil
            let policy = try B.Policy.make(role, team: team)
            let result = try B.bind(pid: 42, path: trace.executable, expected: trace.hash, policy: policy, site: "test", calls: trace.calls)
            #expect(result.identity.hash == trace.hash)
            let expected: [UInt32] = role == "com.google.Chrome" ? [9, 25] : [25]
            #expect(trace.events.filter { $0.kind == "static-check" }.map(\.flags) == expected)
            #expect(trace.events.filter { $0.kind == "dynamic-check" }.allSatisfy { $0.flags == (policy.chrome ? 0 : 16) && $0.rule == policy.requirement })
            #expect(trace.events.filter { $0.kind == "rule" }.allSatisfy { $0.value == policy.requirement })
        }
    }
    @Test func platformOffsetPathAndIncarnationFailuresRefuseThroughActualBinder() throws {
        let role = "com.apple.WindowServer", trace = ScreenRunnerSecurityTrace(executable: URL(fileURLWithPath: "/fixed/WindowServer"), identifier: role)
        let policy = try B.Policy.make(role, team: nil)
        for failure in ["platform", "offset", "path", "incarnation", "catalogue", "file", "strict"] {
            var calls = trace.calls
            let original = calls
            var samples = 0
            let kernel = B.Kernel(path: trace.executable, hash: trace.hash, flags: failure == "platform" ? 0 : 0x04000000)
            calls.slices = .init(open: { path in
                B.Snapshot(path: path, slices: [.init(cpu: 16777228, subtype: 0, offset: failure == "offset" ? 128 : 0, size: 64)], check: {
                    if failure == "file" { throw ScreenFailure.peerUntrusted }
                })
            }, explicit: { _, _ in "slice-0" }, kernel: { _ in
                failure == "path" ? .init(path: URL(fileURLWithPath: "/different"), hash: trace.hash, flags: 0x04000000) : kernel
            }, incarnation: { _ in samples += 1; return failure == "incarnation" && samples == 2 ? ["changed"] : ["stable"] })
            if failure == "path" {
                calls = .init(makeRule: original.makeRule, staticCode: original.staticCode, guest: original.guest,
                    copyStatic: original.copyStatic, checkStatic: original.checkStatic, checkGuest: original.checkGuest,
                    information: { code in
                        let value = try original.information(code)
                        return .init(hash: value.hash, path: URL(fileURLWithPath: "/different"), identifier: value.identifier,
                                     identity: value.identity, offset: value.offset)
                    }, slices: calls.slices)
            }
            if failure == "strict" {
                calls = .init(makeRule: original.makeRule, staticCode: original.staticCode, guest: original.guest,
                    copyStatic: original.copyStatic, checkStatic: { _, _, _ in -66999 }, checkGuest: original.checkGuest,
                    information: original.information, slices: calls.slices)
            }
            let expected = failure == "catalogue" ? B.Catalogue(path: trace.executable, members: [member(7)]) : nil
            #expect(throws: ScreenFailure.peerUntrusted) {
                try B.bind(pid: 42, path: trace.executable, expected: trace.hash, catalogue: expected, policy: policy, site: "test", calls: calls)
            }
        }
    }
    @Test func preflightCatalogueDoesNotPinDefaultStaticSlice() throws {
        let trace = ScreenRunnerSecurityTrace(executable: URL(fileURLWithPath: "/fixed/helper"), identifier: "ai.sliccy.proof-helper")
        var calls = trace.calls
        let original = calls, a = member(2), b = member(offset: 128)
        calls.slices = .init(open: { path in B.Snapshot(path: path, slices: [a.slice, b.slice], check: {}) },
            explicit: { _, slice in slice.offset == 0 ? "other-slice" : "running-slice" },
            kernel: { _ in .init(path: trace.executable, hash: trace.hash, flags: 0) }, incarnation: { _ in ["stable"] })
        calls = .init(makeRule: original.makeRule, staticCode: original.staticCode, guest: original.guest, copyStatic: original.copyStatic,
            checkStatic: original.checkStatic, checkGuest: original.checkGuest, information: { code in
                let m = code == "other-slice" ? a : b
                return .init(hash: m.identity.hash, path: trace.executable, identifier: "ai.sliccy.proof-helper", identity: m.identity,
                             offset: code == "guest-static" ? nil : m.slice.offset)
            }, slices: calls.slices)
        let policy = try B.Policy.make("ai.sliccy.proof-helper", team: "S8LB56P782")
        let catalogue = try B.preflight(path: trace.executable, policy: policy, calls: calls)
        #expect(catalogue.members == [a, b])
        #expect(try B.bind(pid: 42, path: trace.executable, expected: nil, catalogue: catalogue, policy: policy, site: "test", calls: calls) == b)
    }
    @Test func actualNativeAttributeAndInformationConstructorsAreClosed() throws {
        typealias Calls = ScreenRunnerSecurityCalls<SecStaticCode, SecCode, SecRequirement>
        let slice = member(offset: 128).slice, attrs = Calls.nativeAttributes(slice) as NSDictionary
        #expect(attrs.count == 2)
        #expect(attrs[kSecCodeAttributeArchitecture as String] as? NSNumber == NSNumber(value: slice.cpu))
        #expect(attrs[kSecCodeAttributeSubarchitecture as String] as? NSNumber == NSNumber(value: slice.subtype))
        #expect(attrs["UniversalFileOffset"] == nil)
        let value: [String: Any] = [kSecCodeInfoUnique as String: identity().hash, kSecCodeInfoDigestAlgorithm as String: NSNumber(value: 2),
            "cdhashes-full": [NSNumber(value: 2): identity().full], "CodeOffset": NSNumber(value: 128),
            kSecCodeInfoIdentifier as String: "ai.sliccy.mac", kSecCodeInfoMainExecutable as String: URL(fileURLWithPath: "/fixed/app")]
        let info = try Calls.nativeInformation(value)
        #expect(info.identity == identity() && info.offset == 128 && info.identifier == "ai.sliccy.mac")
        var changed = value; changed[kSecCodeInfoDigestAlgorithm as String] = true
        #expect(try Calls.nativeInformation(changed).identity == nil)
        changed = value; changed["CodeOffset"] = -1
        #expect(try Calls.nativeInformation(changed).offset == nil)
    }
    @Test func actualSystemCallerUsesCommonBindingAndNeverDropsPlatform() throws {
        for role in ["ai.sliccy.mac", "com.apple.SecurityAgent"] + B.systemTestRoles {
            let trace = ScreenRunnerSecurityTrace(executable: URL(fileURLWithPath: "/fixed/" + role), identifier: role)
            let result = try ScreenRunnerSystemOwner.code(pid: 42, identifier: role, app: role == "ai.sliccy.mac", calls: trace.calls)
            #expect(result.hash == trace.hash && result.path == trace.executable.path && result.identifier == role)
            #expect(trace.events.filter { $0.kind == "static-check" }.map(\.flags) == [25])
            var calls = trace.calls
            let original = calls.slices!
            calls.slices = .init(open: original.open, explicit: original.explicit,
                kernel: { _ in .init(path: trace.executable, hash: trace.hash, flags: 0) }, incarnation: original.incarnation)
            if role != "ai.sliccy.mac" {
                #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerSystemOwner.code(pid: 42, identifier: role, calls: calls) }
            }
        }
    }
    @Test func actualByteParserRejectsAmbiguousAndMalformedSlices() throws {
        func image() -> Data {
            var data = Data(repeating: 0, count: 192)
            func put(_ offset: Int, _ value: UInt32, big: Bool = true) {
                for i in 0..<4 { data[offset + i] = UInt8(truncatingIfNeeded: value >> UInt32((big ? 3 - i : i) * 8)) }
            }
            put(0, 0xcafebabe); put(4, 2)
            for (index, offset) in [64, 128].enumerated() {
                let entry = 8 + index * 20
                put(entry, 16777228); put(entry + 4, UInt32(index)); put(entry + 8, UInt32(offset)); put(entry + 12, 64); put(entry + 16, 6)
                put(offset, 0xfeedfacf, big: false); put(offset + 4, 16777228, big: false); put(offset + 8, UInt32(index), big: false)
            }
            return data
        }
        let data = image(), slices = try ScreenRunnerSliceFile.slices(data)
        #expect(slices.count == 2 && slices.map(\.offset) == [64, 128] && slices.map(\.subtype) == [0, 1])
        for field in ["overlap", "cpu", "subtype", "alignment", "range", "count", "duplicate"] {
            var changed = data
            switch field {
            case "overlap": changed[39] = 64
            case "cpu": changed[31] = 1
            case "subtype": changed[35] = 9
            case "alignment": changed[47] = 31
            case "range": changed[43] = 255
            case "count": changed[7] = 9
            default: changed[35] = 0; changed[136] = 0
            }
            #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerSliceFile.slices(changed) }
        }
        #expect(throws: ScreenFailure.peerUntrusted) { try ScreenRunnerSliceFile.slices(Data(data.prefix(100))) }
    }
    @Test func actualCodeCheckRemainsBetweenBSDObservations() throws {
        let raw = ScreenRunnerBSDTests().observation(), resolved = try ScreenRunnerBSD.resolve(raw, pid: 42)
        let hash = identity().hash, code = ScreenRunnerSystemOwner.Code(identifier: "com.apple.WindowServer", path: "/fixed/WindowServer", hash: identity().hash)
        var order: [String] = []
        let result = try ScreenRunnerSystemOwner.verifyIdentity(42, identifier: code.identifier,
            observe: { phase in order.append(phase); return resolved }, check: { order.append("code"); return code }, kernel: { (code.path, hash) })
        #expect(order == ["before", "code", "after"] && result.sysctlBound)
        #expect(throws: ScreenFailure.peerUntrusted) {
            try ScreenRunnerSystemOwner.verifyIdentity(42, identifier: code.identifier, observe: { _ in resolved },
                check: { throw ScreenFailure.peerUntrusted }, kernel: { (code.path, hash) })
        }
        var changed = raw; changed.target.before.value.seconds += 1; changed.target.after.value.seconds += 1
        let different = try ScreenRunnerBSD.resolve(changed, pid: 42)
        #expect(throws: ScreenFailure.peerUntrusted) {
            try ScreenRunnerSystemOwner.verifyIdentity(42, identifier: code.identifier, observe: { $0 == "after" ? different : resolved },
                check: { code }, kernel: { (code.path, hash) })
        }
    }
}
private extension ScreenRunnerSliceBinding {
    static var systemTestRoles: [String] { ScreenRunnerInventoryBoundary.systemRoles.sorted() }
}
#endif
