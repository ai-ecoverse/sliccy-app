#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Security
import ScreenSystem

struct ScreenRunnerSecurityCalls<Static, Guest, Rule> {
    struct NativeFailure: Error {
        let operation: String, status: Int32, valuePresent: Bool
    }
    final class Trace {
        var rows: [[Int64]] = []
        var failure: [String: Any] = [:]
        var values: [[Any]] = []
        private var encoded: [Data] = []
        func information(_ value: Information) throws {
            let row: [Any] = [value.hash?.base64EncodedString() as Any? ?? NSNull(), value.path?.path as Any? ?? NSNull(),
                value.identifier as Any? ?? NSNull(), value.identity.map { [$0.type, $0.hash.base64EncodedString(), $0.full.base64EncodedString()] as [Any] } as Any? ?? NSNull(),
                value.offset.map { String($0) } as Any? ?? NSNull()]
            let data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys])
            let index: Int
            if let found = encoded.firstIndex(of: data) { index = found }
            else { index = encoded.count; encoded.append(data); values.append(row) }
            rows[rows.count - 1].append(Int64(index))
        }
        func call<T>(_ operation: Int64, _ body: () throws -> T) throws -> T {
            do { let value = try body(); rows.append([operation, 0, 1]); return value }
            catch {
                if let error = error as? NativeFailure {
                    rows.append([operation, Int64(error.status), error.valuePresent ? 1 : 0])
                    failure = ["operation": error.operation, "status": error.status, "valuePresent": error.valuePresent]
                } else { rows.append([operation, 0, -1]); failure = ["operation": operation, "status": NSNull(), "valuePresent": false] }
                throw error
            }
        }
    }
    struct Information {
        let hash: Data?
        let path: URL?
        var identifier: String? = nil
        var identity: ScreenRunnerSliceBinding.Identity? = nil
        var offset: UInt64? = nil
    }
    let makeRule: (String) throws -> Rule
    let staticCode: (URL) throws -> Static
    let guest: (pid_t) throws -> Guest
    let copyStatic: (Guest) throws -> Static
    let checkStatic: (Static, SecCSFlags, Rule) -> OSStatus
    let checkGuest: (Guest, SecCSFlags, Rule) -> OSStatus
    let information: (Static) throws -> Information
    var slices: ScreenRunnerSliceBinding.Operations<Static>? = nil
    func recording(_ trace: Trace) -> Self {
        var result = Self(makeRule: { text in try trace.call(1) { try self.makeRule(text) } }, staticCode: staticCode,
            guest: { pid in try trace.call(2) { try self.guest(pid) } }, copyStatic: { guest in try trace.call(3) { try self.copyStatic(guest) } },
            checkStatic: checkStatic, checkGuest: checkGuest, information: { code in
                let value = try trace.call(4) { try self.information(code) }
                try trace.information(value); return value
            })
        if let operations = slices {
            result.slices = .init(open: { path in try trace.call(5) { try operations.open(path) } },
                explicit: { path, slice in try trace.call(6) { try operations.explicit(path, slice) } },
                kernel: { pid in try trace.call(7) { try operations.kernel(pid) } },
                incarnation: { pid in try trace.call(8) { try operations.incarnation(pid) } })
        }
        return result
    }
}

extension ScreenRunnerSecurityCalls where Static == SecStaticCode, Guest == SecCode, Rule == SecRequirement {
    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        let type = String(cString: number.objCType)
        guard type != "f", type != "d" else { return nil }
        return number.int64Value
    }
    static func nativeAttributes(_ slice: ScreenRunnerSliceBinding.Slice) -> CFDictionary {
        [kSecCodeAttributeArchitecture as String: NSNumber(value: slice.cpu),
         kSecCodeAttributeSubarchitecture as String: NSNumber(value: slice.subtype)] as CFDictionary
    }
    static func nativeInformation(_ values: [String: Any]) throws -> Information {
            let hash = values[kSecCodeInfoUnique as String] as? Data
            let type = integer(values[kSecCodeInfoDigestAlgorithm as String])
            let full = values["cdhashes-full"] as? [NSNumber: Data]
            var identity: ScreenRunnerSliceBinding.Identity?
            if let hash, let type, let digest = full?[NSNumber(value: type)] {
                identity = .init(type: Int(type), hash: hash, full: digest)
            }
            let offset = integer(values["CodeOffset"])
            return .init(hash: hash, path: values[kSecCodeInfoMainExecutable as String] as? URL,
                identifier: values[kSecCodeInfoIdentifier as String] as? String, identity: identity,
                offset: offset.flatMap { $0 >= 0 ? UInt64($0) : nil })
    }
    static var native: Self {
        .init(makeRule: { text in
            var rule: SecRequirement?
            let status = SecRequirementCreateWithString(text as CFString, [], &rule)
            guard status == errSecSuccess, let rule else { throw NativeFailure(operation: "requirement", status: status, valuePresent: rule != nil) }
            return rule
        }, staticCode: { path in
            var code: SecStaticCode?
            let status = SecStaticCodeCreateWithPath(path as CFURL, [], &code)
            guard status == errSecSuccess, let code else { throw NativeFailure(operation: "static", status: status, valuePresent: code != nil) }
            return code
        }, guest: { pid in
            var code: SecCode?
            let status = SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary, [], &code)
            guard status == errSecSuccess, let code else { throw NativeFailure(operation: "guest", status: status, valuePresent: code != nil) }
            return code
        }, copyStatic: { guest in
            var code: SecStaticCode?
            let status = SecCodeCopyStaticCode(guest, [], &code)
            guard status == errSecSuccess, let code else { throw NativeFailure(operation: "guest-static", status: status, valuePresent: code != nil) }
            return code
        }, checkStatic: SecStaticCodeCheckValidity, checkGuest: SecCodeCheckValidity, information: { code in
            var info: CFDictionary?
            let status = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSInternalInformation), &info)
            guard status == errSecSuccess, let values = info as? [String: Any] else { throw NativeFailure(operation: "information", status: status, valuePresent: info != nil) }
            return try nativeInformation(values)
        }, slices: .init(open: ScreenRunnerSliceFile.open, explicit: { path, slice in
            var code: SecStaticCode?
            let attributes = nativeAttributes(slice)
            let status = SecStaticCodeCreateWithPathAndAttributes(path as CFURL, [], attributes, &code)
            guard status == errSecSuccess, let code else { throw NativeFailure(operation: "explicit-static", status: status, valuePresent: code != nil) }
            return code
        }, kernel: { pid in
            let path = try ScreenRunnerKernelSample.path(pid), hash = try ScreenRunnerKernelSample.hash(pid)
            var flags: UInt32 = 0
            let status = sliccy_runner_flags(pid, &flags)
            guard status == 0 else { throw NativeFailure(operation: "kernel-flags", status: status, valuePresent: false) }
            return .init(path: URL(fileURLWithPath: path), hash: hash, flags: flags)
        }, incarnation: { pid in
            var raw = sliccy_runner_bsd_observation()
            let status = sliccy_runner_bsd_observe(pid, &raw)
            guard status == 0 else { throw NativeFailure(operation: "incarnation", status: status, valuePresent: false) }
            let value = try ScreenRunnerBSD.resolve(raw, pid: pid)
            let fields: [Any] = [raw.self_pid, raw.parent_pid, ScreenRunnerBSD.bracketFields(raw.controls.0),
                ScreenRunnerBSD.bracketFields(raw.controls.1), ScreenRunnerBSD.bracketFields(raw.target)]
            let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
            guard let text = String(data: data, encoding: .utf8) else { throw ScreenFailure.peerUntrusted }
            return [String(value.sample.pid), String(value.sample.parent), String(value.sample.effectiveUID), String(value.sample.realUID),
                String(value.sample.savedUID), String(value.sample.seconds), String(value.sample.microseconds), value.usedSysctl ? "sysctl" : "proc", text]
        }))
    }
}
#endif
