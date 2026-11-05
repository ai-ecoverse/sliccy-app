#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation

final class ScreenRunnerSurfaceDiagnostics: @unchecked Sendable {
    enum Predicate: String, CaseIterable, Sendable { case host, identifier, team, hash, role, path, operation }
    enum Operation: String, CaseIterable, Sendable {
        case host, executableRead = "executable-read", executableHash = "executable-hash", policy
        case staticCode = "static-code", requirement, staticValidity = "static-validity"
        case signingInformation = "signing-information", catalogue, launch
    }
    struct Notice: Sendable {
        let predicate: Predicate, operation: Operation, status: Int32?
        let at: ContinuousClock.Instant
        var fields: [String: Any] {
            ["predicate": predicate.rawValue, "operation": operation.rawValue,
             "status": status.map { $0 as Any } ?? NSNull()]
        }
    }
    private let lock = NSLock()
    private var reported = false
    private let output: @Sendable (Notice) -> Void
    init(output: @escaping @Sendable (Notice) -> Void) { self.output = output }
    func reject(_ predicate: Predicate, _ operation: Operation, status: Int32? = nil) {
        let at = ContinuousClock.now
        lock.lock(); let first = !reported; reported = true; lock.unlock()
        if first { output(.init(predicate: predicate, operation: operation, status: status, at: at)) }
    }
    func observe<T>(_ predicate: Predicate, _ operation: Operation, body: () throws -> T) throws -> T {
        do { return try body() }
        catch { reject(predicate, operation); throw error }
    }
    func verifyHash(_ actual: String, expected: String) throws {
        guard actual == expected else { reject(.hash, .executableHash); throw ScreenFailure.peerUntrusted }
    }
}
#endif
