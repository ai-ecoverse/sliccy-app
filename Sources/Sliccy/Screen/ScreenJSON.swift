import Foundation

/// JSONDecoder accepts duplicate keys. The private protocol does not.
/// Validate lexical structure and decoded key uniqueness before typed decoding.
enum ScreenJSON {
    static func object(_ data: Data, limit: Int = 4096) throws -> [String: Any] {
        guard !data.isEmpty, data.count <= limit, String(data: data, encoding: .utf8) != nil else { throw ScreenFailure.incompatible }
        var scanner = Scanner(bytes: Array(data))
        try scanner.value(depth: 0)
        scanner.whitespace()
        guard scanner.offset == data.count,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw ScreenFailure.incompatible }
        return object
    }
    static func keys(_ object: [String: Any], exact: [String]) throws {
        guard Set(object.keys) == Set(exact) else { throw ScreenFailure.incompatible }
    }
    private struct Scanner {
        let bytes: [UInt8]
        var offset = 0
        mutating func whitespace() { while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 } }
        mutating func take(_ byte: UInt8) throws {
            whitespace()
            guard offset < bytes.count, bytes[offset] == byte else { throw ScreenFailure.incompatible }
            offset += 1
        }
        mutating func string() throws -> String {
            whitespace()
            let start = offset
            try take(34)
            while offset < bytes.count {
                let byte = bytes[offset]; offset += 1
                if byte == 34 { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<offset])) }
                if byte == 92 { offset += 1 }
            }
            throw ScreenFailure.incompatible
        }
        mutating func value(depth: Int) throws {
            whitespace()
            guard depth <= 8, offset < bytes.count else { throw ScreenFailure.incompatible }
            switch bytes[offset] {
            case 123:
                offset += 1; whitespace()
                if offset < bytes.count, bytes[offset] == 125 { offset += 1; return }
                var keys = Set<String>()
                while true {
                    let key = try string()
                    guard keys.insert(key).inserted else { throw ScreenFailure.incompatible }
                    try take(58); try value(depth: depth + 1); whitespace()
                    if offset < bytes.count, bytes[offset] == 125 { offset += 1; return }
                    try take(44)
                }
            case 91:
                offset += 1; whitespace()
                if offset < bytes.count, bytes[offset] == 93 { offset += 1; return }
                while true {
                    try value(depth: depth + 1); whitespace()
                    if offset < bytes.count, bytes[offset] == 93 { offset += 1; return }
                    try take(44)
                }
            case 34: _ = try string()
            default:
                let start = offset
                while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
                guard start < offset else { throw ScreenFailure.incompatible }
                _ = try JSONSerialization.jsonObject(with: Data(bytes[start..<offset]), options: [.fragmentsAllowed])
            }
        }
    }
}
