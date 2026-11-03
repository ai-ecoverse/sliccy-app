#if SLICCY_NATIVE_SCREEN_PROOF
import Foundation
import CoreVideo
import ImageIO

/// Closed source: no initializer accepts pixels, files, IDs or capture objects.
/// Every byte (including row padding) is initialized before the production JPEG
/// encoder sees it. This proves generated content only, never SCK exclusion.
struct ScreenProofSyntheticSource: Sendable {
    let jpeg: Data
    static let dimension = 16
    init() throws {
        var storage: CVPixelBuffer?
        guard CVPixelBufferCreate(kCFAllocatorDefault, 16, 16, kCVPixelFormatType_32BGRA, nil, &storage) == kCVReturnSuccess,
              let storage, CVPixelBufferLockBaseAddress(storage, []) == kCVReturnSuccess else { throw ScreenFailure.resourceLimit }
        guard let pixels = CVPixelBufferGetBaseAddress(storage) else {
            CVPixelBufferUnlockBaseAddress(storage, []); throw ScreenFailure.resourceLimit
        }
        memset(pixels, 128, CVPixelBufferGetBytesPerRow(storage) * 16)
        CVPixelBufferUnlockBaseAddress(storage, [])
        jpeg = try ScreenJPEG.encode(storage)
        guard jpeg.count <= 2048, let source = CGImageSourceCreateWithData(jpeg as CFData, nil),
              let decoded = CGImageSourceCreateImageAtIndex(source, 0, nil), decoded.width == 16, decoded.height == 16,
              let color = CGColorSpace(name: CGColorSpace.sRGB) else { throw ScreenFailure.protection }
        var bytes = [UInt8](repeating: 0, count: 16 * 16 * 4)
        let valid = bytes.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(data: buffer.baseAddress, width: 16, height: 16, bitsPerComponent: 8,
                bytesPerRow: 64, space: color, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return false }
            context.draw(decoded, in: CGRect(x: 0, y: 0, width: 16, height: 16))
            return true
        }
        guard valid, stride(from: 0, to: bytes.count, by: 4).allSatisfy({ offset in
            (0..<3).allSatisfy { abs(Int(bytes[offset + $0]) - 128) <= 3 }
        }) else { throw ScreenFailure.protection }
    }
    static func monotonicMilliseconds() -> String {
        var scale = mach_timebase_info_data_t(); mach_timebase_info(&scale)
        return String(UInt64(Double(mach_absolute_time()) * Double(scale.numer) / Double(scale.denom) / 1e6))
    }
}
#endif
