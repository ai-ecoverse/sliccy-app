import Foundation
import CoreVideo
import ImageIO
import Testing
@testable import Sliccy

struct ScreenCaptureTests {
    @Test func syntheticPixelsEncodeWithoutSourceMetadata() throws {
        var buffer: CVPixelBuffer?
        #expect(CVPixelBufferCreate(kCFAllocatorDefault, 32, 24, kCVPixelFormatType_32BGRA, nil, &buffer) == kCVReturnSuccess)
        let image = try #require(buffer)
        #expect(CVPixelBufferLockBaseAddress(image, []) == kCVReturnSuccess)
        memset(CVPixelBufferGetBaseAddress(image), 127, CVPixelBufferGetBytesPerRow(image) * 24)
        CVPixelBufferUnlockBaseAddress(image, [])
        let encoded = try ScreenJPEG.encode(image)
        #expect(encoded.count < 2_097_152)
        let source = try #require(CGImageSourceCreateWithData(encoded as CFData, nil))
        let properties = try #require(CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any])
        #expect(properties[kCGImagePropertyPixelWidth] as? Int == 32)
        #expect(properties[kCGImagePropertyPixelHeight] as? Int == 24)
        #expect(properties[kCGImagePropertyExifDictionary] == nil)
        #expect(properties[kCGImagePropertyGPSDictionary] == nil)
        #expect(properties[kCGImagePropertyTIFFDictionary] == nil)
    }
    @Test func metadataSegmentsAreRemovedAndMalformedLengthsRefused() throws {
        let jpeg = Data([0xff,0xd8, 0xff,0xe1,0,5,1,2,3, 0xff,0xfe,0,3,4, 0xff,0xda,0,2, 0xff,0xd9])
        #expect(try ScreenJPEG.withoutMetadata(jpeg) == Data([0xff,0xd8,0xff,0xda,0,2,0xff,0xd9]))
        #expect(throws: ScreenFailure.incompatible) { try ScreenJPEG.withoutMetadata(Data([0xff,0xd8,0xff,0xe1,0,12,0])) }
    }
    @Test func indicatorCannotRecoverSilentlyAfterAUIStall() {
        let health = ScreenIndicatorHealth(), now = ContinuousClock.now
        health.renew(visible: true, now: now)
        #expect(health.check(now: now))
        health.renew(visible: true, now: now.advanced(by: .seconds(2)))
        #expect(!health.check(now: now.advanced(by: .seconds(2))))
    }
}
