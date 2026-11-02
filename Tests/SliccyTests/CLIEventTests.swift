import Foundation
import Testing
@testable import Sliccy

struct CLIEventTests {
    @Test func fragmentedUnicodeAndMixedFamilies() throws {
        let input = Data("{\"schema\":1,\"event\":\"linked\",\"caps\":[\"fs\"]}\n{\"t\":\"text\",\"id\":\"opaque-entry\",\"delta\":\"Grüße 🌿\"}\n".utf8)
        var decoder = NDJSONDecoder()
        var events: [CLIEvent] = []
        for byte in input { events += try decoder.append(Data([byte])) }
        #expect(events.count == 2)
        #expect(events[0].kind == "linked")
        #expect(events[1].delta == "Grüße 🌿")
        #expect(events[1].id == "opaque-entry")
    }

    @Test func futureFieldsAndEventsRemainCompatible() throws {
        var decoder = NDJSONDecoder()
        let events = try decoder.append(Data("\n{\"t\":\"future-event\",\"futureField\":true}\n{\"t\":\"run\",\"state\":\"working\"}".utf8))
        #expect(events.first?.kind == "future-event")
        let tail = try decoder.finish()
        #expect(tail.first?.kind == "run")
        #expect(tail.first?.id == nil)
    }

    @Test func malformedJSONFailsExplicitly() {
        var decoder = NDJSONDecoder()
        #expect(throws: (any Error).self) { try decoder.append(Data("not json\n".utf8)) }
    }
}
