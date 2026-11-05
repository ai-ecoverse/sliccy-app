#if SLICCY_CAPTURE_RUNNER_PROOF
import Foundation
import Testing
@testable import Sliccy

struct ScreenRunnerInventoryBoundaryTests {
    typealias B = ScreenRunnerInventoryBoundary
    struct Fixture {
        var cg: [B.CGRecord] = [], sck: [B.SCKRecord] = [], owners: [pid_t: B.Identity] = [:]
        var context: B.Context
        init(_ selected: ScreenRunnerCase = .displayExclusion) {
            var browsers: [ScreenRunnerBrowserWindow: pid_t] = [:]
            if selected.needsBrowser {
                for (index, layout) in ScreenRunnerBrowserWindow.allCases.enumerated() { browsers[layout] = pid_t(20 + index) }
            }
            context = .init(app: 10, surface: 11, browsers: browsers, selected: selected)
            add(id: 1, pid: 10, bundle: "ai.sliccy.mac", rect: CGRect(x: 64, y: 512, width: 320, height: 128))
            add(id: 2, pid: 11, bundle: "ai.sliccy.proof-helper", rect: CGRect(x: 128, y: 128, width: 256, height: 256))
            for (layout, pid) in browsers { add(id: UInt32(pid), pid: pid, bundle: "com.google.Chrome", rect: layout.rect) }
            add(id: 30, pid: 30, bundle: "com.apple.dock", rect: CGRect(x: 0, y: 700, width: 800, height: 60), apple: true)
        }
        mutating func add(id: UInt32, pid: pid_t, bundle: String, rect: CGRect = CGRect(x: 100, y: 400, width: 200, height: 100), apple: Bool = false) {
            cg.append(.init(id: id, pid: pid, rect: rect, layer: 0))
            sck.append(.init(id: id, pid: pid, bundle: bundle, rect: rect, layer: 0))
            owners[pid] = Self.owner(pid, bundle: bundle, apple: apple)
        }
        static func owner(_ pid: pid_t, bundle: String, apple: Bool, hash: UInt8 = 1, seconds: UInt64 = 123) -> B.Identity {
            .init(pid: pid, parent: 1, uid: bundle == "com.apple.WindowServer" ? 88 : 501, seconds: seconds, microseconds: 42,
                  identifier: bundle, path: "/fixed/" + bundle, hash: Data(repeating: hash, count: 20),
                  appleAnchored: apple, verified: true, sysctlBound: bundle == "com.apple.WindowServer", realUID: bundle == "com.apple.WindowServer" ? 0 : nil, savedUID: bundle == "com.apple.WindowServer" ? 0 : nil)
        }
        func read(display: UInt32 = 1, rect: CGRect = CGRect(x: 0, y: 0, width: 1024, height: 768), diagnostics: ScreenRunnerInventoryDiagnostics.Attempt? = nil) throws -> B.Validated {
            try B.validate(display: display, rect: rect, cg: cg, sck: sck,
                           context: context, diagnostics: diagnostics, verify: { pid in
                guard let owner = owners[pid] else { throw ScreenRunnerInventoryIssue.ownerAttribution }
                return owner
            })
        }
    }
    @Test func actualBoundarySelectsOnlyTheOwnedHelperWithoutTitles() throws {
        for title in [nil, "unexpected", "Sliccy proof host A1"] as [String?] {
            var fixture = Fixture()
            for index in fixture.sck.indices { fixture.sck[index].diagnosticTitle = title }
            let result = try fixture.read()
            #expect(result.allowed == 2)
            try result.requireSelection([2])
            for ids in [[], [UInt32(1)], [20], [30], [2, 20]] {
                #expect(throws: ScreenFailure.protection) { try result.requireSelection(ids) }
            }
        }
    }
    @Test func recognizedAuthorizationIsProtectedInEveryOrdinaryCase() throws {
        for selected in ScreenRunnerCase.allCases where selected != .authorizationExclusion {
            var fixture = Fixture(selected)
            fixture.add(id: 40, pid: 40, bundle: "com.apple.SecurityAgent", apple: true)
            let result = try fixture.read()
            #expect(result.fingerprint.windows.first(where: { $0.id == 40 })?.kind == .authorization)
            #expect(result.authorizationNew.isEmpty)
            #expect(throws: ScreenFailure.protection) { try result.requireSelection([40]) }
        }
    }
    @Test func authorizationNeedsActualPostRequestCorrelation() throws {
        var fixture = Fixture(.authorizationExclusion)
        fixture.add(id: 40, pid: 40, bundle: "com.apple.SecurityAgent", apple: true)
        #expect(throws: ScreenRunnerInventoryIssue.authorizationRequester) { try fixture.read() }
        fixture.context.authorizationBefore = []
        fixture.context.authorizationRequesterVerified = true
        fixture.context.authorizationRequestedAt = fixture.context.observedAt.advanced(by: .milliseconds(-1))
        #expect(try fixture.read().authorizationNew == [40])
        fixture.context.authorizationBefore = [40]
        #expect(throws: ScreenRunnerInventoryIssue.authorizationAmbiguous) { try fixture.read() }
        fixture.context.authorizationBefore = []
        fixture.context.authorizationRequestedAt = fixture.context.observedAt.advanced(by: .milliseconds(1))
        #expect(throws: ScreenRunnerInventoryIssue.authorizationRequester) { try fixture.read() }
    }
    @Test func mixedKnownUnknownPromptAndEitherInventoryOnlyUnknownRefuse() {
        for side in 0...2 {
            var fixture = Fixture()
            fixture.add(id: 40, pid: 40, bundle: "com.apple.SecurityAgent", apple: true)
            fixture.add(id: 41, pid: 41, bundle: "unclassified.prompt", apple: true)
            if side == 1 { fixture.cg.removeAll { $0.id == 41 } }
            if side == 2 { fixture.sck.removeAll { $0.id == 41 } }
            #expect(throws: ScreenRunnerInventoryIssue.unclassifiedOwner) { try fixture.read() }
        }
    }
    @Test func completenessAndAmbiguityRunAtActualBoundary() {
        for pid in [pid_t(10), 11, 20, 40] {
            var fixture = Fixture()
            fixture.add(id: 40, pid: 40, bundle: "com.apple.SecurityAgent", apple: true)
            fixture.sck.removeAll { $0.pid == pid }
            #expect(throws: ScreenRunnerInventoryIssue.completeness) { try fixture.read() }
        }
        var duplicate = Fixture()
        let window = duplicate.cg.first { $0.pid == 20 }!
        duplicate.cg.append(.init(id: 99, pid: 20, rect: window.rect, layer: window.layer))
        duplicate.sck.append(.init(id: 99, pid: 20, bundle: "com.google.Chrome", rect: window.rect, layer: window.layer))
        #expect(throws: ScreenRunnerInventoryIssue.windowIdentity) { try duplicate.read() }
    }
    @Test func everyExclusionRelevantFingerprintFieldChangesIdentity() throws {
        let base = Fixture(), frozen = try base.read().fingerprint
        for field in ["id", "pid", "bundle", "bounds", "layer", "source", "hash", "incarnation"] {
            var changed = base
            let id: UInt32 = field == "id" ? 31 : 30, pid: pid_t = field == "pid" ? 31 : 30
            let bundle = field == "bundle" ? "com.apple.finder" : "com.apple.dock"
            let rect = field == "bounds" ? CGRect(x: 1, y: 700, width: 800, height: 60) : CGRect(x: 0, y: 700, width: 800, height: 60)
            let layer = field == "layer" ? 1 : 0
            changed.cg.removeAll { $0.id == 30 }; changed.sck.removeAll { $0.id == 30 }; changed.owners.removeValue(forKey: 30)
            changed.cg.append(.init(id: id, pid: pid, rect: rect, layer: layer))
            if field != "source" { changed.sck.append(.init(id: id, pid: pid, bundle: bundle, rect: rect, layer: layer)) }
            changed.owners[pid] = Fixture.owner(pid, bundle: bundle, apple: true, hash: field == "hash" ? 2 : 1, seconds: field == "incarnation" ? 124 : 123)
            let result = try changed.read()
            #expect(result.fingerprint != frozen)
            #expect(throws: ScreenFailure.protection) { try result.requireSelection([id]) }
        }
    }
    @Test func ownerAndAPIPresenceFieldsCannotDisappearFromFingerprint() throws {
        let baseline = Fixture(), fingerprint = try baseline.read().fingerprint
        for field in ["parent", "uid", "microseconds", "path", "sysctlBound", "inCG", "inSCK", "kind"] {
            var changed = baseline
            let owner = changed.owners[30]!
            changed.owners[30] = .init(pid: owner.pid, parent: field == "parent" ? 2 : owner.parent,
                uid: field == "uid" ? 502 : owner.uid, seconds: owner.seconds,
                microseconds: field == "microseconds" ? 43 : owner.microseconds,
                identifier: field == "kind" ? "com.apple.SecurityAgent" : owner.identifier,
                path: field == "path" ? "/fixed/replaced" : owner.path, hash: owner.hash,
                appleAnchored: owner.appleAnchored, verified: owner.verified,
                sysctlBound: field == "sysctlBound" ? true : owner.sysctlBound)
            if field == "inCG" { changed.cg.removeAll { $0.id == 30 } }
            if field == "inSCK" { changed.sck.removeAll { $0.id == 30 } }
            if field == "kind" {
                let window = changed.sck.first { $0.id == 30 }!
                changed.sck.removeAll { $0.id == 30 }
                changed.sck.append(.init(id: window.id, pid: window.pid, bundle: "com.apple.SecurityAgent", rect: window.rect, layer: window.layer))
            }
            #expect(try changed.read().fingerprint != fingerprint)
        }
        #expect(try baseline.read(display: 2).fingerprint != fingerprint)
        #expect(try baseline.read(rect: CGRect(x: 0, y: 0, width: 1200, height: 800)).fingerprint != fingerprint)
        for field in ["verified", "appleAnchored"] {
            var changed = baseline
            let owner = changed.owners[30]!
            changed.owners[30] = .init(pid: owner.pid, parent: owner.parent, uid: owner.uid,
                seconds: owner.seconds, microseconds: owner.microseconds, identifier: owner.identifier,
                path: owner.path, hash: owner.hash, appleAnchored: field != "appleAnchored", verified: field != "verified", sysctlBound: false)
            #expect(throws: (any Error).self) { try changed.read() }
        }
    }
    @Test func systemRecognitionNeverSelectsAndRequiresAppleBinding() throws {
        for identifier in B.systemRoles {
            var fixture = Fixture()
            fixture.add(id: 50, pid: 50, bundle: identifier, apple: true)
            let accepted = try fixture.read()
            #expect(throws: ScreenFailure.protection) { try accepted.requireSelection([50]) }
            fixture.owners[50] = Fixture.owner(50, bundle: identifier, apple: false)
            #expect(throws: ScreenRunnerInventoryIssue.unclassifiedOwner) { try fixture.read() }
        }
    }
    @Test func authorizationAnchorAndWindowServerBracketAreMandatoryAtReadBoundary() throws {
        for (identifier, apple, bracket) in [("com.apple.SecurityAgent", false, false), ("com.apple.WindowServer", true, false)] {
            var fixture = Fixture()
            fixture.add(id: 50, pid: 50, bundle: identifier, apple: apple)
            let owner = fixture.owners[50]!
            fixture.owners[50] = .init(pid: owner.pid, parent: owner.parent, uid: owner.uid, seconds: owner.seconds, microseconds: owner.microseconds,
                identifier: owner.identifier, path: owner.path, hash: owner.hash, appleAnchored: apple, verified: true, sysctlBound: bracket)
            #expect(throws: (any Error).self) { try fixture.read() }
            fixture.owners[50] = Fixture.owner(50, bundle: identifier, apple: true)
            let accepted = try fixture.read()
            #expect(throws: ScreenFailure.protection) { try accepted.requireSelection([50]) }
        }
    }
    @Test func reassignedWindowPIDsChangeFingerprintWithoutChangingOwnerSet() throws {
        var fixture = Fixture()
        fixture.add(id: 31, pid: 31, bundle: "com.apple.dock", rect: CGRect(x: 800, y: 700, width: 100, height: 60), apple: true)
        let original = try fixture.read().fingerprint
        fixture.cg = fixture.cg.map { value in
            .init(id: value.id, pid: value.pid == 30 ? 31 : value.pid == 31 ? 30 : value.pid, rect: value.rect, layer: value.layer)
        }
        fixture.sck = fixture.sck.map { value in
            .init(id: value.id, pid: value.pid == 30 ? 31 : value.pid == 31 ? 30 : value.pid, bundle: value.bundle, rect: value.rect, layer: value.layer)
        }
        let reassigned = try fixture.read().fingerprint
        #expect(reassigned.owners == original.owners)
        #expect(reassigned != original)
    }
    @Test func acceptedFingerprintRecordsCompareEachStoredFieldIndependently() throws {
        let fingerprint = try Fixture().read().fingerprint
        let window = try #require(fingerprint.windows.first { $0.pid == 30 })
        for field in ["pid", "bundle", "kind"] {
            let changed = B.Window(id: window.id, pid: field == "pid" ? 31 : window.pid,
                bundle: field == "bundle" ? "com.apple.finder" : window.bundle, rect: window.rect, layer: window.layer,
                kind: field == "kind" ? .authorization : window.kind, inCG: window.inCG, inSCK: window.inSCK)
            let other = B.Fingerprint(display: fingerprint.display, rect: fingerprint.rect,
                windows: fingerprint.windows.map { $0.id == window.id ? changed : $0 }, owners: fingerprint.owners)
            #expect(other != fingerprint)
        }
        let owner = try #require(fingerprint.owners.first { $0.pid == 30 })
        for field in ["pid", "identifier", "appleAnchored", "verified"] {
            let changed = B.Identity(pid: field == "pid" ? 31 : owner.pid, parent: owner.parent, uid: owner.uid,
                seconds: owner.seconds, microseconds: owner.microseconds,
                identifier: field == "identifier" ? "com.apple.finder" : owner.identifier, path: owner.path, hash: owner.hash,
                appleAnchored: field == "appleAnchored" ? false : owner.appleAnchored,
                verified: field == "verified" ? false : owner.verified, sysctlBound: owner.sysctlBound)
            let other = B.Fingerprint(display: fingerprint.display, rect: fingerprint.rect,
                windows: fingerprint.windows, owners: fingerprint.owners.map { $0.pid == owner.pid ? changed : $0 })
            #expect(other != fingerprint)
        }
    }
    @Test func derivedFingerprintFieldsRemainBoundToActualValidatedOwners() throws {
        var fixture = Fixture()
        fixture.add(id: 40, pid: 40, bundle: "com.apple.SecurityAgent", apple: true)
        let result = try fixture.read()
        for window in result.fingerprint.windows {
            let owner = try #require(result.fingerprint.owners.first { $0.pid == window.pid })
            #expect(window.bundle == owner.identifier && owner.verified)
            let expected: B.Kind
            if owner.pid == fixture.context.surface { expected = .allowed }
            else if owner.pid == fixture.context.app { expected = .app }
            else if let layout = fixture.context.browsers.first(where: { $0.value == owner.pid })?.key {
                expected = try #require(B.Kind(rawValue: "chrome-" + layout.profile))
            } else if owner.identifier == "com.apple.SecurityAgent" { expected = .authorization; #expect(owner.appleAnchored) }
            else { expected = .system; #expect(owner.appleAnchored && B.systemRoles.contains(owner.identifier)) }
            #expect(window.kind == expected)
        }
        for field in ["pid", "bundle", "verified"] {
            var changed = fixture
            let owner = changed.owners[30]!
            if field == "bundle" {
                changed.sck = changed.sck.map { .init(id: $0.id, pid: $0.pid, bundle: $0.pid == 30 ? "com.apple.finder" : $0.bundle, rect: $0.rect, layer: $0.layer) }
            } else {
                changed.owners[30] = .init(pid: field == "pid" ? 31 : owner.pid, parent: owner.parent, uid: owner.uid,
                    seconds: owner.seconds, microseconds: owner.microseconds, identifier: owner.identifier,
                    path: owner.path, hash: owner.hash, appleAnchored: owner.appleAnchored,
                    verified: field != "verified", sysctlBound: owner.sysctlBound)
            }
            #expect(throws: (any Error).self) { try changed.read() }
        }
    }

}
#endif
