import Foundation
import Darwin

enum ScreenFailure: Error { case peerUntrusted, incompatible, resourceLimit, stalled }
enum ScreenRunnerCase: String { case selectedWindow = "selected-window" }

@main struct SurfaceFixture {
 static func main() throws {
  let journal=try ScreenRunnerJournal(.selectedWindow,authorityFailed:{exit(2)})
  func attempt()->ScreenRunnerSurfaceDiagnostics {
   ScreenRunnerSurfaceDiagnostics(output:{notice in journal.emit("surface-refusal",notice.fields,at:notice.at)})
  }
  for predicate in ScreenRunnerSurfaceDiagnostics.Predicate.allCases {
   let source=attempt();source.reject(predicate,.policy);source.reject(.operation,.launch)
  }
  for operation in ScreenRunnerSurfaceDiagnostics.Operation.allCases {attempt().reject(.operation,operation)}
  for status in [Int32.min,Int32(0),Int32.max] {attempt().reject(.role,.staticValidity,status:status)}
  do {try attempt().verifyHash("wrong",expected:"right");exit(3)} catch ScreenFailure.peerUntrusted {}
  if journal.failed {exit(4)}
 }
}
