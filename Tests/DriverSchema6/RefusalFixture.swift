import Foundation
import CoreGraphics
import Darwin

enum ScreenFailure: Error { case incompatible, resourceLimit, stalled }
enum ScreenRunnerCase: String { case selectedWindow = "selected-window" }
enum ScreenRunnerInventoryIssue: String, Error {
case permission = "permission"
case surfaceIdentity = "surface-identity"
case browserIdentity = "browser-identity"
case shareableContent = "shareable-content"
case displayGeometry = "display-geometry"
case cgInventory = "cg-inventory"
case ownerAttribution = "owner-attribution"
case completeness = "completeness"
case surfaceGeometry = "surface-geometry"
case browserWindowCount = "browser-window-count"
case windowIdentity = "window-identity"
case appWindows = "app-windows"
case authorizationRequester = "authorization-requester"
case authorizationMissing = "authorization-missing"
case authorizationAmbiguous = "authorization-ambiguous"
case authorizationIdentity = "authorization-identity"
case sourceChanged = "source-changed"
case unclassifiedOwner = "unclassified-owner"
case unknown = "unknown"
}

enum ScreenRunnerInventoryBoundary {
 struct CGRecord: Sendable {let id:UInt32,pid:Int32,rect:CGRect,layer:Int}
 struct SCKRecord: Sendable {let id:UInt32,pid:Int32,bundle:String,rect:CGRect,layer:Int}
 struct Identity: Sendable {let pid:Int32,parent:Int32,uid:UInt32,seconds:UInt64,microseconds:UInt64,identifier:String,path:String,hash:Data,appleAnchored:Bool,verified:Bool,sysctlBound:Bool,realUID:UInt32?,savedUID:UInt32?}
}

@main struct RefusalFixture {
 static func main() throws {
  let output = try ScreenRunnerJournal(.selectedWindow,authorityFailed:{exit(2)})
  let rect=CGRect(x:128,y:128,width:256,height:256)
  let owner=ScreenRunnerInventoryBoundary.Identity(pid:42,parent:1,uid:501,seconds:UInt64.max,microseconds:2,identifier:"com.apple.WindowManager",path:"/not-emitted",hash:Data(repeating:1,count:20),appleAnchored:true,verified:true,sysctlBound:false,realUID:501,savedUID:nil)
  let notice=ScreenRunnerInventoryDiagnostics.Notice(attempt:1,site:.initial,issue:.ownerAttribution,branch:.bundlePair,comparison:.bundle,pid:42,windowID:7,signingIdentifier:"com.apple.WindowManager",cg:[.init(id:7,pid:42,rect:rect,layer:0)],sck:[.init(id:7,pid:42,bundle:"com.apple.Wallpaper",rect:rect,layer:0)],owner:owner,at:.now)
  output.emit("inventory-refusal",notice.fields,at:notice.at)
  let missing=ScreenRunnerInventoryDiagnostics.Notice(attempt:3,site:.refresh,issue:.ownerAttribution,branch:.sckOwner,comparison:.present,pid:nil,windowID:8,signingIdentifier:nil,cg:[],sck:[.init(id:8,pid:nil,bundle:nil,rect:CGRect(x:CGFloat.infinity,y:0,width:0,height:-1),layer:-2147483624)],owner:nil,at:.now)
  output.emit("inventory-refusal",missing.fields,at:missing.at)
  let invalid=ScreenRunnerInventoryDiagnostics.Notice(attempt:4,site:.monitor,issue:.ownerAttribution,branch:.ownerIdentifier,comparison:.identifier,pid:-1,windowID:nil,signingIdentifier:"invalid identifier",cg:[],sck:[],owner:nil,at:.now)
  output.emit("inventory-refusal",invalid.fields,at:invalid.at)
  if output.failed {exit(3)}
 }
}
