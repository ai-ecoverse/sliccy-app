import CryptoKit
import Foundation

// Verify against the public key shipped in the app, not the signing key's own pair.
let args = CommandLine.arguments
guard args.count == 4, let publicBytes = Data(base64Encoded: args[1]),
      let signature = Data(base64Encoded: args[2]) else { fatalError("Invalid verification arguments") }
let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicBytes)
let archive = try Data(contentsOf: URL(fileURLWithPath: args[3]), options: .mappedIfSafe)
guard key.isValidSignature(signature, for: archive) else { fatalError("Update signature does not match the bundled public key") }
print("Update archive Ed25519 signature verified against release public key.")
