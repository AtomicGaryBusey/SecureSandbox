import CryptoKit
import Foundation

public enum NativeHostIdentity {
    public static func p256JWKThumbprintURI(x963PublicKey: Data) throws -> String {
        guard x963PublicKey.count == 65, x963PublicKey.first == 0x04 else {
            throw NativeAuthError.invalidPolicy("P-256 public key")
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: x963PublicKey)
        } catch {
            throw NativeAuthError.invalidPolicy("P-256 public key")
        }
        let x = x963PublicKey[1..<33].base64URLEncodedString()
        let y = x963PublicKey[33..<65].base64URLEncodedString()
        let canonical = #"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#
        let digest = Data(SHA256.hash(data: Data(canonical.utf8))).base64URLEncodedString()
        return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:\(digest)"
    }
}
