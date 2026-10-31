import CryptoKit
import Foundation
import SecureSandboxUpdateCore

private enum SignerFailure: Error, LocalizedError {
    case usage
    case configuration(String)

    var errorDescription: String? {
        switch self {
        case .usage:
            "usage: SecureSandboxUpdateSigner public-key | sign MANIFEST_JSON ENVELOPE_JSON KEY_ID"
        case .configuration(let reason): reason
        }
    }
}

@main
struct SecureSandboxUpdateSigner {
    static func main() {
        do { try run() }
        catch {
            FileHandle.standardError.write(Data("Update signer: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }

    private static func run() throws {
        let arguments = CommandLine.arguments
        let privateKey = try loadPrivateKey()
        if arguments.count == 2, arguments[1] == "public-key" {
            print(privateKey.publicKey.rawRepresentation.base64EncodedString())
            return
        }
        guard arguments.count == 5, arguments[1] == "sign" else { throw SignerFailure.usage }
        let input = URL(fileURLWithPath: arguments[2]).standardizedFileURL
        let output = URL(fileURLWithPath: arguments[3]).standardizedFileURL
        let keyID = arguments[4]
        guard keyID.range(of: #"^[A-Za-z0-9._-]{1,64}$"#, options: .regularExpression) != nil else {
            throw SignerFailure.configuration("invalid key ID")
        }
        let payload = try Data(contentsOf: input, options: .mappedIfSafe)
        guard payload.count <= 131_072 else { throw SignerFailure.configuration("manifest exceeds 128 KiB") }
        _ = try JSONDecoder().decode(UpdateManifest.self, from: payload)
        let envelope = SignedUpdateEnvelope(
            schema: SignedUpdateEnvelope.schema,
            keyID: keyID,
            payloadBase64: payload.base64EncodedString(),
            signatureBase64: try privateKey.signature(for: payload).base64EncodedString()
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        try encoder.encode(envelope).write(to: output, options: [.atomic])
    }

    private static func loadPrivateKey() throws -> Curve25519.Signing.PrivateKey {
        guard let encoded = ProcessInfo.processInfo.environment["SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64"],
              let data = Data(base64Encoded: encoded), data.count == 32 else {
            throw SignerFailure.configuration(
                "SECURE_SANDBOX_UPDATE_SIGNING_KEY_BASE64 must be supplied through op-agents run"
            )
        }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: data)
    }
}
