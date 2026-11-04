import CryptoKit
import Foundation
import Security

public struct OpenAIJWKS: Decodable, Sendable {
    public let keys: [OpenAIJWK]

    public init(data: Data) throws {
        guard data.count <= 262_144 else { throw NativeAuthError.invalidToken("JWKS size") }
        do { self = try JSONDecoder().decode(Self.self, from: data) }
        catch { throw NativeAuthError.invalidToken("JWKS JSON") }
        guard (1...32).contains(keys.count), Set(keys.map(\.kid)).count == keys.count,
              keys.allSatisfy({ (1...256).contains($0.kid.utf8.count)
                  && (342...1_366).contains($0.n.utf8.count)
                  && (4...16).contains($0.e.utf8.count) }) else {
            throw NativeAuthError.invalidToken("JWKS key set")
        }
    }
}

public struct OpenAIJWK: Decodable, Sendable {
    public let kty: String
    public let kid: String
    public let use: String
    public let alg: String
    public let n: String
    public let e: String
}

public struct OpenAITokenResponse: Sendable {
    let accessToken: String
    let refreshToken: String
    let idToken: String
    public let tokenType: String
    public let expiresIn: Int
    public let scopes: Set<String>
    public let earliestRefreshAt: Int

    public init(data: Data) throws {
        guard data.count <= 131_072,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NativeAuthError.invalidTokenResponse("JSON")
        }
        let expected = Set([
            "access_token", "refresh_token", "id_token", "token_type", "expires_in",
            "scope", "earliest_refresh_at",
        ])
        guard Set(object.keys) == expected,
              let access = object["access_token"] as? String,
              let refresh = object["refresh_token"] as? String,
              let id = object["id_token"] as? String,
              let type = object["token_type"] as? String,
              let expires = integer(object["expires_in"]),
              let scope = object["scope"] as? String,
              let earliest = integer(object["earliest_refresh_at"]),
              (16...65_536).contains(access.utf8.count),
              (16...16_384).contains(refresh.utf8.count),
              (16...65_536).contains(id.utf8.count), type == "Bearer", expires == 3600,
              earliest >= 0 else {
            throw NativeAuthError.invalidTokenResponse("fields")
        }
        let granted = Set(scope.split(separator: " ").map(String.init))
        guard granted.count == scope.split(separator: " ").count,
              granted == Set(OpenAISignInPolicy.requiredScopes) else {
            throw NativeAuthError.invalidTokenResponse("scopes")
        }
        accessToken = access
        refreshToken = refresh
        idToken = id
        tokenType = type
        expiresIn = expires
        scopes = granted
        earliestRefreshAt = earliest
    }
}

public struct ValidatedOpenAITokenSet: Sendable {
    let accessToken: String
    let refreshToken: String
    let idToken: String
    public let clientID: String
    let subject: String
    public let accountSubjectSHA256: String
    public let workspaceSHA256: String
    public let scopes: Set<String>
    public let accessExpiresAt: Date
    public let earliestRefreshAt: Date
    public let refreshExpiresAt: Date
    public let savedAt: Date

    public var contentFreeStatus: OpenAITokenStatus {
        OpenAITokenStatus(
            clientIDHash: Self.sha256(clientID),
            accountSubjectSHA256: accountSubjectSHA256,
            workspaceSHA256: workspaceSHA256,
            accessExpiresAt: accessExpiresAt,
            earliestRefreshAt: earliestRefreshAt,
            refreshExpiresAt: refreshExpiresAt,
            scopeSHA256: Self.sha256(scopes.sorted().joined(separator: " "))
        )
    }

    static func sha256(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}

public struct OpenAITokenStatus: Equatable, Sendable {
    public let clientIDHash: String
    public let accountSubjectSHA256: String
    public let workspaceSHA256: String
    public let accessExpiresAt: Date
    public let earliestRefreshAt: Date
    public let refreshExpiresAt: Date
    public let scopeSHA256: String
}

public enum OpenAITokenVerifier {
    public static func validate(
        response: OpenAITokenResponse,
        exchange: OpenAICodeExchange,
        jwks: OpenAIJWKS,
        now: Date = Date()
    ) throws -> ValidatedOpenAITokenSet {
        try validate(
            response: response,
            clientID: exchange.clientID,
            expectedNonce: exchange.nonce,
            expectedSubjectSHA256: exchange.expectedSubjectSHA256,
            jwks: jwks,
            now: now
        )
    }

    public static func validateRefresh(
        response: OpenAITokenResponse,
        exchange: OpenAIRefreshExchange,
        jwks: OpenAIJWKS,
        now: Date = Date()
    ) throws -> ValidatedOpenAITokenSet {
        try validate(
            response: response,
            clientID: exchange.clientID,
            expectedNonce: nil,
            expectedSubjectSHA256: exchange.expectedSubjectSHA256,
            jwks: jwks,
            now: now
        )
    }

    private static func validate(
        response: OpenAITokenResponse,
        clientID: String,
        expectedNonce: String?,
        expectedSubjectSHA256: String?,
        jwks: OpenAIJWKS,
        now: Date
    ) throws -> ValidatedOpenAITokenSet {
        try OpenAISignInPolicy.validateIssuedClientID(clientID)
        let idClaims = try verifyJWT(
            response.idToken, jwks: jwks, expectedAudience: clientID,
            expectedNonce: expectedNonce, expectedClientID: nil, expectedSubject: nil, now: now
        )
        let subject = try requiredString(idClaims, "sub", maximum: 1024)
        let accountDigest = ValidatedOpenAITokenSet.sha256(subject)
        if let expectedSubjectSHA256,
           !constantTimeEqual(expectedSubjectSHA256, accountDigest) {
            throw NativeAuthError.invalidToken("account changed")
        }
        let accessClaims = try verifyJWT(
            response.accessToken, jwks: jwks, expectedAudience: OpenAISignInPolicy.resource,
            expectedNonce: nil, expectedClientID: clientID, expectedSubject: subject, now: now
        )
        let accessScopes = try scopeSet(accessClaims["scope"])
        guard accessScopes == Set(OpenAISignInPolicy.requiredScopes),
              accessScopes == response.scopes else {
            throw NativeAuthError.invalidToken("access scopes")
        }
        let accessExpiration = try requiredInteger(accessClaims, "exp")
        let accessIssuedAt = try requiredInteger(accessClaims, "iat")
        let expiresAt = Date(timeIntervalSince1970: TimeInterval(accessExpiration))
        guard accessExpiration - accessIssuedAt == response.expiresIn,
              abs(now.timeIntervalSince1970 - TimeInterval(accessIssuedAt)) <= 300,
              expiresAt > now.addingTimeInterval(-30),
              expiresAt <= now.addingTimeInterval(TimeInterval(response.expiresIn) + 300) else {
            throw NativeAuthError.invalidToken("access lifetime")
        }
        let earliest = Date(timeIntervalSince1970: TimeInterval(response.earliestRefreshAt))
        guard earliest >= now.addingTimeInterval(-120), earliest < expiresAt else {
            throw NativeAuthError.invalidToken("refresh timing")
        }
        return ValidatedOpenAITokenSet(
            accessToken: response.accessToken, refreshToken: response.refreshToken,
            idToken: response.idToken, clientID: clientID, subject: subject,
            accountSubjectSHA256: accountDigest,
            workspaceSHA256: ValidatedOpenAITokenSet.sha256(clientID),
            scopes: response.scopes, accessExpiresAt: expiresAt,
            earliestRefreshAt: earliest,
            refreshExpiresAt: now.addingTimeInterval(30 * 24 * 60 * 60),
            savedAt: now
        )
    }

    static func verifyJWT(
        _ token: String,
        jwks: OpenAIJWKS,
        expectedAudience: String,
        expectedNonce: String?,
        expectedClientID: String?,
        expectedSubject: String?,
        now: Date
    ) throws -> [String: Any] {
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let headerData = Data(base64URL: String(parts[0])),
              let claimsData = Data(base64URL: String(parts[1])),
              let signature = Data(base64URL: String(parts[2])),
              headerData.count <= 16_384, claimsData.count <= 65_536,
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              Set(header.keys).isSubset(of: ["alg", "kid", "typ"]),
              header["alg"] as? String == "RS256",
              let kid = header["kid"] as? String, (1...256).contains(kid.utf8.count),
              header["typ"] == nil || header["typ"] as? String == "JWT",
              let key = jwks.keys.first(where: { $0.kid == kid }),
              let secKey = try? rsaKey(key) else {
            throw NativeAuthError.invalidToken("JWT header")
        }
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        guard SecKeyVerifySignature(secKey, .rsaSignatureMessagePKCS1v15SHA256,
                                    signingInput as CFData, signature as CFData, nil) else {
            throw NativeAuthError.signatureInvalid
        }
        guard let claims = try? JSONSerialization.jsonObject(with: claimsData) as? [String: Any],
              try requiredString(claims, "iss", maximum: 256) == OpenAISignInPolicy.issuer,
              try audience(claims["aud"], containsOnly: expectedAudience),
              let expiration = try? requiredInteger(claims, "exp"),
              let issuedAt = try? requiredInteger(claims, "iat"),
              expiration > Int(now.timeIntervalSince1970) - 30,
              issuedAt <= Int(now.timeIntervalSince1970) + 30 else {
            throw NativeAuthError.invalidToken("JWT claims")
        }
        if let notBefore = integer(claims["nbf"]), notBefore > Int(now.timeIntervalSince1970) + 30 {
            throw NativeAuthError.invalidToken("not before")
        }
        if let expectedNonce {
            guard let nonce = claims["nonce"] as? String, constantTimeEqual(nonce, expectedNonce) else {
                throw NativeAuthError.invalidToken("nonce")
            }
        }
        if let expectedClientID {
            guard claims["client_id"] as? String == expectedClientID else {
                throw NativeAuthError.invalidToken("client identifier")
            }
        }
        if let expectedSubject {
            guard let subject = claims["sub"] as? String, constantTimeEqual(subject, expectedSubject) else {
                throw NativeAuthError.invalidToken("subject")
            }
        }
        return claims
    }
}

func rsaKey(_ jwk: OpenAIJWK) throws -> SecKey {
    guard jwk.kty == "RSA", jwk.use == "sig", jwk.alg == "RS256",
          let modulus = Data(base64URL: jwk.n), let exponent = Data(base64URL: jwk.e),
          (256...1_024).contains(modulus.count), (3...8).contains(exponent.count) else {
        throw NativeAuthError.invalidToken("JWK")
    }
    let body = derInteger(modulus) + derInteger(exponent)
    let encoded = der(0x30, body)
    let attributes: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits: modulus.count * 8,
    ]
    guard let key = SecKeyCreateWithData(encoded as CFData, attributes as CFDictionary, nil) else {
        throw NativeAuthError.invalidToken("JWK key")
    }
    return key
}

func derInteger(_ value: Data) -> Data {
    var bytes = value
    while bytes.count > 1, bytes.first == 0,
          bytes[bytes.index(after: bytes.startIndex)] & 0x80 == 0 {
        bytes.removeFirst()
    }
    if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
    return der(0x02, bytes)
}

func der(_ tag: UInt8, _ body: Data) -> Data {
    var result = Data([tag])
    if body.count < 128 {
        result.append(UInt8(body.count))
    } else {
        var length = body.count
        var octets: [UInt8] = []
        while length > 0 { octets.insert(UInt8(length & 0xff), at: 0); length >>= 8 }
        result.append(0x80 | UInt8(octets.count))
        result.append(contentsOf: octets)
    }
    result.append(body)
    return result
}

func integer(_ value: Any?) -> Int? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) != CFBooleanGetTypeID(),
          number.doubleValue.isFinite,
          number.doubleValue >= Double(Int.min),
          number.doubleValue <= Double(Int.max),
          number.doubleValue.rounded() == number.doubleValue else { return nil }
    return number.intValue
}

func requiredInteger(_ object: [String: Any], _ key: String) throws -> Int {
    guard let value = integer(object[key]), (0...253_402_300_799).contains(value) else {
        throw NativeAuthError.invalidToken("integer claim")
    }
    return value
}

func requiredString(_ object: [String: Any], _ key: String, maximum: Int) throws -> String {
    guard let value = object[key] as? String, !value.isEmpty, value.utf8.count <= maximum,
          value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
        throw NativeAuthError.invalidToken("string claim")
    }
    return value
}

func audience(_ value: Any?, containsOnly expected: String) throws -> Bool {
    if let string = value as? String { return string == expected }
    if let values = value as? [String] { return values.count == 1 && values[0] == expected }
    throw NativeAuthError.invalidToken("audience")
}

func scopeSet(_ value: Any?) throws -> Set<String> {
    guard let string = value as? String else { throw NativeAuthError.invalidToken("scope") }
    let parts = string.split(separator: " ").map(String.init)
    let result = Set(parts)
    guard result.count == parts.count else { throw NativeAuthError.invalidToken("scope") }
    return result
}
