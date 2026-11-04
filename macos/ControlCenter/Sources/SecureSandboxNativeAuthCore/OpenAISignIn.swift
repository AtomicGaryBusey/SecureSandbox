import CryptoKit
import Foundation
import Security

public enum NativeAuthError: Error, Equatable, LocalizedError {
    case invalidPolicy(String)
    case invalidAttempt(String)
    case invalidCallback(String)
    case authorizationDenied
    case authorizationFailed
    case invalidTokenResponse(String)
    case invalidToken(String)
    case signatureInvalid
    case randomFailure

    public var errorDescription: String? {
        switch self {
        case .invalidPolicy(let reason): "Native authentication policy is invalid: \(reason)."
        case .invalidAttempt(let reason): "The sign-in attempt is invalid: \(reason)."
        case .invalidCallback(let reason): "The sign-in callback is invalid: \(reason)."
        case .authorizationDenied: "The operator declined authorization."
        case .authorizationFailed: "The provider did not authorize this sign-in attempt."
        case .invalidTokenResponse(let reason): "The provider token response is invalid: \(reason)."
        case .invalidToken(let reason): "The provider token is invalid: \(reason)."
        case .signatureInvalid: "The provider token signature is invalid."
        case .randomFailure: "Secure random generation failed."
        }
    }
}

public enum OpenAISignInPolicy {
    public static let issuer = "https://auth.openai.com"
    public static let authorizationEndpoint = URL(string: "https://auth.openai.com/api/accounts/authorize")!
    public static let tokenEndpoint = URL(string: "https://auth.openai.com/api/accounts/oauth/token")!
    public static let revocationEndpoint = URL(string: "https://auth.openai.com/api/accounts/oauth/revoke")!
    public static let jwksEndpoint = URL(string: "https://auth.openai.com/.well-known/jwks.json")!
    public static let resource = "https://api.openai.com/v1"
    public static let dynamicClientID = "dynamic_agent_client"
    public static let agentName = "SecureSandbox"
    public static let callbackPath = "/auth/callback"
    public static let requiredScopes = [
        "openid", "profile", "email", "offline_access", "resource.invoke",
        "chatgpt.tokens.use.direct",
    ]
    public static let attemptLifetime: TimeInterval = 300

    public static func validateHostID(_ value: String) throws {
        let thumbprintPrefix = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"
        let uuidPrefix = "urn:uuid:"
        guard value.utf8.count <= 512 else { throw NativeAuthError.invalidPolicy("host identifier length") }
        if value.hasPrefix(thumbprintPrefix) {
            let digest = String(value.dropFirst(thumbprintPrefix.count))
            guard digest.range(of: #"^[A-Za-z0-9_-]{43}$"#, options: .regularExpression) != nil else {
                throw NativeAuthError.invalidPolicy("host identifier thumbprint")
            }
            return
        }
        if value.hasPrefix(uuidPrefix), UUID(uuidString: String(value.dropFirst(uuidPrefix.count))) != nil {
            return
        }
        throw NativeAuthError.invalidPolicy("host identifier format")
    }

    public static func validateIssuedClientID(_ value: String) throws {
        guard value != dynamicClientID,
              value.range(of: #"^[A-Za-z0-9._-]{8,256}$"#, options: .regularExpression) != nil else {
            throw NativeAuthError.invalidToken("issued client identifier")
        }
    }
}

public enum OpenAIRegistration: Equatable, Sendable {
    case new
    case returning(
        clientID: String,
        expectedSubjectSHA256: String,
        retainedIDTokenHint: String?
    )
}

struct OpenAIAuthorizationAttempt: Equatable, Sendable {
    let registration: OpenAIRegistration
    let hostID: String
    let callbackURL: URL
    let state: String
    let nonce: String
    let codeVerifier: String
    let createdAt: Date
    let expiresAt: Date

    init(
        registration: OpenAIRegistration,
        hostID: String,
        callbackURL: URL,
        state: String,
        nonce: String,
        codeVerifier: String,
        createdAt: Date,
        expiresAt: Date
    ) throws {
        self.registration = registration
        self.hostID = hostID
        self.callbackURL = callbackURL
        self.state = state
        self.nonce = nonce
        self.codeVerifier = codeVerifier
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        try validate()
    }

    static func begin(
        registration: OpenAIRegistration,
        hostID: String,
        callbackPort: UInt16,
        now: Date = Date()
    ) throws -> Self {
        guard callbackPort > 0,
              let callback = URL(string: "http://127.0.0.1:\(callbackPort)\(OpenAISignInPolicy.callbackPath)") else {
            throw NativeAuthError.invalidAttempt("callback port")
        }
        return try Self(
            registration: registration,
            hostID: hostID,
            callbackURL: callback,
            state: secureRandomURLSafe(bytes: 32),
            nonce: secureRandomURLSafe(bytes: 32),
            codeVerifier: secureRandomURLSafe(bytes: 64),
            createdAt: now,
            expiresAt: now.addingTimeInterval(OpenAISignInPolicy.attemptLifetime)
        )
    }

    func authorizationURL(now: Date = Date()) throws -> URL {
        try validate(now: now)
        var components = URLComponents(url: OpenAISignInPolicy.authorizationEndpoint,
                                       resolvingAgainstBaseURL: false)!
        let clientID: String
        var items: [URLQueryItem] = []
        switch registration {
        case .new:
            clientID = OpenAISignInPolicy.dynamicClientID
            items.append(URLQueryItem(name: "agent_name_hint", value: OpenAISignInPolicy.agentName))
        case .returning(let issued, _, let retainedIDTokenHint):
            try OpenAISignInPolicy.validateIssuedClientID(issued)
            clientID = issued
            if let retainedIDTokenHint {
                items.append(URLQueryItem(name: "id_token_hint", value: retainedIDTokenHint))
            }
        }
        items.append(contentsOf: [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "ext_agent_host_id", value: hostID),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: callbackURL.absoluteString),
            URLQueryItem(name: "scope", value: OpenAISignInPolicy.requiredScopes.joined(separator: " ")),
            URLQueryItem(name: "resource", value: OpenAISignInPolicy.resource),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "code_challenge", value: pkceChallenge),
        ])
        components.queryItems = items
        guard let url = components.url else { throw NativeAuthError.invalidAttempt("authorization URL") }
        return url
    }

    var pkceChallenge: String {
        Data(SHA256.hash(data: Data(codeVerifier.utf8))).base64URLEncodedString()
    }

    func consumeCallback(_ url: URL, now: Date = Date()) throws -> OpenAICodeExchange {
        try validate(now: now)
        guard var expected = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let actual = URLComponents(url: url, resolvingAgainstBaseURL: false),
              actual.scheme == expected.scheme, actual.host == expected.host,
              actual.port == expected.port, actual.path == expected.path,
              actual.user == nil, actual.password == nil, actual.fragment == nil else {
            throw NativeAuthError.invalidCallback("origin or path")
        }
        expected.query = nil
        let allowed = Set(["code", "state", "scope", "client_id", "error"])
        var values: [String: String] = [:]
        for item in actual.queryItems ?? [] {
            guard allowed.contains(item.name), values[item.name] == nil, let value = item.value else {
                throw NativeAuthError.invalidCallback("query shape")
            }
            values[item.name] = value
        }
        guard let returnedState = values["state"], constantTimeEqual(returnedState, state) else {
            throw NativeAuthError.invalidCallback("state")
        }
        if let error = values["error"] {
            guard values["code"] == nil else { throw NativeAuthError.invalidCallback("mixed result") }
            if error == "access_denied" { throw NativeAuthError.authorizationDenied }
            throw NativeAuthError.authorizationFailed
        }
        guard let code = values["code"], (8...8192).contains(code.utf8.count),
              code.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw NativeAuthError.invalidCallback("authorization code")
        }
        let clientID: String
        switch registration {
        case .new:
            guard let issued = values["client_id"] else {
                throw NativeAuthError.invalidCallback("missing issued client identifier")
            }
            try OpenAISignInPolicy.validateIssuedClientID(issued)
            clientID = issued
        case .returning(let expectedClientID, _, _):
            try OpenAISignInPolicy.validateIssuedClientID(expectedClientID)
            guard values["client_id"] == nil || values["client_id"] == expectedClientID else {
                throw NativeAuthError.invalidCallback("changed client identifier")
            }
            clientID = expectedClientID
        }
        return OpenAICodeExchange(
            code: code, clientID: clientID, codeVerifier: codeVerifier,
            redirectURI: callbackURL.absoluteString, resource: OpenAISignInPolicy.resource,
            nonce: nonce,
            expectedSubjectSHA256: {
                if case .returning(_, let digest, _) = registration { return digest }
                return nil
            }()
        )
    }

    func validate(now: Date? = nil) throws {
        try OpenAISignInPolicy.validateHostID(hostID)
        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              components.scheme == "http", components.host == "127.0.0.1",
              components.path == OpenAISignInPolicy.callbackPath,
              components.port.map({ $0 > 0 }) == true,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil else {
            throw NativeAuthError.invalidAttempt("callback")
        }
        for (label, value, range) in [
            ("state", state, 43...128), ("nonce", nonce, 43...128),
            ("PKCE verifier", codeVerifier, 43...128),
        ] {
            guard range.contains(value.utf8.count),
                  value.range(of: #"^[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil else {
                throw NativeAuthError.invalidAttempt(label)
            }
        }
        guard expiresAt > createdAt,
              expiresAt.timeIntervalSince(createdAt) == OpenAISignInPolicy.attemptLifetime else {
            throw NativeAuthError.invalidAttempt("lifetime")
        }
        if let now, now < createdAt.addingTimeInterval(-30) || now >= expiresAt {
            throw NativeAuthError.invalidAttempt("expired")
        }
        if case .returning(let clientID, let subjectDigest, let retainedIDTokenHint) = registration {
            try OpenAISignInPolicy.validateIssuedClientID(clientID)
            guard subjectDigest.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil else {
                throw NativeAuthError.invalidAttempt("account binding")
            }
            if let retainedIDTokenHint {
                let parts = retainedIDTokenHint.split(separator: ".", omittingEmptySubsequences: false)
                guard (64...65_536).contains(retainedIDTokenHint.utf8.count), parts.count == 3,
                      parts.allSatisfy({ !$0.isEmpty && Data(base64URL: String($0)) != nil }) else {
                    throw NativeAuthError.invalidAttempt("ID token hint")
                }
            }
        }
    }
}

public actor OpenAIAuthorizationSession {
    private var attempt: OpenAIAuthorizationAttempt?

    private init(attempt: OpenAIAuthorizationAttempt) {
        self.attempt = attempt
    }

    public static func begin(
        registration: OpenAIRegistration,
        hostID: String,
        callbackPort: UInt16,
        now: Date = Date()
    ) throws -> OpenAIAuthorizationSession {
        OpenAIAuthorizationSession(attempt: try .begin(
            registration: registration, hostID: hostID, callbackPort: callbackPort, now: now
        ))
    }

    public func authorizationURL(now: Date = Date()) throws -> URL {
        guard let attempt else { throw NativeAuthError.invalidAttempt("already consumed") }
        return try attempt.authorizationURL(now: now)
    }

    public func consumeCallback(_ url: URL, now: Date = Date()) throws -> OpenAICodeExchange {
        guard let current = attempt else { throw NativeAuthError.invalidAttempt("already consumed") }
        attempt = nil
        return try current.consumeCallback(url, now: now)
    }
}

public struct OpenAICodeExchange: Sendable {
    let code: String
    public let clientID: String
    let codeVerifier: String
    public let redirectURI: String
    public let resource: String
    let nonce: String
    let expectedSubjectSHA256: String?

    public var formBody: Data {
        formEncode([
            ("grant_type", "authorization_code"), ("client_id", clientID),
            ("code", code), ("code_verifier", codeVerifier),
            ("redirect_uri", redirectURI), ("resource", resource),
        ])
    }
}

public struct OpenAIRefreshExchange: Sendable {
    public let clientID: String
    let refreshToken: String
    let expectedSubjectSHA256: String

    public init(
        clientID: String,
        refreshToken: String,
        expectedSubjectSHA256: String
    ) throws {
        try OpenAISignInPolicy.validateIssuedClientID(clientID)
        guard (16...16_384).contains(refreshToken.utf8.count),
              expectedSubjectSHA256.range(
                  of: #"^[0-9a-f]{64}$"#, options: .regularExpression
              ) != nil else {
            throw NativeAuthError.invalidToken("refresh token")
        }
        self.clientID = clientID
        self.refreshToken = refreshToken
        self.expectedSubjectSHA256 = expectedSubjectSHA256
    }

    public var formBody: Data {
        formEncode([
            ("grant_type", "refresh_token"), ("client_id", clientID),
            ("refresh_token", refreshToken), ("resource", OpenAISignInPolicy.resource),
        ])
    }
}

public struct OpenAIRevocationRequest: Sendable {
    public let clientID: String
    let refreshToken: String

    public init(clientID: String, refreshToken: String) throws {
        try OpenAISignInPolicy.validateIssuedClientID(clientID)
        guard (16...16_384).contains(refreshToken.utf8.count) else {
            throw NativeAuthError.invalidToken("refresh token")
        }
        self.clientID = clientID
        self.refreshToken = refreshToken
    }

    public var formBody: Data {
        formEncode([
            ("token", refreshToken), ("token_type_hint", "refresh_token"),
            ("client_id", clientID),
        ])
    }
}

func secureRandomURLSafe(bytes: Int) throws -> String {
    var value = Data(count: bytes)
    let status = value.withUnsafeMutableBytes { buffer in
        SecRandomCopyBytes(kSecRandomDefault, bytes, buffer.baseAddress!)
    }
    guard status == errSecSuccess else { throw NativeAuthError.randomFailure }
    return value.base64URLEncodedString()
}

func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
    let a = Array(lhs.utf8), b = Array(rhs.utf8)
    guard a.count == b.count else { return false }
    var difference: UInt8 = 0
    for index in a.indices { difference |= a[index] ^ b[index] }
    return difference == 0
}

func formEncode(_ fields: [(String, String)]) -> Data {
    let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    let text = fields.map { name, value in
        let encodedName = name.addingPercentEncoding(withAllowedCharacters: allowed)!
        let encodedValue = value.addingPercentEncoding(withAllowedCharacters: allowed)!
        return "\(encodedName)=\(encodedValue)"
    }.joined(separator: "&")
    return Data(text.utf8)
}

extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URL: String) {
        guard base64URL.range(of: #"^[A-Za-z0-9_-]*$"#, options: .regularExpression) != nil else {
            return nil
        }
        var value = base64URL.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = value.count % 4
        if remainder != 0 { value.append(String(repeating: "=", count: 4 - remainder)) }
        guard let decoded = Data(base64Encoded: value),
              decoded.base64URLEncodedString() == base64URL else { return nil }
        self = decoded
    }
}
