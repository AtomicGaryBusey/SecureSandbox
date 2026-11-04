import CryptoKit
import Foundation
import Testing
@testable import SecureSandboxNativeAuthCore

struct NativeAuthCoreTests {
    private let hostID = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + String(repeating: "A", count: 43)
    private let state = String(repeating: "s", count: 43)
    private let nonce = String(repeating: "n", count: 43)
    private let verifier = String(repeating: "v", count: 64)
    private let now = Date(timeIntervalSince1970: 2_000_000_000)

    @Test func firstRegistrationUsesExactOpenAIContract() throws {
        let attempt = try fixture(.new)
        let url = try attempt.authorizationURL(now: now)
        let items = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
        let values = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
        #expect(values["client_id"] == "dynamic_agent_client")
        #expect(values["agent_name_hint"] == "SecureSandbox")
        #expect(values["ext_agent_host_id"] == hostID)
        #expect(values["redirect_uri"] == "http://127.0.0.1:4242/auth/callback")
        #expect(values["resource"] == "https://api.openai.com/v1")
        #expect(values["scope"] == OpenAISignInPolicy.requiredScopes.joined(separator: " "))
        #expect(values["code_challenge_method"] == "S256")
        #expect(values["code_challenge"] == attempt.pkceChallenge)
    }

    @Test func returningRegistrationOmitsAgentHintAndBindsAccount() throws {
        let hint = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0."
            + String(repeating: "A", count: 43)
        let attempt = try fixture(.returning(
            clientID: "oaiapp_fixture",
            expectedSubjectSHA256: String(repeating: "a", count: 64),
            retainedIDTokenHint: hint
        ))
        let items = try #require(URLComponents(url: try attempt.authorizationURL(now: now),
                                              resolvingAgainstBaseURL: false)?.queryItems)
        let names = Set(items.map(\.name))
        #expect(!names.contains("agent_name_hint"))
        #expect(items.first(where: { $0.name == "client_id" })?.value == "oaiapp_fixture")
        #expect(items.first(where: { $0.name == "id_token_hint" })?.value == hint)
    }

    @Test func callbackRejectsOriginMixupDuplicateAndChangedClient() throws {
        let returning = try fixture(.returning(
            clientID: "oaiapp_fixture",
            expectedSubjectSHA256: String(repeating: "a", count: 64),
            retainedIDTokenHint: nil
        ))
        let good = URL(string: "http://127.0.0.1:4242/auth/callback?code=fixture-code&state=\(state)")!
        #expect(try returning.consumeCallback(good, now: now).clientID == "oaiapp_fixture")
        for url in [
            URL(string: "http://localhost:4242/auth/callback?code=fixture-code&state=\(state)")!,
            URL(string: "http://127.0.0.1:4242/callback?code=fixture-code&state=\(state)")!,
            URL(string: "http://127.0.0.1:4242/auth/callback?code=fixture-code&state=wrong")!,
            URL(string: "http://127.0.0.1:4242/auth/callback?code=a&code=b&state=\(state)")!,
            URL(string: "http://127.0.0.1:4242/auth/callback?code=fixture-code&state=\(state)&client_id=oaiapp_other")!,
        ] {
            #expect(throws: (any Error).self) { try returning.consumeCallback(url, now: now) }
        }
        #expect(throws: (any Error).self) {
            try returning.consumeCallback(good, now: now.addingTimeInterval(301))
        }
    }

    @Test func productionAuthorizationSessionConsumesEveryCallbackAttemptOnce() async throws {
        let session = try OpenAIAuthorizationSession.begin(
            registration: .new, hostID: hostID, callbackPort: 4242, now: now
        )
        let authorizationURL = try await session.authorizationURL(now: now)
        let returnedState = try #require(
            URLComponents(url: authorizationURL, resolvingAgainstBaseURL: false)?.queryItems?
                .first(where: { $0.name == "state" })?.value
        )
        let callback = URL(string: "http://127.0.0.1:4242/auth/callback?code=fixture-code&state="
            + returnedState
            + "&client_id=oaiapp_fixture")!
        _ = try await session.consumeCallback(callback, now: now)
        var replayRejected = false
        do { _ = try await session.consumeCallback(callback, now: now) }
        catch { replayRejected = true }
        #expect(replayRejected)
    }

    @Test func deniedCallbackNeverReturnsAnExchange() throws {
        let attempt = try fixture(.new)
        let url = URL(string: "http://127.0.0.1:4242/auth/callback?error=access_denied&state=\(state)")!
        #expect(throws: NativeAuthError.authorizationDenied) {
            try attempt.consumeCallback(url, now: now)
        }
    }

    @Test func codeRefreshAndRevocationFormsHaveNoFallbackFields() throws {
        let attempt = try fixture(.new)
        let callback = URL(string: "http://127.0.0.1:4242/auth/callback?code=fixture-code&state=\(state)&client_id=oaiapp_fixture")!
        let exchange = try attempt.consumeCallback(callback, now: now)
        let body = String(decoding: exchange.formBody, as: UTF8.self)
        #expect(body.contains("grant_type=authorization_code"))
        #expect(body.contains("resource=https%3A%2F%2Fapi.openai.com%2Fv1"))
        #expect(!body.contains("client_secret"))
        let refresh = try OpenAIRefreshExchange(
            clientID: "oaiapp_fixture",
            refreshToken: String(repeating: "r", count: 32),
            expectedSubjectSHA256: String(repeating: "a", count: 64)
        )
        #expect(String(decoding: refresh.formBody, as: UTF8.self).contains("grant_type=refresh_token"))
        let revoke = try OpenAIRevocationRequest(clientID: "oaiapp_fixture", refreshToken: String(repeating: "r", count: 32))
        #expect(String(decoding: revoke.formBody, as: UTF8.self).contains("token_type_hint=refresh_token"))
    }

    @Test func tokenResponseRequiresExactRotatingSetAndScopes() throws {
        let object: [String: Any] = [
            "access_token": String(repeating: "a", count: 32),
            "refresh_token": String(repeating: "r", count: 32),
            "id_token": String(repeating: "i", count: 32),
            "token_type": "Bearer", "expires_in": 3600,
            "scope": OpenAISignInPolicy.requiredScopes.joined(separator: " "),
            "earliest_refresh_at": 2_000_000_100,
        ]
        _ = try OpenAITokenResponse(data: JSONSerialization.data(withJSONObject: object))
        var partial = object
        partial["scope"] = "openid profile email"
        #expect(throws: (any Error).self) {
            try OpenAITokenResponse(data: JSONSerialization.data(withJSONObject: partial))
        }
        var extended = object
        extended["fallback_api_key"] = true
        #expect(throws: (any Error).self) {
            try OpenAITokenResponse(data: JSONSerialization.data(withJSONObject: extended))
        }
    }

    @Test func signedOIDCTokensBindIssuerAudienceNonceClientAccountWorkspaceAndScopes() throws {
        let signer = try RS256Fixture()
        let subject = "opaque-account-subject"
        let clientID = "oaiapp_fixture"
        let attempt = try fixture(.returning(
            clientID: clientID,
            expectedSubjectSHA256: SHA256.hash(data: Data(subject.utf8)).map { String(format: "%02x", $0) }.joined(),
            retainedIDTokenHint: nil
        ))
        let callback = URL(string: "http://127.0.0.1:4242/auth/callback?code=fixture-code&state=\(state)")!
        let exchange = try attempt.consumeCallback(callback, now: now)
        let response = try tokenResponse(
            accessToken: signer.accessToken,
            idToken: signer.idToken
        )
        let validated = try OpenAITokenVerifier.validate(
            response: response, exchange: exchange, jwks: signer.jwks, now: now
        )
        #expect(validated.clientID == clientID)
        #expect(validated.accountSubjectSHA256 == SHA256.hash(data: Data(subject.utf8))
            .map { String(format: "%02x", $0) }.joined())
        #expect(validated.workspaceSHA256 == SHA256.hash(data: Data(clientID.utf8))
            .map { String(format: "%02x", $0) }.joined())
        #expect(validated.scopes == Set(OpenAISignInPolicy.requiredScopes))
        #expect(validated.refreshExpiresAt == now.addingTimeInterval(30 * 24 * 60 * 60))

        let refresh = try OpenAIRefreshExchange(
            clientID: clientID,
            refreshToken: String(repeating: "r", count: 32),
            expectedSubjectSHA256: validated.accountSubjectSHA256
        )
        let refreshed = try OpenAITokenVerifier.validateRefresh(
            response: response, exchange: refresh, jwks: signer.jwks, now: now
        )
        #expect(refreshed.accountSubjectSHA256 == validated.accountSubjectSHA256)
        let wrongAccountRefresh = try OpenAIRefreshExchange(
            clientID: clientID,
            refreshToken: String(repeating: "r", count: 32),
            expectedSubjectSHA256: String(repeating: "0", count: 64)
        )
        #expect(throws: (any Error).self) {
            try OpenAITokenVerifier.validateRefresh(
                response: response,
                exchange: wrongAccountRefresh,
                jwks: signer.jwks,
                now: now
            )
        }

        #expect(throws: (any Error).self) {
            try OpenAITokenVerifier.validate(
                response: try tokenResponse(
                    accessToken: signer.accessToken,
                    idToken: signer.idTokenWrongNonce
                ),
                exchange: exchange, jwks: signer.jwks, now: now
            )
        }
        #expect(throws: (any Error).self) {
            try OpenAITokenVerifier.validate(
                response: try tokenResponse(
                    accessToken: signer.accessTokenWrongClient,
                    idToken: signer.idToken
                ),
                exchange: exchange, jwks: signer.jwks, now: now
            )
        }
        #expect(throws: (any Error).self) {
            try OpenAITokenVerifier.validate(
                response: try tokenResponse(
                    accessToken: signer.accessToken,
                    idToken: signer.idTokenWrongAudience
                ),
                exchange: exchange, jwks: signer.jwks, now: now
            )
        }
    }

    @Test func jwtMutationUnknownKeyAndOversizedJWKFailClosed() throws {
        let signer = try RS256Fixture()
        let clientID = "oaiapp_fixture"
        let attempt = try fixture(.new)
        let exchange = try attempt.consumeCallback(
            URL(string: "http://127.0.0.1:4242/auth/callback?code=fixture-code&state=\(state)&client_id=\(clientID)")!,
            now: now
        )
        var accessParts = signer.accessToken.split(separator: ".").map(String.init)
        var signature = Array(accessParts[2])
        let mutationIndex = signature.count / 2
        signature[mutationIndex] = signature[mutationIndex] == "A" ? "B" : "A"
        accessParts[2] = String(signature)
        let access = accessParts.joined(separator: ".")
        #expect(throws: (any Error).self) {
            try OpenAITokenVerifier.validate(
                response: try tokenResponse(accessToken: access, idToken: signer.idToken),
                exchange: exchange, jwks: signer.jwks, now: now
            )
        }
        let emptyKeys = try OpenAIJWKS(data: Data(#"{"keys":[{"kty":"RSA","kid":"other","use":"sig","alg":"RS256","n":""#
            .appending(String(repeating: "A", count: 342))
            .appending(#"","e":"AQAB"}]}"#).utf8))
        #expect(throws: (any Error).self) {
            try OpenAITokenVerifier.validate(
                response: try tokenResponse(
                    accessToken: signer.accessToken,
                    idToken: signer.idToken
                ),
                exchange: exchange, jwks: emptyKeys, now: now
            )
        }
        let oversized: [String: Any] = ["keys": [[
            "kty": "RSA", "kid": "oversized", "use": "sig", "alg": "RS256",
            "n": String(repeating: "A", count: 2_000), "e": "AQAB",
        ]]]
        #expect(throws: (any Error).self) {
            try OpenAIJWKS(data: JSONSerialization.data(withJSONObject: oversized))
        }
    }

    @Test func p256HostIdentityUsesRFC9278CanonicalThumbprint() throws {
        let key = P256.Signing.PrivateKey()
        let uri = try NativeHostIdentity.p256JWKThumbprintURI(x963PublicKey: key.publicKey.x963Representation)
        #expect(uri.hasPrefix("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"))
        try OpenAISignInPolicy.validateHostID(uri)
        var changed = key.publicKey.x963Representation
        changed[changed.count - 1] ^= 1
        #expect(throws: (any Error).self) {
            try NativeHostIdentity.p256JWKThumbprintURI(x963PublicKey: changed)
        }
        let other = P256.Signing.PrivateKey()
        #expect(try NativeHostIdentity.p256JWKThumbprintURI(
            x963PublicKey: other.publicKey.x963Representation
        ) != uri)
    }

    @Test func codexPlanPinsProviderModelDaybreakAndToolEnvironment() throws {
        let arguments = try CodexNativePolicy.appServerArguments(model: "gpt-6-sol")
        #expect(arguments.contains(#"model_provider="openai_chatgpt_plan""#))
        #expect(arguments.contains(#"model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN""#))
        #expect(arguments.contains(#"shell_environment_policy.inherit="none""#))
        #expect(arguments.contains("sandbox_workspace_write.network_access=false"))
        #expect(arguments.contains("skills.bundled.enabled=false"))
        #expect(arguments.contains("skills.include_instructions=false"))
        #expect(arguments.contains("project_doc_max_bytes=0"))
        #expect(arguments.contains("features.plugins=false"))
        #expect(arguments.contains("features.hooks=false"))
        #expect(arguments.contains("features.skill_search=false"))
        #expect(arguments.contains("daybreak=true"))
        #expect(throws: (any Error).self) {
            try CodexNativePolicy.appServerArguments(model: "gpt-6.1-sol")
        }
        let request = try CodexNativePolicy.turnStartRequest(
            id: 3, threadID: "thread-fixture", input: "bounded test", model: "gpt-6-sol"
        )
        let object = try #require(JSONSerialization.jsonObject(with: request) as? [String: Any])
        let params = try #require(object["params"] as? [String: Any])
        #expect(params["cyberAccessProgram"] as? String == "daybreakBlue")
        #expect(params["model"] as? String == "gpt-6-sol")
        #expect(params["effort"] as? String == "high")
        #expect(params["disabledPluginIds"] as? [String] == [])
    }

    @Test func realProtocolCompletionRequiresExactThreadTurnAndTrustedAccess() throws {
        let threadStart: [String: Any] = [
            "id": 2,
            "result": [
                "model": "gpt-6-sol",
                "modelProvider": "openai_chatgpt_plan",
                "serviceTier": NSNull(),
                "disabledPluginIds": [],
                "cwd": "/home/agent/research-workspace",
                "runtimeWorkspaceRoots": [],
                "instructionSources": [],
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "sandbox": ["type": "readOnly", "networkAccess": false],
                "activePermissionProfile": NSNull(),
                "reasoningEffort": "high",
                "multiAgentMode": "explicitRequestOnly",
                "thread": [
                    "id": "01a1a60c-832e-7d61-8381-fcd372b23aef",
                    "model": "gpt-6-sol",
                    "modelProvider": "openai_chatgpt_plan",
                    "reasoningEffort": "high",
                    "environments": [],
                    "daybreakEnabled": true,
                    "cwd": "/home/agent/research-workspace",
                    "ephemeral": false,
                ],
            ],
        ]
        let threadID = try CodexNativePolicy.verifyThreadStartResponse(
            JSONSerialization.data(withJSONObject: threadStart),
            requestID: 2,
            model: "gpt-6-sol"
        )
        #expect(threadID == "01a1a60c-832e-7d61-8381-fcd372b23aef")
        var reroutedThread = threadStart
        var reroutedResult = reroutedThread["result"] as! [String: Any]
        reroutedResult["model"] = "gpt-6-luna"
        reroutedThread["result"] = reroutedResult
        #expect(throws: (any Error).self) {
            try CodexNativePolicy.verifyThreadStartResponse(
                JSONSerialization.data(withJSONObject: reroutedThread),
                requestID: 2,
                model: "gpt-6-sol"
            )
        }

        let capabilityResponses: [[String: Any]] = [
            ["id": 10, "result": ["data": [[
                "cwd": CodexNativePolicy.workspace, "skills": [], "errors": [],
            ]]]],
            ["id": 11, "result": [
                "marketplaces": [], "marketplaceLoadErrors": [], "featuredPluginIds": [],
            ]],
            ["id": 12, "result": ["data": [[
                "cwd": CodexNativePolicy.workspace,
                "hooks": [], "warnings": [], "errors": [],
            ]]]],
            ["id": 13, "result": ["data": [], "nextCursor": NSNull()]],
        ]
        try CodexNativePolicy.verifyCapabilityReadback(
            skills: JSONSerialization.data(withJSONObject: capabilityResponses[0]),
            plugins: JSONSerialization.data(withJSONObject: capabilityResponses[1]),
            hooks: JSONSerialization.data(withJSONObject: capabilityResponses[2]),
            mcpServers: JSONSerialization.data(withJSONObject: capabilityResponses[3]),
            startingAt: 10
        )
        var enabledSkill = capabilityResponses
        var skillResult = enabledSkill[0]["result"] as! [String: Any]
        skillResult["data"] = [[
            "cwd": CodexNativePolicy.workspace,
            "skills": [["name": "future-skill", "enabled": true]],
            "errors": [],
        ]]
        enabledSkill[0]["result"] = skillResult
        #expect(throws: (any Error).self) {
            try CodexNativePolicy.verifyCapabilityReadback(
                skills: JSONSerialization.data(withJSONObject: enabledSkill[0]),
                plugins: JSONSerialization.data(withJSONObject: enabledSkill[1]),
                hooks: JSONSerialization.data(withJSONObject: enabledSkill[2]),
                mcpServers: JSONSerialization.data(withJSONObject: enabledSkill[3]),
                startingAt: 10
            )
        }
        #expect(try CodexNativePolicy.isCapabilityInvalidation(
            JSONSerialization.data(withJSONObject: ["method": "skills/changed", "params": [:]])
        ))

        let turnStart: [String: Any] = [
            "id": 3,
            "result": ["turn": [
                "id": "019a4888-cbbc-7a01-af49-3120b5b616b9",
                "status": "inProgress",
                "items": [],
            ]],
        ]
        let turnID = try CodexNativePolicy.verifyTurnStartResponse(
            JSONSerialization.data(withJSONObject: turnStart),
            requestID: 3
        )
        #expect(turnID == "019a4888-cbbc-7a01-af49-3120b5b616b9")

        let valid: [String: Any] = [
            "method": "turn/completed",
            "params": ["threadId": "thread-1", "turn": [
                "id": "turn-1", "status": "completed", "items": [],
            ]],
        ]
        let data = try JSONSerialization.data(withJSONObject: valid)
        try CodexNativePolicy.verifyCompletedTurn(data, threadID: "thread-1", turnID: "turn-1")
        for mutation in [["status": "failed"], ["id": "turn-other"]] {
            var changed = valid
            var params = changed["params"] as! [String: Any]
            var turn = params["turn"] as! [String: Any]
            for (key, value) in mutation { turn[key] = value }
            params["turn"] = turn
            changed["params"] = params
            #expect(throws: (any Error).self) {
                try CodexNativePolicy.verifyCompletedTurn(
                    JSONSerialization.data(withJSONObject: changed),
                    threadID: "thread-1", turnID: "turn-1"
                )
            }
        }
        let verification: [String: Any] = [
            "method": "model/verification",
            "params": ["threadId": "thread-1", "turnId": "turn-1",
                       "verifications": ["trustedAccessForCyber"]],
        ]
        try CodexNativePolicy.verifyTrustedAccess(
            JSONSerialization.data(withJSONObject: verification),
            threadID: "thread-1", turnID: "turn-1"
        )
        let reroute: [String: Any] = [
            "method": "model/rerouted",
            "params": ["threadId": "thread-1", "turnId": "turn-1",
                       "fromModel": "gpt-6-sol", "toModel": "gpt-6-luna",
                       "reason": "highRiskCyberActivity"],
        ]
        #expect(throws: (any Error).self) {
            try CodexNativePolicy.rejectReroute(
                JSONSerialization.data(withJSONObject: reroute),
                threadID: "thread-1", turnID: "turn-1"
            )
        }
    }

    private func fixture(_ registration: OpenAIRegistration) throws -> OpenAIAuthorizationAttempt {
        try OpenAIAuthorizationAttempt(
            registration: registration, hostID: hostID,
            callbackURL: URL(string: "http://127.0.0.1:4242/auth/callback")!,
            state: state, nonce: nonce, codeVerifier: verifier,
            createdAt: now, expiresAt: now.addingTimeInterval(300)
        )
    }

    private func tokenResponse(accessToken: String, idToken: String) throws -> OpenAITokenResponse {
        try OpenAITokenResponse(data: JSONSerialization.data(withJSONObject: [
            "access_token": accessToken,
            "refresh_token": String(repeating: "r", count: 32),
            "id_token": idToken,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": OpenAISignInPolicy.requiredScopes.joined(separator: " "),
            "earliest_refresh_at": Int(now.timeIntervalSince1970) + 100,
        ]))
    }
}

private struct RS256Fixture {
    let jwks: OpenAIJWKS
    let idToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUtcnNhLWtleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJvYWlhcHBfZml4dHVyZSIsImV4cCI6MjAwMDAwMzYwMCwiaWF0IjoyMDAwMDAwMDAwLCJpc3MiOiJodHRwczovL2F1dGgub3BlbmFpLmNvbSIsIm5vbmNlIjoibm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubiIsInN1YiI6Im9wYXF1ZS1hY2NvdW50LXN1YmplY3QifQ.NAXjcF0yynWQFZliEJF9pHXaDe-TPHvP8PbxlirvcjV5OrtB3Ja_kqsYIdf2MrNx6HZu5ib2SE4EZeRoIEk24HY9LrIVFXu_bVfMxOi4-6OohmIMKxZxzqTExBvf_mYV4K9izdJsjf9mlPfVZeq7XQe6EWHVhiSIpNXhXmXziyvPoPKTnEARl_I1RUrNZVOlC4QR2slfSptCJ3skeu6D3qQ8hQLYTywZEBsJXnui7IZkUuLIbHXsf0QAwxEZH2l3EDmrjk9g8P78cEs2VmG3gKV-r7UqeBzmjPS7t9AS4xJH5kbhbCf4N-xb0CWeo0BSgTKqco2bAV6PZsta52bG5w"
    let idTokenWrongNonce = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUtcnNhLWtleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJvYWlhcHBfZml4dHVyZSIsImV4cCI6MjAwMDAwMzYwMCwiaWF0IjoyMDAwMDAwMDAwLCJpc3MiOiJodHRwczovL2F1dGgub3BlbmFpLmNvbSIsIm5vbmNlIjoid3JvbmciLCJzdWIiOiJvcGFxdWUtYWNjb3VudC1zdWJqZWN0In0.JiQI7Sw5QfYkytRrveS2R1V4paYYU9p4piyTAy7AswSW7QRp8wKcKMZiSgtIBt-6WK97HybHPrXXKv7eP-0Qi277FJ2Ab7D3IpO5hR6-iBRH4ch36ANeTbWk5tcvoj-oCO5OMgIuxZYXNe3h6ylGOZ3e8gkvMEZwmQC9675WGP3wwHrub0EqGqwYWoVYneXGClNSVFaaGS35_ACZQisd584H6pB0JlrCfRGo8oib9xBdpnp73yV6n-VVz-64edNLc7CWMb7rrVYk0D4WIRI-M8z2s07mL4vMupZG8SFYx04hvXBtra-_aIcqpm0WucCfW5TIjkFoacCsJ31MX98lGw"
    let idTokenWrongAudience = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUtcnNhLWtleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJvYWlhcHBfb3RoZXIiLCJleHAiOjIwMDAwMDM2MDAsImlhdCI6MjAwMDAwMDAwMCwiaXNzIjoiaHR0cHM6Ly9hdXRoLm9wZW5haS5jb20iLCJub25jZSI6Im5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4iLCJzdWIiOiJvcGFxdWUtYWNjb3VudC1zdWJqZWN0In0.YD15-tXz_Sq4V_zmDCyBA5RcpohdgOck7TW22emnmcaHflfhRvOi4JUXmFy56wSF65hLwz-zcmlh565gGW3wCvsSj2GrdeIbDeBgP3WqSeeaKw015t0PBP2NUQFnbrHOVSImTDjK2uw5kPXBP3do0PHcSa8BfRqPl3N5lIbqqh5YVGN4_sCGfm1rHG305uFdGyAuQv_ZqWwiW73BYFEX7ZxDR22dX2JO4zT03lxxI3mBHbFp1n5qgssE4izFr5l-llNwQCX-hvJmvqUatUTXnlM9n3hBjsKxYThiYORD3LoDVLIFkT2HsnK2Q4fu93De7WLhi0CZlupjs8BdPf0axQ"
    let accessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUtcnNhLWtleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2FwaS5vcGVuYWkuY29tL3YxIiwiY2xpZW50X2lkIjoib2FpYXBwX2ZpeHR1cmUiLCJleHAiOjIwMDAwMDM2MDAsImlhdCI6MjAwMDAwMDAwMCwiaXNzIjoiaHR0cHM6Ly9hdXRoLm9wZW5haS5jb20iLCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIG9mZmxpbmVfYWNjZXNzIHJlc291cmNlLmludm9rZSBjaGF0Z3B0LnRva2Vucy51c2UuZGlyZWN0Iiwic3ViIjoib3BhcXVlLWFjY291bnQtc3ViamVjdCJ9.BUhzOK4JQ5xpZflUgtHu__urYh5uYoBqFXrjM0vstppjbBSYS_pga4ncdhuX5HaCDzgtWyGs_Vy530DqGFhNe53aaDn1Fd0mmRyR2xUMpk07gh4IPorCCcDIqvU6CyHU_eYAmdGgAKDSxEmjUc4NaAK7fFyMtwojIvj6B_SqRaRlm4bRecK8eAD3gPnVbootIC8uCoOaZQ3CvY9eT_W7IoO9j-nx7KQjh-vK8Zj5pMal-Yz7T6mwjE69Yc9Zy_uTiZobIf8eoS6rEkY79m293ZxWmKdgmt74jStw3uucCU8uIhLehgb_yNrw15Pf2L2k-98yVn1mxKDwVcNvYWCC3A"
    let accessTokenWrongClient = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZpeHR1cmUtcnNhLWtleSIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2FwaS5vcGVuYWkuY29tL3YxIiwiY2xpZW50X2lkIjoib2FpYXBwX290aGVyIiwiZXhwIjoyMDAwMDAzNjAwLCJpYXQiOjIwMDAwMDAwMDAsImlzcyI6Imh0dHBzOi8vYXV0aC5vcGVuYWkuY29tIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCBvZmZsaW5lX2FjY2VzcyByZXNvdXJjZS5pbnZva2UgY2hhdGdwdC50b2tlbnMudXNlLmRpcmVjdCIsInN1YiI6Im9wYXF1ZS1hY2NvdW50LXN1YmplY3QifQ.CEAnwPFU33nQXoFVRgCvN9op5dsBvD_SYy-whWKGKbXvB_zIrkJVHcFq7zJXQao16AXYXr_J1wFOa3mQk0yACYraHNpcXD-aL2ROgM1QmSaTtSrYvAWhw5IrSm1PL390nIc3D2p305s7MNsBqwPopEtluKyNYLeqs283Vrm51Mqp_PAsi5ABnDJssn-B4ok53HWWC59YamPpqNUBmt-PGSr5BGQCQ0kkl4nLUL81o7VZMqA-G_3UyIYkBzdRoSZBk9e1POlqAdBnD341QC2_qv58uAahyM5SUU27V-4gHnGtoaK__hbpx71LE5xxn10mb_HZp8YTXe0S9jAV4Rcrgw"

    init() throws {
        let object: [String: Any] = ["keys": [[
            "kty": "RSA", "kid": "fixture-rsa-key", "use": "sig", "alg": "RS256",
            "n": "wV3E1gl-6KLBRopvTTEp7w4MY3BHEzRZXJP2-JJTdeMcJu4KgjML9SDQdAQSmQ5Teq6GucKyPhqTUmszsAAfSn-9xl4EPOKsqVhUSBWAjaXgsCz8AXnwhqRzfP7wowQ1d4qNtayYyVD03sTVlj8ICdHghUDknS2h-xTC8sRg7Lcmi0Cq6taKj3jhSFhMeIQCqBK6RllKPNUfhA7cGutTdFhyUe1AMEHNtCjNxJDOja1j3U8GGxp5AzyvEhgNYEc6hW35jXkLjP_BbYZtGB9CrzY1Kx3luDNaw2XpPNN1xqwSVDimbKd53uEcvXhUc2idtw8ddhoxAsSms10qg4AWyQ",
            "e": "AQAB",
        ]]]
        jwks = try OpenAIJWKS(data: JSONSerialization.data(withJSONObject: object))
    }
}
