import AppKit
import Foundation
import SecureSandboxNativeAuthCore

protocol VisibleBrowserOpening: Sendable {
    func open(_ url: URL) async throws
}

struct SystemVisibleBrowser: VisibleBrowserOpening {
    func open(_ url: URL) async throws {
        let opened = await MainActor.run { NSWorkspace.shared.open(url) }
        guard opened else { throw NativeCredentialHelperError.browserLaunchFailed }
    }
}

protocol OpenAITokenValidating: Sendable {
    func validateInitial(
        responseData: Data,
        exchange: OpenAICodeExchange,
        jwksData: Data,
        now: Date
    ) throws -> StoredOpenAICredentials

    func validateRefresh(
        responseData: Data,
        previous: StoredOpenAICredentials,
        jwksData: Data,
        now: Date
    ) throws -> StoredOpenAICredentials
}

struct CoreOpenAITokenValidator: OpenAITokenValidating {
    func validateInitial(
        responseData: Data,
        exchange: OpenAICodeExchange,
        jwksData: Data,
        now: Date
    ) throws -> StoredOpenAICredentials {
        do {
            let response = try OpenAITokenResponse(data: responseData)
            let jwks = try OpenAIJWKS(data: jwksData)
            let validated = try OpenAITokenVerifier.validate(
                response: response, exchange: exchange, jwks: jwks, now: now
            )
            return try StoredOpenAICredentials.from(responseData: responseData, validated: validated)
        } catch {
            throw NativeCredentialHelperError.providerResponseRejected
        }
    }

    func validateRefresh(
        responseData: Data,
        previous: StoredOpenAICredentials,
        jwksData: Data,
        now: Date
    ) throws -> StoredOpenAICredentials {
        do {
            let exchange = try OpenAIRefreshExchange(
                clientID: previous.clientID,
                refreshToken: previous.refreshToken,
                expectedSubjectSHA256: previous.accountSubjectSHA256
            )
            let response = try OpenAITokenResponse(data: responseData)
            let jwks = try OpenAIJWKS(data: jwksData)
            let validated = try OpenAITokenVerifier.validateRefresh(
                response: response, exchange: exchange, jwks: jwks, now: now
            )
            return try StoredOpenAICredentials.from(responseData: responseData, validated: validated)
        } catch {
            throw NativeCredentialHelperError.providerResponseRejected
        }
    }
}

actor NativeCredentialCoordinator {
    typealias CallbackReceiverFactory = @Sendable () -> any AuthorizationCallbackReceiving

    private let hostIdentity: any NativeHostIdentityProviding
    private let callbackReceiver: CallbackReceiverFactory
    private let browser: any VisibleBrowserOpening
    private let transport: any OpenAIHTTPTransport
    private let validator: any OpenAITokenValidating
    private let vault: any OpenAICredentialVault
    private let consumer: any CredentialConsumerLaunching
    private var operationActive = false

    init(
        hostIdentity: any NativeHostIdentityProviding,
        callbackReceiver: @escaping CallbackReceiverFactory,
        browser: any VisibleBrowserOpening,
        transport: any OpenAIHTTPTransport,
        validator: any OpenAITokenValidating,
        vault: any OpenAICredentialVault,
        consumer: any CredentialConsumerLaunching
    ) {
        self.hostIdentity = hostIdentity
        self.callbackReceiver = callbackReceiver
        self.browser = browser
        self.transport = transport
        self.validator = validator
        self.vault = vault
        self.consumer = consumer
    }

    func status(now: Date = Date()) throws -> NativeCredentialStatus {
        guard let stored = try vault.load() else {
            return try NativeCredentialStatus(provider: .openAIChatGPT, state: .loggedOut)
        }
        return try stored.status(now: now)
    }

    func login(now: Date = Date()) async throws -> NativeCredentialStatus {
        try Task.checkCancellation()
        try beginOperation()
        defer { operationActive = false }
        let previous = try vault.load()
        let registration: OpenAIRegistration = if let previous {
            .returning(
                clientID: previous.clientID,
                expectedSubjectSHA256: previous.accountSubjectSHA256,
                retainedIDTokenHint: previous.idToken
            )
        } else {
            .new
        }
        let receiver = callbackReceiver()
        let callbackPort = try receiver.begin()
        defer { receiver.cancel() }
        let hostID = try hostIdentity.hostID()
        let authorization = try OpenAIAuthorizationSession.begin(
            registration: registration,
            hostID: hostID,
            callbackPort: callbackPort,
            now: now
        )
        let authorizationURL = try await authorization.authorizationURL(now: now)
        try await browser.open(authorizationURL)
        let callback = try await receiver.waitForCallback(
            deadline: now.addingTimeInterval(OpenAISignInPolicy.attemptLifetime)
        )
        let exchange = try await authorization.consumeCallback(callback, now: Date())
        let responseData = try await transport.exchangeCode(formBody: exchange.formBody)
        let jwksData = try await transport.fetchJWKS()
        let replacement = try validator.validateInitial(
            responseData: responseData, exchange: exchange, jwksData: jwksData, now: Date()
        )
        if let previous, !Self.sameReturningAuthority(previous, replacement) {
            throw NativeCredentialHelperError.providerResponseRejected
        }
        try Task.checkCancellation()
        try vault.replace(with: replacement)
        return try replacement.status(now: Date())
    }

    static func sameReturningAuthority(
        _ previous: StoredOpenAICredentials,
        _ replacement: StoredOpenAICredentials
    ) -> Bool {
        previous.clientID == replacement.clientID
            && previous.accountSubjectSHA256 == replacement.accountSubjectSHA256
            && previous.workspaceSHA256 == replacement.workspaceSHA256
    }

    func refresh(now: Date = Date()) async throws -> NativeCredentialStatus {
        try Task.checkCancellation()
        try beginOperation()
        defer { operationActive = false }
        guard let previous = try vault.load() else { throw NativeCredentialHelperError.credentialNotFound }
        guard now >= previous.earliestRefreshAt.addingTimeInterval(-30), now < previous.refreshExpiresAt else {
            throw NativeCredentialHelperError.providerResponseRejected
        }
        let request: OpenAIRefreshExchange
        do {
            request = try OpenAIRefreshExchange(
                clientID: previous.clientID,
                refreshToken: previous.refreshToken,
                expectedSubjectSHA256: previous.accountSubjectSHA256
            )
        }
        catch { throw NativeCredentialHelperError.providerResponseRejected }
        let responseData = try await transport.refresh(formBody: request.formBody)
        let jwksData = try await transport.fetchJWKS()
        let replacement = try validator.validateRefresh(
            responseData: responseData,
            previous: previous,
            jwksData: jwksData,
            now: now
        )
        guard replacement.clientID == previous.clientID,
              replacement.accountSubjectSHA256 == previous.accountSubjectSHA256,
              replacement.workspaceSHA256 == previous.workspaceSHA256,
              replacement.scopeSHA256 == previous.scopeSHA256,
              replacement.savedAt >= previous.savedAt else {
            throw NativeCredentialHelperError.providerResponseRejected
        }
        try Task.checkCancellation()
        try vault.replace(with: replacement)
        return try replacement.status(now: now)
    }

    func logout() async throws -> NativeCredentialStatus {
        try Task.checkCancellation()
        try beginOperation()
        defer { operationActive = false }
        guard let stored = try vault.load() else {
            return try NativeCredentialStatus(provider: .openAIChatGPT, state: .loggedOut)
        }
        let request: OpenAIRevocationRequest
        do { request = try OpenAIRevocationRequest(clientID: stored.clientID, refreshToken: stored.refreshToken) }
        catch { throw NativeCredentialHelperError.revocationFailed }
        do { try await transport.revoke(formBody: request.formBody) }
        catch { throw NativeCredentialHelperError.revocationFailed }
        try Task.checkCancellation()
        try vault.delete()
        return try NativeCredentialStatus(provider: .openAIChatGPT, state: .loggedOut)
    }

    func destroyLocalCredential() throws -> NativeCredentialStatus {
        try Task.checkCancellation()
        try beginOperation()
        defer { operationActive = false }
        try vault.delete()
        return try NativeCredentialStatus(provider: .openAIChatGPT, state: .loggedOut)
    }

    func recoverLocalState() throws -> NativeCredentialStatus {
        // Recovery is deliberately destructive and is reachable only through
        // the independently authorized XPC service action.  It does not try to
        // decode potentially corrupt credential bytes before deleting the one
        // fixed Keychain item.
        try Task.checkCancellation()
        try beginOperation()
        defer { operationActive = false }
        try vault.delete()
        return try NativeCredentialStatus(provider: .openAIChatGPT, state: .loggedOut)
    }

    func project(_ request: CredentialProjectionRequest, now: Date = Date()) async throws -> LaunchedCredentialConsumer {
        try Task.checkCancellation()
        try beginOperation()
        defer { operationActive = false }
        guard let stored = try vault.load(), now < stored.accessExpiresAt else {
            throw NativeCredentialHelperError.credentialNotFound
        }
        return try await consumer.launch(credential: stored, request: request, now: now)
    }

    private func beginOperation() throws {
        guard !operationActive else { throw NativeCredentialHelperError.operationInProgress }
        operationActive = true
    }
}
