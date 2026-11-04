import Foundation
import SecureSandboxNativeAuthCore

protocol OpenAIHTTPTransport: Sendable {
    func exchangeCode(formBody: Data) async throws -> Data
    func refresh(formBody: Data) async throws -> Data
    func fetchJWKS() async throws -> Data
    func revoke(formBody: Data) async throws
}

final class OpenAIFixedOriginHTTPClient: OpenAIHTTPTransport, @unchecked Sendable {
    func exchangeCode(formBody: Data) async throws -> Data {
        try await postToken(formBody)
    }

    func refresh(formBody: Data) async throws -> Data {
        try await postToken(formBody)
    }

    func fetchJWKS() async throws -> Data {
        var request = URLRequest(url: OpenAISignInPolicy.jwksEndpoint)
        request.httpMethod = "GET"
        request.httpShouldHandleCookies = false
        return try await perform(
            request,
            endpoint: OpenAISignInPolicy.jwksEndpoint,
            acceptedStatus: [200],
            maximumBodyBytes: 262_144,
            requireJSON: true
        )
    }

    func revoke(formBody: Data) async throws {
        guard formBody.count <= 32_768 else { throw NativeCredentialHelperError.providerTransportFailed }
        var request = URLRequest(url: OpenAISignInPolicy.revocationEndpoint)
        request.httpMethod = "POST"
        request.httpBody = formBody
        request.httpShouldHandleCookies = false
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        _ = try await perform(
            request,
            endpoint: OpenAISignInPolicy.revocationEndpoint,
            acceptedStatus: [200, 204],
            maximumBodyBytes: 16_384,
            requireJSON: false
        )
    }

    private func postToken(_ formBody: Data) async throws -> Data {
        guard formBody.count <= 32_768 else { throw NativeCredentialHelperError.providerTransportFailed }
        var request = URLRequest(url: OpenAISignInPolicy.tokenEndpoint)
        request.httpMethod = "POST"
        request.httpBody = formBody
        request.httpShouldHandleCookies = false
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        return try await perform(
            request,
            endpoint: OpenAISignInPolicy.tokenEndpoint,
            acceptedStatus: [200],
            maximumBodyBytes: 131_072,
            requireJSON: true
        )
    }

    private func perform(
        _ request: URLRequest,
        endpoint: URL,
        acceptedStatus: Set<Int>,
        maximumBodyBytes: Int,
        requireJSON: Bool
    ) async throws -> Data {
        guard Self.isExact(request.url, endpoint), request.httpShouldHandleCookies == false else {
            throw NativeCredentialHelperError.providerTransportFailed
        }
        let delegate = BoundedOpenAIRequest(
            endpoint: endpoint,
            acceptedStatus: acceptedStatus,
            maximumBodyBytes: maximumBodyBytes,
            requireJSON: requireJSON
        )
        return try await delegate.execute(request, configuration: Self.configuration())
    }

    fileprivate static func isExact(_ actual: URL?, _ expected: URL) -> Bool {
        guard let actual,
              let a = URLComponents(url: actual, resolvingAgainstBaseURL: false),
              let e = URLComponents(url: expected, resolvingAgainstBaseURL: false) else { return false }
        return a.scheme == "https" && a.scheme == e.scheme && a.host == e.host
            && a.port == e.port && a.path == e.path && a.query == nil && a.fragment == nil
            && a.user == nil && a.password == nil
    }

    private static func configuration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpMaximumConnectionsPerHost = 1
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 45
        configuration.waitsForConnectivity = false
        configuration.httpAdditionalHeaders = [
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": "SecureSandboxNativeCredentialHelper/1",
        ]
        return configuration
    }
}

private final class BoundedOpenAIRequest: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let endpoint: URL
    private let acceptedStatus: Set<Int>
    private let maximumBodyBytes: Int
    private let requireJSON: Bool
    private let lock = NSLock()
    private var session: URLSession?
    private var continuation: CheckedContinuation<Data, any Error>?
    private var body = Data()
    private var responseAccepted = false
    private var terminalError: NativeCredentialHelperError?

    init(endpoint: URL, acceptedStatus: Set<Int>, maximumBodyBytes: Int, requireJSON: Bool) {
        self.endpoint = endpoint
        self.acceptedStatus = acceptedStatus
        self.maximumBodyBytes = maximumBodyBytes
        self.requireJSON = requireJSON
    }

    func execute(_ request: URLRequest, configuration: URLSessionConfiguration) async throws -> Data {
        try Task.checkCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                lock.withLock { self.continuation = continuation }
                let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
                let shouldStart = lock.withLock { () -> Bool in
                    guard self.continuation != nil, terminalError == nil else { return false }
                    self.session = session
                    return true
                }
                if shouldStart {
                    session.dataTask(with: request).resume()
                } else {
                    session.invalidateAndCancel()
                    finish(.failure(NativeCredentialHelperError.providerTransportFailed))
                }
            }
        } onCancel: {
            self.cancel()
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        lock.withLock { terminalError = .providerResponseRejected }
        completionHandler(nil)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        guard let http = response as? HTTPURLResponse,
              OpenAIFixedOriginHTTPClient.isExact(http.url, endpoint),
              acceptedStatus.contains(http.statusCode),
              http.value(forHTTPHeaderField: "Content-Encoding") == nil
                  || http.value(forHTTPHeaderField: "Content-Encoding") == "identity",
              response.expectedContentLength < 0
                  || response.expectedContentLength <= Int64(maximumBodyBytes),
              !requireJSON || http.mimeType == "application/json" else {
            lock.withLock { terminalError = .providerResponseRejected }
            completionHandler(.cancel)
            return
        }
        lock.withLock { responseAccepted = true }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let shouldCancel = lock.withLock { () -> Bool in
            guard terminalError == nil, body.count + data.count <= maximumBodyBytes else {
                terminalError = .providerResponseRejected
                return true
            }
            body.append(data)
            return false
        }
        if shouldCancel { dataTask.cancel() }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: (any Error)?
    ) {
        let result: Result<Data, any Error> = lock.withLock {
            if let terminalError { return .failure(terminalError) }
            guard error == nil, responseAccepted else {
                return .failure(NativeCredentialHelperError.providerTransportFailed)
            }
            return .success(body)
        }
        finish(result)
    }

    private func cancel() {
        let state = lock.withLock { () -> (URLSession?, Bool) in
            terminalError = .providerTransportFailed
            return (session, session == nil && continuation != nil)
        }
        state.0?.invalidateAndCancel()
        if state.1 { finish(.failure(NativeCredentialHelperError.providerTransportFailed)) }
    }

    private func finish(_ result: Result<Data, any Error>) {
        let state = lock.withLock { () -> (CheckedContinuation<Data, any Error>?, URLSession?) in
            let continuation = self.continuation
            let session = self.session
            self.continuation = nil
            self.session = nil
            body.removeAll(keepingCapacity: false)
            return (continuation, session)
        }
        state.1?.finishTasksAndInvalidate()
        state.0?.resume(with: result)
    }
}

private extension NSLock {
    func withLock<T>(_ operation: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try operation()
    }
}
