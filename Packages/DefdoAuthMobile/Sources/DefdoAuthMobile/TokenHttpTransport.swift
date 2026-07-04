import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Token/revocation endpoint transport. Implementations must never log
/// parameter values (codes, verifiers, tokens).
public protocol TokenHttpTransport: Sendable {
    func exchangeCode(tokenEndpoint: String, params: [String: String]) async -> Result<TokenResponse, AuthError>
    func refreshToken(tokenEndpoint: String, params: [String: String]) async -> Result<RefreshResponse, AuthError>
    func revokeToken(revocationEndpoint: String, params: [String: String]) async -> Result<Void, AuthError>
}

public struct URLSessionTokenHttpTransport: TokenHttpTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func exchangeCode(
        tokenEndpoint: String,
        params: [String: String]
    ) async -> Result<TokenResponse, AuthError> {
        await post(tokenEndpoint, params: params).map(TokenResponse.parse)
    }

    public func refreshToken(
        tokenEndpoint: String,
        params: [String: String]
    ) async -> Result<RefreshResponse, AuthError> {
        await post(tokenEndpoint, params: params).map(RefreshResponse.parse)
    }

    public func revokeToken(
        revocationEndpoint: String,
        params: [String: String]
    ) async -> Result<Void, AuthError> {
        await post(revocationEndpoint, params: params).map { _ in () }
    }

    /// POSTs application/x-www-form-urlencoded and returns the parsed JSON
    /// object. OAuth error payloads (4xx with `error` field) are returned as
    /// parsed bodies so callers can normalize them.
    private func post(_ endpoint: String, params: [String: String]) async -> Result<[String: Any], AuthError> {
        guard let url = URL(string: endpoint) else {
            return .failure(.invalidDiscovery("invalid endpoint URL"))
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = params
            .map { "\(AuthorizationRequestBuilder.rfc3986Encode($0.key))=\(AuthorizationRequestBuilder.rfc3986Encode($0.value))" }
            .joined(separator: "&")
            .data(using: .utf8)

        do {
            let (data, _) = try await session.data(for: request)
            if data.isEmpty { return .success([:]) }
            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return .success([:])
            }
            return .success(json)
        } catch {
            return .failure(.retryable)
        }
    }
}
