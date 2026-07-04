import Foundation

/// Builds the authorization request URL. The endpoint must always come from a
/// validated discovery document — never hardcode /openid/authorize or
/// /oauth/authorize.
public enum AuthorizationRequestBuilder {
    public static func parameters(_ request: LoginRequest) throws -> [(String, String)] {
        let config = request.config
        guard !config.clientID.isEmpty else { throw AuthError.invalidCallback("missing client_id") }
        guard !config.redirectURI.isEmpty else { throw AuthError.invalidCallback("missing redirect_uri") }
        guard !config.scopes.isEmpty else { throw AuthError.invalidCallback("empty scopes") }
        guard PKCE.isValidVerifier(request.codeVerifier) else {
            throw AuthError.invalidCallback("invalid code_challenge")
        }

        var params: [(String, String)] = [
            ("response_type", "code"),
            ("client_id", config.clientID),
            ("redirect_uri", config.redirectURI),
            ("scope", config.scopes.joined(separator: " ")),
            ("state", request.state),
            ("code_challenge", PKCE.s256Challenge(request.codeVerifier)),
            ("code_challenge_method", "S256")
        ]
        if config.useNonce, let nonce = request.nonce, !nonce.isEmpty {
            params.append(("nonce", nonce))
        }
        return params
    }

    public static func url(authorizationEndpoint: String, request: LoginRequest) throws -> URL {
        guard !authorizationEndpoint.isEmpty else {
            throw AuthError.invalidDiscovery("missing authorization_endpoint")
        }
        let query = try parameters(request)
            .map { "\(rfc3986Encode($0.0))=\(rfc3986Encode($0.1))" }
            .joined(separator: "&")
        guard let url = URL(string: "\(authorizationEndpoint)?\(query)") else {
            throw AuthError.invalidDiscovery("invalid authorization_endpoint URL")
        }
        return url
    }

    static func rfc3986Encode(_ value: String) -> String {
        let unreserved = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        return value.addingPercentEncoding(withAllowedCharacters: unreserved) ?? value
    }
}
