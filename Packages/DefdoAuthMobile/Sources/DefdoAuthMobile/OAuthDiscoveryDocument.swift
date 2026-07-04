import Foundation

/// OAuth/OIDC discovery metadata. Accepts both the OIDC discovery document
/// (/.well-known/openid-configuration) and the RFC 8414 OAuth Authorization
/// Server metadata document (/.well-known/oauth-authorization-server):
/// OIDC-only fields are simply absent for the latter.
///
/// Mirrors the Android `dev.defdo.mobile.auth.OAuthDiscoveryDocument`.
public struct OAuthDiscoveryDocument: Sendable, Equatable {
    public let issuer: String?
    public let authorizationEndpoint: String?
    public let tokenEndpoint: String?
    public let revocationEndpoint: String?
    public let userinfoEndpoint: String?
    public let jwksURI: String?
    public let codeChallengeMethodsSupported: [String]?
    public let scopesSupported: [String]?
    public let grantTypesSupported: [String]?
    public let responseTypesSupported: [String]?
    public let tokenEndpointAuthMethodsSupported: [String]?

    public init(
        issuer: String?,
        authorizationEndpoint: String?,
        tokenEndpoint: String?,
        revocationEndpoint: String? = nil,
        userinfoEndpoint: String? = nil,
        jwksURI: String? = nil,
        codeChallengeMethodsSupported: [String]? = nil,
        scopesSupported: [String]? = nil,
        grantTypesSupported: [String]? = nil,
        responseTypesSupported: [String]? = nil,
        tokenEndpointAuthMethodsSupported: [String]? = nil
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.userinfoEndpoint = userinfoEndpoint
        self.jwksURI = jwksURI
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.scopesSupported = scopesSupported
        self.grantTypesSupported = grantTypesSupported
        self.responseTypesSupported = responseTypesSupported
        self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
    }

    /// Builds a document from a parsed JSON object.
    public static func fromJson(_ map: [String: Any]) -> OAuthDiscoveryDocument {
        OAuthDiscoveryDocument(
            issuer: map["issuer"] as? String,
            authorizationEndpoint: map["authorization_endpoint"] as? String,
            tokenEndpoint: map["token_endpoint"] as? String,
            revocationEndpoint: map["revocation_endpoint"] as? String,
            userinfoEndpoint: map["userinfo_endpoint"] as? String,
            jwksURI: map["jwks_uri"] as? String,
            codeChallengeMethodsSupported: stringList(map["code_challenge_methods_supported"]),
            scopesSupported: stringList(map["scopes_supported"]),
            grantTypesSupported: stringList(map["grant_types_supported"]),
            responseTypesSupported: stringList(map["response_types_supported"]),
            tokenEndpointAuthMethodsSupported: stringList(map["token_endpoint_auth_methods_supported"])
        )
    }

    /// Parses a raw discovery JSON body and builds the document.
    public static func fromJsonText(_ body: String) -> OAuthDiscoveryDocument? {
        guard let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return fromJson(json)
    }

    public func validate() -> AuthError? { validate(nil) }

    /// Validates the document for use by a public PKCE mobile client:
    /// required endpoints present, exact issuer match (no trailing-slash
    /// tolerance), HTTPS-only endpoints on the issuer's host, S256 support,
    /// `code` response type, and the `authorization_code` grant.
    public func validate(_ expectedIssuer: String?) -> AuthError? {
        guard let issuer, !issuer.isEmpty else {
            return .invalidDiscovery("missing issuer")
        }
        guard let authorizationEndpoint, !authorizationEndpoint.isEmpty else {
            return .invalidDiscovery("missing authorization_endpoint")
        }
        guard let tokenEndpoint, !tokenEndpoint.isEmpty else {
            return .invalidDiscovery("missing token_endpoint")
        }

        if let expectedIssuer, issuer != expectedIssuer {
            return .invalidDiscovery("issuer mismatch: expected \(expectedIssuer), got \(issuer)")
        }

        let endpoints: [(String, String?)] = [
            ("authorization_endpoint", authorizationEndpoint),
            ("token_endpoint", tokenEndpoint),
            ("revocation_endpoint", revocationEndpoint)
        ]

        for (name, url) in endpoints {
            if let url, !url.hasPrefix("https://") {
                return .invalidDiscovery("\(name) must use HTTPS")
            }
        }

        if let expectedIssuer, let issuerHost = URL(string: expectedIssuer)?.host {
            for (name, url) in endpoints {
                if let url, let endpointHost = URL(string: url)?.host, endpointHost != issuerHost {
                    return .invalidDiscovery(
                        "\(name) host (\(endpointHost)) does not match issuer host (\(issuerHost))"
                    )
                }
            }
        }

        if let methods = codeChallengeMethodsSupported, !methods.contains("S256") {
            return .invalidDiscovery("code_challenge_methods_supported does not include S256")
        }

        if let responseTypes = responseTypesSupported, !responseTypes.contains("code") {
            return .invalidDiscovery("response_types_supported does not include code")
        }

        if let grants = grantTypesSupported, !grants.contains("authorization_code") {
            return .invalidDiscovery("grant_types_supported does not include authorization_code")
        }

        return nil
    }

    private static func stringList(_ value: Any?) -> [String]? {
        (value as? [Any])?.map { "\($0)" }
    }
}
