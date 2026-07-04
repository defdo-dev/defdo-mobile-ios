import XCTest
@testable import DefdoAuthMobile

/// Discovery contract against the live idp.mi-omv.com metadata shape.
/// Source of truth: shared-contracts/auth/discovery.{oidc,oauth_as}.mi-omv.fixture.json
final class DiscoveryContractTests: XCTestCase {
    static let oidcFixture = """
    {
      "issuer": "https://idp.mi-omv.com",
      "authorization_endpoint": "https://idp.mi-omv.com/openid/authorize",
      "token_endpoint": "https://idp.mi-omv.com/oauth/token",
      "revocation_endpoint": "https://idp.mi-omv.com/oauth/revoke",
      "introspection_endpoint": "https://idp.mi-omv.com/oauth/introspect",
      "device_authorization_endpoint": "https://idp.mi-omv.com/oauth/device",
      "userinfo_endpoint": "https://idp.mi-omv.com/openid/userinfo",
      "jwks_uri": "https://idp.mi-omv.com/openid/jwks",
      "scopes_supported": ["address", "email", "metadata", "offline_access", "openid", "phone", "profile"],
      "grant_types_supported": ["client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
      "response_types_supported": ["code"],
      "code_challenge_methods_supported": ["S256"],
      "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"],
      "id_token_signing_alg_values_supported": ["RS512"],
      "subject_types_supported": ["public"]
    }
    """

    static let oauthASFixture = """
    {
      "issuer": "https://idp.mi-omv.com",
      "authorization_endpoint": "https://idp.mi-omv.com/oauth/authorize",
      "token_endpoint": "https://idp.mi-omv.com/oauth/token",
      "revocation_endpoint": "https://idp.mi-omv.com/oauth/revoke",
      "introspection_endpoint": "https://idp.mi-omv.com/oauth/introspect",
      "device_authorization_endpoint": "https://idp.mi-omv.com/oauth/device",
      "jwks_uri": "https://idp.mi-omv.com/openid/jwks",
      "scopes_supported": ["address", "email", "metadata", "offline_access", "openid", "phone", "profile"],
      "grant_types_supported": ["client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
      "response_types_supported": ["code"],
      "code_challenge_methods_supported": ["S256"],
      "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"]
    }
    """

    private let issuer = "https://idp.mi-omv.com"

    func testParsesOIDCDiscoveryFromLiveShape() throws {
        let doc = try XCTUnwrap(OAuthDiscoveryDocument.fromJsonText(Self.oidcFixture))
        XCTAssertNil(doc.validate(issuer))
        XCTAssertEqual(doc.authorizationEndpoint, "https://idp.mi-omv.com/openid/authorize")
        XCTAssertNotNil(doc.userinfoEndpoint, "OIDC discovery must include userinfo_endpoint")
        XCTAssertEqual(doc.tokenEndpointAuthMethodsSupported?.contains("none"), true,
                       "token_endpoint_auth_methods_supported must include none for public clients")
    }

    func testParsesOAuthASMetadataFromLiveShape() throws {
        let oidc = try XCTUnwrap(OAuthDiscoveryDocument.fromJsonText(Self.oidcFixture))
        let doc = try XCTUnwrap(OAuthDiscoveryDocument.fromJsonText(Self.oauthASFixture))
        XCTAssertNil(doc.validate(issuer))
        XCTAssertEqual(doc.authorizationEndpoint, "https://idp.mi-omv.com/oauth/authorize")
        XCTAssertNil(doc.userinfoEndpoint, "OAuth AS metadata must not require userinfo_endpoint")
        XCTAssertEqual(doc.tokenEndpoint, oidc.tokenEndpoint,
                       "token_endpoint must be identical between discovery documents")
        XCTAssertEqual(doc.revocationEndpoint, oidc.revocationEndpoint,
                       "revocation_endpoint must be identical between discovery documents")
    }

    func testAuthorizeURLUsesDiscoveredEndpointPerDocument() throws {
        let config = AuthConfig(
            clientID: "selfcare-mobile",
            discoveryURL: URL(string: "\(issuer)/.well-known/openid-configuration")!,
            redirectURI: "https://login.defdo-telecom.example/mobile/oauth/callback",
            scopes: ["openid", "profile", "offline_access"]
        )
        let request = LoginRequest(
            config: config,
            state: "state-1",
            nonce: "nonce-1",
            codeVerifier: PKCE.generateVerifier()
        )

        let oidc = try XCTUnwrap(OAuthDiscoveryDocument.fromJsonText(Self.oidcFixture))
        let oidcURL = try AuthorizationRequestBuilder.url(
            authorizationEndpoint: XCTUnwrap(oidc.authorizationEndpoint), request: request
        )
        XCTAssertTrue(oidcURL.absoluteString.hasPrefix("https://idp.mi-omv.com/openid/authorize?"))

        let oauthAS = try XCTUnwrap(OAuthDiscoveryDocument.fromJsonText(Self.oauthASFixture))
        let asURL = try AuthorizationRequestBuilder.url(
            authorizationEndpoint: XCTUnwrap(oauthAS.authorizationEndpoint), request: request
        )
        XCTAssertTrue(asURL.absoluteString.hasPrefix("https://idp.mi-omv.com/oauth/authorize?"))
        XCTAssertTrue(asURL.absoluteString.contains("code_challenge_method=S256"))
        XCTAssertFalse(asURL.absoluteString.contains("client_secret"))
    }

    func testRejectsIssuerMismatch() throws {
        let doc = try XCTUnwrap(OAuthDiscoveryDocument.fromJsonText(Self.oidcFixture))
        XCTAssertEqual(
            doc.validate("https://other.example"),
            .invalidDiscovery("issuer mismatch: expected https://other.example, got https://idp.mi-omv.com")
        )
    }

    func testRejectsTrailingSlashIssuerAsMismatch() throws {
        let doc = try XCTUnwrap(OAuthDiscoveryDocument.fromJsonText(Self.oidcFixture))
        XCTAssertNotNil(doc.validate("https://idp.mi-omv.com/"),
                        "issuer comparison must be exact — no trailing-slash tolerance")
    }

    func testRejectsMissingS256() {
        let doc = OAuthDiscoveryDocument(
            issuer: "https://auth.example",
            authorizationEndpoint: "https://auth.example/authorize",
            tokenEndpoint: "https://auth.example/token",
            codeChallengeMethodsSupported: ["plain"]
        )
        XCTAssertEqual(doc.validate(), .invalidDiscovery("code_challenge_methods_supported does not include S256"))
    }

    func testRejectsMissingCodeResponseType() {
        let doc = OAuthDiscoveryDocument(
            issuer: "https://auth.example",
            authorizationEndpoint: "https://auth.example/authorize",
            tokenEndpoint: "https://auth.example/token",
            responseTypesSupported: ["token"]
        )
        XCTAssertEqual(doc.validate(), .invalidDiscovery("response_types_supported does not include code"))
    }

    func testRejectsMissingAuthorizationCodeGrant() {
        let doc = OAuthDiscoveryDocument(
            issuer: "https://auth.example",
            authorizationEndpoint: "https://auth.example/authorize",
            tokenEndpoint: "https://auth.example/token",
            grantTypesSupported: ["client_credentials"]
        )
        XCTAssertEqual(doc.validate(), .invalidDiscovery("grant_types_supported does not include authorization_code"))
    }

    func testRejectsNonHTTPSAndForeignHostEndpoints() {
        let nonHTTPS = OAuthDiscoveryDocument(
            issuer: "https://auth.example",
            authorizationEndpoint: "http://auth.example/authorize",
            tokenEndpoint: "https://auth.example/token"
        )
        XCTAssertEqual(nonHTTPS.validate(), .invalidDiscovery("authorization_endpoint must use HTTPS"))

        let foreignHost = OAuthDiscoveryDocument(
            issuer: "https://auth.example",
            authorizationEndpoint: "https://auth.example/authorize",
            tokenEndpoint: "https://evil.example/token"
        )
        XCTAssertEqual(
            foreignHost.validate("https://auth.example"),
            .invalidDiscovery("token_endpoint host (evil.example) does not match issuer host (auth.example)")
        )
    }

    func testRejectsMissingRequiredEndpoints() {
        XCTAssertNotNil(OAuthDiscoveryDocument(
            issuer: "", authorizationEndpoint: "https://a.example/x", tokenEndpoint: "https://a.example/t"
        ).validate())
        XCTAssertNotNil(OAuthDiscoveryDocument(
            issuer: "https://a.example", authorizationEndpoint: nil, tokenEndpoint: "https://a.example/t"
        ).validate())
        XCTAssertNotNil(OAuthDiscoveryDocument(
            issuer: "https://a.example", authorizationEndpoint: "https://a.example/x", tokenEndpoint: ""
        ).validate())
    }
}
