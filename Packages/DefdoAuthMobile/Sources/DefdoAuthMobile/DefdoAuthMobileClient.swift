import Foundation

/// Opens the system browser / auth session for the authorization request.
public protocol BrowserAuthAdapter: Sendable {
    func openAuthorizationURL(_ url: URL) async
}

/// Public PKCE OAuth client for Defdo mobile apps.
///
/// Contract mirror of the Android `dev.defdo.mobile.auth.DefdoAuthMobileClient`:
/// authorization-code + PKCE (S256) with `token_endpoint_auth_method: none` —
/// no client secret exists in the app. Endpoints always come from the injected
/// (validated) discovery document.
public protocol DefdoAuthMobileClient: Sendable {
    func startLogin(_ request: LoginRequest) async -> LoginResult
    func handleCallback(_ callbackURL: URL, expectedState: String, expectedRedirectURI: String) async -> LoginResult
    func currentSession() async -> AuthSession?
    func refresh(_ session: AuthSession) async -> LoginResult
    func revoke(_ session: AuthSession) async -> LoginResult
}

public actor DefdoAuthMobileClientImpl: DefdoAuthMobileClient {
    private let config: AuthConfig
    private let discovery: OAuthDiscoveryDocument
    private let browserAdapter: BrowserAuthAdapter
    private let tokenStore: TokenStore
    private let tokenTransport: TokenHttpTransport

    private var pendingVerifiers: [String: String] = [:]

    public init(
        config: AuthConfig,
        discovery: OAuthDiscoveryDocument,
        browserAdapter: BrowserAuthAdapter,
        tokenStore: TokenStore,
        tokenTransport: TokenHttpTransport
    ) {
        self.config = config
        self.discovery = discovery
        self.browserAdapter = browserAdapter
        self.tokenStore = tokenStore
        self.tokenTransport = tokenTransport
    }

    public func startLogin(_ request: LoginRequest) async -> LoginResult {
        guard let endpoint = discovery.authorizationEndpoint else {
            return .failed(.invalidDiscovery("missing authorization_endpoint"))
        }
        let url: URL
        do {
            url = try AuthorizationRequestBuilder.url(authorizationEndpoint: endpoint, request: request)
        } catch let error as AuthError {
            return .failed(error)
        } catch {
            return .failed(.oauthError("authorize_url_failed"))
        }

        pendingVerifiers[request.state] = request.codeVerifier
        await browserAdapter.openAuthorizationURL(url)
        return .pendingBrowser(url)
    }

    public func handleCallback(
        _ callbackURL: URL,
        expectedState: String,
        expectedRedirectURI: String
    ) async -> LoginResult {
        guard let codeVerifier = pendingVerifiers.removeValue(forKey: expectedState) else {
            return .failed(.invalidCallback("no pending login for state"))
        }

        let code: String
        switch CallbackValidator.validate(callbackURL, expectedState: expectedState, expectedRedirectURI: expectedRedirectURI) {
        case .success(let value): code = value
        case .failure(let error): return .failed(error)
        }

        guard let tokenEndpoint = discovery.tokenEndpoint else {
            return .failed(.invalidDiscovery("missing token_endpoint"))
        }

        let params = [
            "grant_type": "authorization_code",
            "client_id": config.clientID,
            "redirect_uri": config.redirectURI,
            "code": code,
            "code_verifier": codeVerifier
        ]

        switch await tokenTransport.exchangeCode(tokenEndpoint: tokenEndpoint, params: params) {
        case .success(let response): return onTokenResponse(response)
        case .failure(let error): return .failed(error)
        }
    }

    public func currentSession() async -> AuthSession? {
        tokenStore.read()
    }

    public func refresh(_ session: AuthSession) async -> LoginResult {
        guard let tokenEndpoint = discovery.tokenEndpoint else {
            return .failed(.invalidDiscovery("missing token_endpoint"))
        }
        guard let refreshToken = session.refreshToken, !refreshToken.isEmpty else {
            return .failed(.requiresLogin)
        }

        let params = [
            "grant_type": "refresh_token",
            "client_id": config.clientID,
            "refresh_token": refreshToken
        ]

        switch await tokenTransport.refreshToken(tokenEndpoint: tokenEndpoint, params: params) {
        case .failure(let error):
            return .failed(error)
        case .success(let response):
            if response.requiresLogin {
                tokenStore.clear()
                return .failed(.requiresLogin)
            }
            guard response.isSuccess else {
                let error = response.error.map(AuthError.normalize) ?? .oauthError("refresh_failed")
                return .failed(error)
            }
            guard response.isAcceptableTokenType else {
                tokenStore.clear()
                return .failed(.oauthError("unsupported_token_type"))
            }
            let refreshed = AuthSession(
                accessToken: response.accessToken ?? "",
                refreshToken: response.refreshToken ?? session.refreshToken,
                idToken: response.idToken ?? session.idToken,
                expiresInSeconds: response.expiresIn ?? session.expiresInSeconds,
                scope: response.scope ?? session.scope,
                tokenType: response.tokenType ?? session.tokenType
            )
            tokenStore.write(refreshed)
            return .authenticated(refreshed)
        }
    }

    public func revoke(_ session: AuthSession) async -> LoginResult {
        if let revocationEndpoint = discovery.revocationEndpoint,
           let refreshToken = session.refreshToken, !refreshToken.isEmpty {
            let params = [
                "token": refreshToken,
                "token_type_hint": "refresh_token",
                "client_id": config.clientID
            ]
            _ = await tokenTransport.revokeToken(revocationEndpoint: revocationEndpoint, params: params)
        }
        tokenStore.clear()
        return .loggedOut
    }

    private func onTokenResponse(_ response: TokenResponse) -> LoginResult {
        guard response.isSuccess else {
            let error = response.error.map(AuthError.normalize) ?? .oauthError("token_failed")
            return .failed(error)
        }
        guard response.isAcceptableTokenType else {
            return .failed(.oauthError("unsupported_token_type"))
        }
        let session = AuthSession(
            accessToken: response.accessToken ?? "",
            refreshToken: response.refreshToken,
            idToken: response.idToken,
            expiresInSeconds: response.expiresIn ?? 3600,
            scope: response.scope ?? config.scopes.joined(separator: " "),
            tokenType: response.tokenType ?? "Bearer"
        )
        tokenStore.write(session)
        return .authenticated(session)
    }
}
