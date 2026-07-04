import Foundation

/// One login attempt: config + per-attempt state, nonce, and PKCE verifier.
public struct LoginRequest: Sendable {
    public let config: AuthConfig
    public let state: String
    public let nonce: String?
    public let codeVerifier: String

    public init(config: AuthConfig, state: String, nonce: String?, codeVerifier: String) {
        self.config = config
        self.state = state
        self.nonce = nonce
        self.codeVerifier = codeVerifier
    }
}

public enum LoginResult: Sendable {
    case pendingBrowser(URL)
    case authenticated(AuthSession)
    case failed(AuthError)
    case loggedOut
}

/// Persisted session material. Stored only via SecureTokenStore (Keychain on
/// device) — never printed, never in UserDefaults.
public struct AuthSession: Sendable, Equatable {
    public let accessToken: String
    public let refreshToken: String?
    public let idToken: String?
    public let expiresInSeconds: Int64
    public let scope: String
    public let tokenType: String

    public init(
        accessToken: String,
        refreshToken: String?,
        idToken: String?,
        expiresInSeconds: Int64,
        scope: String,
        tokenType: String = "Bearer"
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.expiresInSeconds = expiresInSeconds
        self.scope = scope
        self.tokenType = tokenType
    }
}

public struct TokenResponse: Sendable {
    public let accessToken: String?
    public let refreshToken: String?
    public let idToken: String?
    public let tokenType: String?
    public let expiresIn: Int64?
    public let scope: String?
    public let error: String?

    public init(
        accessToken: String?,
        refreshToken: String?,
        idToken: String?,
        tokenType: String?,
        expiresIn: Int64?,
        scope: String?,
        error: String?
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.scope = scope
        self.error = error
    }

    public var isSuccess: Bool {
        !(accessToken ?? "").isEmpty && (error ?? "").isEmpty
    }

    /// Bearer-only contract; a missing token_type is tolerated.
    public var isAcceptableTokenType: Bool {
        tokenType == nil || tokenType?.lowercased() == "bearer"
    }

    public static func parse(_ map: [String: Any]) -> TokenResponse {
        TokenResponse(
            accessToken: map["access_token"] as? String,
            refreshToken: map["refresh_token"] as? String,
            idToken: map["id_token"] as? String,
            tokenType: map["token_type"] as? String,
            expiresIn: (map["expires_in"] as? NSNumber)?.int64Value,
            scope: map["scope"] as? String,
            error: map["error"] as? String
        )
    }
}

public struct RefreshResponse: Sendable {
    public let accessToken: String?
    public let refreshToken: String?
    public let idToken: String?
    public let tokenType: String?
    public let expiresIn: Int64?
    public let scope: String?
    public let error: String?

    public init(
        accessToken: String?,
        refreshToken: String?,
        idToken: String?,
        tokenType: String?,
        expiresIn: Int64?,
        scope: String?,
        error: String?
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.scope = scope
        self.error = error
    }

    public var isSuccess: Bool {
        !(accessToken ?? "").isEmpty && (error ?? "").isEmpty
    }

    public var requiresLogin: Bool { error == "invalid_grant" }

    public var isAcceptableTokenType: Bool {
        tokenType == nil || tokenType?.lowercased() == "bearer"
    }

    public static func parse(_ map: [String: Any]) -> RefreshResponse {
        RefreshResponse(
            accessToken: map["access_token"] as? String,
            refreshToken: map["refresh_token"] as? String,
            idToken: map["id_token"] as? String,
            tokenType: map["token_type"] as? String,
            expiresIn: (map["expires_in"] as? NSNumber)?.int64Value,
            scope: map["scope"] as? String,
            error: map["error"] as? String
        )
    }
}
