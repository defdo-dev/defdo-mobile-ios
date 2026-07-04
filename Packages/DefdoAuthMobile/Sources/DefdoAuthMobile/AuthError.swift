/// Normalized auth library errors. Mirrors the Android
/// `dev.defdo.mobile.auth.AuthError` sealed class.
public enum AuthError: Error, Sendable, Equatable {
    case invalidDiscovery(String)
    case invalidCallback(String)
    case oauthError(String)
    case requiresLogin
    case retryable

    /// Maps raw OAuth error codes to normalized errors, matching the shared
    /// contract in shared-contracts/auth/auth_error_normalization.json.
    public static func normalize(_ error: String) -> AuthError {
        switch error {
        case "invalid_request": return .oauthError("invalid_request")
        case "invalid_grant": return .requiresLogin
        case "temporarily_unavailable": return .retryable
        case "access_denied": return .oauthError("user_cancelled")
        default: return .oauthError(error)
        }
    }
}
