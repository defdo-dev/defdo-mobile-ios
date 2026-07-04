import Foundation

/// Validates the OAuth redirect callback: exact scheme/host/port/path match
/// against the registered redirect URI, no duplicated parameters, state match.
/// Returns the authorization code on success.
public enum CallbackValidator {
    public static func validate(
        _ callbackURL: URL,
        expectedState: String,
        expectedRedirectURI: String
    ) -> Result<String, AuthError> {
        guard let expected = URL(string: expectedRedirectURI) else {
            return .failure(.invalidCallback("invalid expected redirect URI"))
        }

        if callbackURL.scheme != expected.scheme {
            return .failure(.invalidCallback("wrong redirect URI scheme"))
        }
        if callbackURL.host != expected.host {
            return .failure(.invalidCallback("wrong redirect URI host"))
        }
        if callbackURL.port != expected.port {
            return .failure(.invalidCallback("wrong redirect URI port"))
        }
        if normalizedPath(callbackURL) != normalizedPath(expected) {
            return .failure(.invalidCallback("wrong redirect URI path"))
        }

        guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let items = components.queryItems, !items.isEmpty else {
            return .failure(.invalidCallback("missing query"))
        }

        let names = items.map(\.name)
        if names.count != Set(names).count {
            return .failure(.invalidCallback("suspicious duplicated params"))
        }

        var params: [String: String] = [:]
        for item in items {
            params[item.name] = item.value ?? ""
        }

        if let error = params["error"] {
            return .failure(.invalidCallback("oauth error callback: \(error)"))
        }
        guard let code = params["code"], !code.isEmpty else {
            return .failure(.invalidCallback("missing code"))
        }
        guard let state = params["state"] else {
            return .failure(.invalidCallback("missing state"))
        }
        if state != expectedState {
            return .failure(.invalidCallback("mismatched state"))
        }

        return .success(code)
    }

    private static func normalizedPath(_ url: URL) -> String {
        let path = url.path
        return path.isEmpty ? "" : path
    }
}
