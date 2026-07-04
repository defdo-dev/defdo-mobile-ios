import Foundation

/// Static client configuration. `clientID` is the only brand/app authority the
/// app asserts, and only to defdo_auth. Public PKCE client: no client secret
/// exists anywhere in this library.
public struct AuthConfig: Sendable {
    public let clientID: String
    public let discoveryURL: URL
    public let redirectURI: String
    public let scopes: [String]
    public let useNonce: Bool

    public init(
        clientID: String,
        discoveryURL: URL,
        redirectURI: String,
        scopes: [String],
        useNonce: Bool = true
    ) {
        self.clientID = clientID
        self.discoveryURL = discoveryURL
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.useNonce = useNonce
    }
}
