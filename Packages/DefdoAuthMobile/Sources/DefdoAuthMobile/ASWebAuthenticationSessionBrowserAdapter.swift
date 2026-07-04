#if canImport(AuthenticationServices)
import Foundation
import AuthenticationServices

/// BrowserAuthAdapter backed by ASWebAuthenticationSession. The callback URL
/// itself is delivered to the app through its redirect handling (onOpenURL /
/// scene delegate), not through this adapter.
@MainActor
public final class ASWebAuthenticationSessionBrowserAdapter: BrowserAuthAdapter {
    private let callbackScheme: String
    private let contextProvider: ASWebAuthenticationPresentationContextProviding

    public init(
        callbackScheme: String,
        contextProvider: ASWebAuthenticationPresentationContextProviding
    ) {
        self.callbackScheme = callbackScheme
        self.contextProvider = contextProvider
    }

    public nonisolated func openAuthorizationURL(_ url: URL) async {
        await MainActor.run {
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: callbackScheme
            ) { _, _ in }
            session.presentationContextProvider = contextProvider
            session.start()
        }
    }
}
#endif
