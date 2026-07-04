import XCTest
@testable import DefdoAuthMobile

final class PKCEAndCallbackTests: XCTestCase {
    // RFC 7636 appendix B vector, mirrored in
    // shared-contracts/auth/pkce.test_vectors.json.
    func testS256ChallengeMatchesSharedVector() {
        XCTAssertEqual(
            PKCE.s256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        )
    }

    func testGeneratedVerifierIsValidAndUnique() {
        let first = PKCE.generateVerifier()
        let second = PKCE.generateVerifier()
        XCTAssertTrue(PKCE.isValidVerifier(first))
        XCTAssertTrue(PKCE.isValidVerifier(second))
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(first.count, 43)
    }

    func testInvalidVerifiersRejected() {
        XCTAssertFalse(PKCE.isValidVerifier("short"))
        XCTAssertFalse(PKCE.isValidVerifier(String(repeating: "a", count: 129)))
        XCTAssertFalse(PKCE.isValidVerifier(String(repeating: "a", count: 42) + "!"))
    }

    private let redirect = "https://login.defdo-telecom.example/mobile/oauth/callback"

    func testCallbackAcceptsExactMatchAndReturnsCode() throws {
        let url = URL(string: "\(redirect)?code=abc123&state=st-1")!
        let result = CallbackValidator.validate(url, expectedState: "st-1", expectedRedirectURI: redirect)
        XCTAssertEqual(try result.get(), "abc123")
    }

    func testCallbackRejectsWrongHostSchemePathAndState() {
        let cases: [(String, String)] = [
            ("https://evil.example/mobile/oauth/callback?code=c&state=st-1", "wrong host"),
            ("http://login.defdo-telecom.example/mobile/oauth/callback?code=c&state=st-1", "wrong scheme"),
            ("https://login.defdo-telecom.example/other?code=c&state=st-1", "wrong path"),
            ("\(redirect)?code=c&state=other", "wrong state"),
            ("\(redirect)?state=st-1", "missing code"),
            ("\(redirect)?code=c&code=d&state=st-1", "duplicated params"),
            ("\(redirect)?error=access_denied&state=st-1", "error callback")
        ]
        for (raw, label) in cases {
            let url = URL(string: raw)!
            let result = CallbackValidator.validate(url, expectedState: "st-1", expectedRedirectURI: redirect)
            if case .success = result {
                XCTFail("expected rejection for \(label): \(raw)")
            }
        }
    }

    func testSecureTokenStoreRoundtrip() {
        let store = SecureTokenStore(storage: InMemorySecureStorageAdapter())
        let session = AuthSession(
            accessToken: "at-1",
            refreshToken: "rt-1",
            idToken: nil,
            expiresInSeconds: 3600,
            scope: "openid profile offline_access"
        )
        store.write(session)
        XCTAssertEqual(store.read(), session)
        store.clear()
        XCTAssertNil(store.read())
    }
}
