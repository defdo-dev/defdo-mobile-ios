import Foundation
import CryptoKit

/// RFC 7636 PKCE helpers. Only S256 is supported (`plain` is never used).
public enum PKCE {
    /// 32 random bytes, base64url without padding — 43-char verifier.
    public static func generateVerifier() -> String {
        var rng = SystemRandomNumberGenerator()
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in bytes.indices {
            bytes[i] = UInt8.random(in: .min ... .max, using: &rng)
        }
        return base64URL(Data(bytes))
    }

    public static func isValidVerifier(_ verifier: String) -> Bool {
        guard (43...128).contains(verifier.count) else { return false }
        let allowed = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-")
        return verifier.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    /// BASE64URL(SHA256(ASCII(verifier))) per RFC 7636 §4.2.
    public static func s256Challenge(_ verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return base64URL(Data(digest))
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
