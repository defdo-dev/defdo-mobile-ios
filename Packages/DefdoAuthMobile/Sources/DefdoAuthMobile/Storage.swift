import Foundation
#if canImport(Security)
import Security
#endif

/// Raw secure byte storage. Production adapter is Keychain-backed; tests use
/// the in-memory adapter.
public protocol SecureStorageAdapter: Sendable {
    func get(_ key: String) -> Data?
    func put(_ key: String, value: Data)
    func delete(_ key: String)
}

public final class InMemorySecureStorageAdapter: SecureStorageAdapter, @unchecked Sendable {
    private var store: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func get(_ key: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return store[key]
    }

    public func put(_ key: String, value: Data) {
        lock.lock(); defer { lock.unlock() }
        store[key] = value
    }

    public func delete(_ key: String) {
        lock.lock(); defer { lock.unlock() }
        store.removeValue(forKey: key)
    }
}

#if canImport(Security)
/// Keychain-backed storage (kSecClassGenericPassword). Tokens never touch
/// UserDefaults or files.
public struct KeychainSecureStorageAdapter: SecureStorageAdapter {
    private let service: String

    public init(service: String = "dev.defdo.mobile.auth") {
        self.service = service
    }

    public func get(_ key: String) -> Data? {
        var query = baseQuery(key)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    public func put(_ key: String, value: Data) {
        var query = baseQuery(key)
        let update: [String: Any] = [kSecValueData as String: value]

        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            query[kSecValueData as String] = value
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(query as CFDictionary, nil)
        }
    }

    public func delete(_ key: String) {
        SecItemDelete(baseQuery(key) as CFDictionary)
    }

    private func baseQuery(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
    }
}
#endif

public protocol TokenStore: Sendable {
    func read() -> AuthSession?
    func write(_ session: AuthSession)
    func clear()
}

/// Versioned JSON envelope over a SecureStorageAdapter. Schema matches the
/// Android SecureTokenStore (schema_version 1) so envelopes stay auditable
/// across platforms.
public struct SecureTokenStore: TokenStore {
    private static let key = "defdo_auth_session"
    private static let schemaVersion = 1

    private let storage: SecureStorageAdapter

    public init(storage: SecureStorageAdapter) {
        self.storage = storage
    }

    public func read() -> AuthSession? {
        guard let data = storage.get(Self.key),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (json["schema_version"] as? Int) == Self.schemaVersion,
              let accessToken = json["access_token"] as? String else {
            return nil
        }
        return AuthSession(
            accessToken: accessToken,
            refreshToken: json["refresh_token"] as? String,
            idToken: json["id_token"] as? String,
            expiresInSeconds: (json["expires_in"] as? NSNumber)?.int64Value ?? 0,
            scope: json["scope"] as? String ?? "",
            tokenType: json["token_type"] as? String ?? "Bearer"
        )
    }

    public func write(_ session: AuthSession) {
        var envelope: [String: Any] = [
            "schema_version": Self.schemaVersion,
            "access_token": session.accessToken,
            "token_type": session.tokenType,
            "expires_in": session.expiresInSeconds,
            "captured_at": Int64(Date().timeIntervalSince1970),
            "scope": session.scope
        ]
        if let refreshToken = session.refreshToken { envelope["refresh_token"] = refreshToken }
        if let idToken = session.idToken { envelope["id_token"] = idToken }

        if let data = try? JSONSerialization.data(withJSONObject: envelope) {
            storage.put(Self.key, value: data)
        }
    }

    public func clear() {
        storage.delete(Self.key)
    }
}
