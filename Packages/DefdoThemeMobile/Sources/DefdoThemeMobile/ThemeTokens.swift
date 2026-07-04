/// A resolved theme document as served by GET /mobile/theme.
///
/// Mirrors the Android `dev.defdo.mobile.theme.ThemeTokens` data class and the
/// shared theme contract: a flat map of token name -> #RRGGBB color string.
public struct ThemeTokens: Sendable, Equatable {
    public let schemaVersion: Int
    public let themeVersion: String
    public let mode: ThemeMode
    public let tokens: [String: String]

    public init(schemaVersion: Int, themeVersion: String, mode: ThemeMode, tokens: [String: String]) {
        self.schemaVersion = schemaVersion
        self.themeVersion = themeVersion
        self.mode = mode
        self.tokens = tokens
    }
}
