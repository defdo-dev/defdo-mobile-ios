/// Theme rendering mode. Raw values match the `mode` field of the theme
/// contract (shared-contracts/theme/theme_token_schema.json).
public enum ThemeMode: String, Sendable, Equatable, Hashable, CaseIterable {
    case light
    case dark
}
