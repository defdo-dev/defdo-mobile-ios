import Foundation

public enum ThemeValidationError: Error, Sendable, Equatable {
    case missingTokens([String])
    case invalidColor([String])
}

/// Validates a theme document against the shared contract: every required
/// token present, every value a #RRGGBB color. Mirrors the Android
/// `ThemeTokenValidator`.
public enum ThemeTokenValidator {
    public static let requiredTokens: [String] = [
        "color.background.primary",
        "color.background.surface",
        "color.text.primary",
        "color.text.muted",
        "color.action.primary.background",
        "color.action.primary.text",
        "color.status.success.background",
        "color.status.warning.text",
        "color.input.border.default",
        "color.input.border.focused"
    ]

    public static func validate(_ tokens: ThemeTokens) -> ThemeValidationError? {
        let missing = requiredTokens.filter { tokens.tokens[$0] == nil }
        if !missing.isEmpty { return .missingTokens(missing) }

        let invalid = tokens.tokens
            .filter { !isValidColor($0.value) }
            .keys
            .sorted()
        if !invalid.isEmpty { return .invalidColor(invalid) }

        return nil
    }

    private static func isValidColor(_ value: String) -> Bool {
        guard value.count == 7, value.hasPrefix("#") else { return false }
        return value.dropFirst().allSatisfy { $0.isHexDigit }
    }
}
