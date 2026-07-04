import XCTest
@testable import DefdoThemeMobile

final class ThemeTokenValidatorTests: XCTestCase {
    private func validTokens(mode: ThemeMode = .light) -> ThemeTokens {
        var tokens: [String: String] = [:]
        for name in ThemeTokenValidator.requiredTokens {
            tokens[name] = "#145DCC"
        }
        return ThemeTokens(schemaVersion: 1, themeVersion: "t-1", mode: mode, tokens: tokens)
    }

    func testValidThemePasses() {
        XCTAssertNil(ThemeTokenValidator.validate(validTokens()))
    }

    func testMissingRequiredTokenFails() {
        var tokens = validTokens().tokens
        tokens.removeValue(forKey: "color.text.primary")
        let theme = ThemeTokens(schemaVersion: 1, themeVersion: "t-1", mode: .light, tokens: tokens)
        XCTAssertEqual(
            ThemeTokenValidator.validate(theme),
            .missingTokens(["color.text.primary"])
        )
    }

    func testInvalidColorFails() {
        var tokens = validTokens().tokens
        tokens["color.text.muted"] = "not-a-color"
        let theme = ThemeTokens(schemaVersion: 1, themeVersion: "t-1", mode: .dark, tokens: tokens)
        XCTAssertEqual(
            ThemeTokenValidator.validate(theme),
            .invalidColor(["color.text.muted"])
        )
    }

    func testShortHexAndMissingHashFail() {
        for bad in ["#FFF", "145DCC", "#145DC", "#145DCCFF"] {
            var tokens = validTokens().tokens
            tokens["color.background.primary"] = bad
            let theme = ThemeTokens(schemaVersion: 1, themeVersion: "t-1", mode: .light, tokens: tokens)
            XCTAssertNotNil(ThemeTokenValidator.validate(theme), "expected \(bad) to be rejected")
        }
    }

    func testModeRawValuesMatchContract() {
        XCTAssertEqual(ThemeMode.light.rawValue, "light")
        XCTAssertEqual(ThemeMode.dark.rawValue, "dark")
    }
}
