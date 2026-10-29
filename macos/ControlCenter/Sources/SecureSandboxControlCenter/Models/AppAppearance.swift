import SwiftUI

enum AppAppearance: String, CaseIterable, Identifiable {
    case system, light, dark

    var id: String { rawValue }

    var title: String {
        switch self {
        case .system: "System"
        case .light: "Light"
        case .dark: "Dark"
        }
    }

    static func colorScheme(for preference: String) -> ColorScheme? {
        switch AppAppearance(rawValue: preference) ?? .system {
        case .system: nil
        case .light: .light
        case .dark: .dark
        }
    }
}
