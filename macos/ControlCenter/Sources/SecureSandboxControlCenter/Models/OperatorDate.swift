import Foundation

enum OperatorDate {
    static func display(_ value: String) -> String {
        let standard = ISO8601DateFormatter()
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        guard let date = standard.date(from: value) ?? fractional.date(from: value) else { return value }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}
