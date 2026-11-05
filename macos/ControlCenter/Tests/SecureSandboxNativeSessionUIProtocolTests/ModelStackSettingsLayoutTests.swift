import Foundation
import Testing

@Suite struct ModelStackSettingsLayoutTests {
    @Test func executionModeSelectorIsResponsiveAndKeepsFullMeaning() throws {
        let source = try modelStackSettingsSource()

        #expect(source.contains("ViewThatFits(in: .horizontal)"))
        #expect(source.contains("Text(\"Brokered\")"))
        #expect(source.contains("Text(\"Native Vendor\")"))
        #expect(source.contains("Brokered Provider Profile"))
        #expect(source.contains("Native Vendor Harness + Model Stack"))
        #expect(source.contains("Native Vendor Harness and Model Stack"))
        #expect(source.contains(".frame(maxWidth: .infinity)"))
        #expect(!source.contains(".frame(width: 430)"))
    }

    private func modelStackSettingsSource() throws -> String {
        let packageRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(
            contentsOf: packageRoot.appendingPathComponent(
                "Sources/SecureSandboxControlCenter/Views/ModelStackSettingsView.swift"
            ),
            encoding: .utf8
        )
    }
}
