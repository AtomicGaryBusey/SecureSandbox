import AppKit
import SwiftUI

@main
struct ControlCenterApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var store = CatalogStore()
    @AppStorage("appearancePreference") private var appearancePreference = AppAppearance.system.rawValue

    var body: some Scene {
        WindowGroup("SecureSandbox", id: "main") {
            ContentView(store: store)
                .frame(minWidth: 760, minHeight: 520)
                .preferredColorScheme(AppAppearance.colorScheme(for: appearancePreference))
        }
        .defaultLaunchBehavior(.presented)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Refresh Catalogs") { Task { await store.refresh() } }
                    .keyboardShortcut("r", modifiers: .command)
            }
            NavigationCommands(store: store)
        }
        WindowGroup("Session Terminal", id: "terminal", for: String.self) { $sessionID in
            TerminalWindowView(sessionID: sessionID ?? "")
                .frame(minWidth: 700, minHeight: 460)
                .preferredColorScheme(AppAppearance.colorScheme(for: appearancePreference))
        }
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)
        .commandsRemoved()
        WindowGroup("Direct Administrator Shell", id: "breakglass", for: String.self) { $destination in
            BreakGlassTerminalView(destination: destination ?? "")
                .frame(minWidth: 700, minHeight: 460)
                .preferredColorScheme(AppAppearance.colorScheme(for: appearancePreference))
        }
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)
        .commandsRemoved()

        Settings {
            SettingsView()
        }
    }
}

private struct NavigationCommands: Commands {
    let store: CatalogStore
    @Environment(\.openWindow) private var openWindow
    @FocusedValue(NavigationState.self) private var navigation

    var body: some Commands {
        CommandMenu("Navigate") {
            Button("Show Sessions") { navigation?.section = .sessions }
                .keyboardShortcut("1", modifiers: [.command, .option])
                .disabled(navigation == nil)
            Button("Search Sessions") {
                navigation?.section = .sessions
                navigation?.searchRequest += 1
            }
            .keyboardShortcut("f", modifiers: .command)
            .disabled(navigation == nil)
            Button("New Analysis") { openWindow(id: "terminal", value: "new") }
                .keyboardShortcut("n", modifiers: .command)
            Button("Open Selected Session Terminal") {
                if let selected = navigation?.selectedSessionID,
                   store.sessions.contains(where: { $0.id == selected }) {
                    openWindow(id: "terminal", value: selected)
                }
            }
            .keyboardShortcut("t", modifiers: [.command, .shift])
            .disabled(navigation?.section != .sessions
                      || !store.sessions.contains(where: { $0.id == navigation?.selectedSessionID }))
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}
