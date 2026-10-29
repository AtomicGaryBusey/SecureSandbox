import AppKit
import SwiftUI

@main
struct ControlCenterApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.openWindow) private var openWindow
    @State private var store = CatalogStore()
    @State private var navigation = NavigationState()

    var body: some Scene {
        WindowGroup("SecureSandbox", id: "main") {
            ContentView(store: store, navigation: navigation)
                .frame(minWidth: 760, minHeight: 520)
        }
        .defaultLaunchBehavior(.presented)
        WindowGroup("Session Terminal", id: "terminal", for: String.self) { $sessionID in
            TerminalWindowView(sessionID: sessionID ?? "")
                .frame(minWidth: 700, minHeight: 460)
        }
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)
        WindowGroup("Direct Administrator Shell", id: "breakglass", for: String.self) { $destination in
            BreakGlassTerminalView(destination: destination ?? "")
                .frame(minWidth: 700, minHeight: 460)
        }
        .defaultLaunchBehavior(.suppressed)
        .restorationBehavior(.disabled)
        .commands {
            CommandGroup(after: .newItem) {
                Button("Refresh Catalogs") { Task { await store.refresh() } }
                    .keyboardShortcut("r", modifiers: .command)
            }
            CommandMenu("Navigate") {
                Button("Show Sessions") { navigation.section = .sessions }
                    .keyboardShortcut("1", modifiers: [.command, .option])
                Button("Search Sessions") {
                    navigation.section = .sessions
                    navigation.searchRequest += 1
                }
                .keyboardShortcut("f", modifiers: .command)
                Button("New Analysis") {
                    openWindow(id: "terminal", value: "new")
                }
                .keyboardShortcut("n", modifiers: .command)
                Button("Open Selected Session Terminal") {
                    if let selected = navigation.selectedSessionID,
                       store.sessions.contains(where: { $0.id == selected }) {
                        openWindow(id: "terminal", value: selected)
                    }
                }
                .keyboardShortcut("t", modifiers: [.command, .shift])
                .disabled(navigation.section != .sessions
                          || !store.sessions.contains(where: { $0.id == navigation.selectedSessionID }))
            }
        }

        Settings {
            SettingsView()
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}
