import AppKit
import SwiftUI

@main
struct ControlCenterApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var store = CatalogStore()

    var body: some Scene {
        WindowGroup("SecureSandbox", id: "main") {
            ContentView(store: store)
                .frame(minWidth: 760, minHeight: 520)
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Refresh Catalogs") { Task { await store.refresh() } }
                    .keyboardShortcut("r", modifiers: .command)
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
