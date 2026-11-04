import AppKit
import Foundation
import SwiftTerm

public enum NativeTerminalSecurityPolicy {
    public static let maximumOscBytes = 64 * 1_024
    public static let scrollbackLines = 500

    public static let options = TerminalOptions(
        cols: 80,
        rows: 25,
        convertEol: false,
        termName: "xterm-256color",
        cursorStyle: .blinkBlock,
        screenReaderMode: false,
        scrollback: scrollbackLines,
        tabStopWidth: 8,
        enableSixelReported: false,
        kittyGraphics: KittyGraphicsConfiguration(
            storageLimitBytesPerScreen: 0,
            localMediaPolicy: [],
            trustedTemporaryDirectory: nil
        ),
        ansi256PaletteStrategy: .base16Lab,
        regionalIndicatorWidth: .wide,
        initialBidiState: .default,
        maximumBidiParagraphRows: 256,
        initialBidiArrowKeySwap: false,
        featureReport: nil,
        maximumOscBytes: maximumOscBytes,
        kittyClipboardPolicy: [],
        kittyClipboardWriteLimitBytes:
            TerminalOptions.minimumKittyClipboardWriteLimitBytes,
        kittyClipboardMaximumRepresentations: 1,
        kittyClipboardMaximumAliases: 0,
        enableOsc8Hyperlinks: false
    )
}

/// Drops device-control and application-program control strings before they
/// reach SwiftTerm.  Sixel and Kitty graphics are not part of this protected
/// text-only surface, and dropping them here keeps hostile unterminated strings
/// from reaching the emulator's much larger protocol accumulation limits.
public struct NativeTerminalOutputFilter: Sendable {
    private enum State: Sendable, Equatable {
        case ground
        case escape
        case droppingControl
        case droppingControlEscape
    }

    private var state: State = .ground

    public init() {}

    public var isDroppingControlString: Bool {
        state == .droppingControl || state == .droppingControlEscape
    }

    public mutating func filter(_ data: Data) -> Data {
        var result = Data()
        result.reserveCapacity(data.count)
        for byte in data {
            switch state {
            case .ground:
                switch byte {
                case 0x1b:
                    state = .escape
                case 0x90, 0x9f: // C1 DCS / APC
                    state = .droppingControl
                default:
                    result.append(byte)
                }
            case .escape:
                if byte == 0x50 || byte == 0x5f { // ESC P / ESC _
                    state = .droppingControl
                } else {
                    result.append(0x1b)
                    if byte == 0x1b {
                        state = .escape
                    } else {
                        result.append(byte)
                        state = .ground
                    }
                }
            case .droppingControl:
                if byte == 0x1b {
                    state = .droppingControlEscape
                } else if byte == 0x9c { // C1 ST
                    state = .ground
                }
            case .droppingControlEscape:
                if byte == 0x5c { // ESC \
                    state = .ground
                } else if byte != 0x1b {
                    state = .droppingControl
                }
            }
        }
        return result
    }
}

public final class NativeClaudeSecureTerminalView: TerminalView {
    public convenience init(secureFrame: CGRect) {
        self.init(
            frame: secureFrame,
            font: nil,
            options: NativeTerminalSecurityPolicy.options
        )
        allowMouseReporting = false
        linkReporting = .none
    }

    /// Terminal parser replies are derived from untrusted output.  They must
    /// never enter the authenticated remote-input channel; actual keyboard
    /// input continues through TerminalView.send(data:) and its view delegate.
    nonisolated public override func send(
        source: Terminal, data: ArraySlice<UInt8>
    ) {}

    @objc public override func paste(_ sender: Any) {}
    @objc public override func copy(_ sender: Any) {}

    public override func validateUserInterfaceItem(
        _ item: NSValidatedUserInterfaceItem
    ) -> Bool {
        switch item.action {
        case #selector(paste(_:)), #selector(copy(_:)),
             #selector(performFindPanelAction(_:)),
             #selector(performTextFinderAction(_:)):
            false
        default:
            super.validateUserInterfaceItem(item)
        }
    }

    @objc public override func performFindPanelAction(_ sender: Any?) {}
    public override func performTextFinderAction(_ sender: Any?) {}
}
