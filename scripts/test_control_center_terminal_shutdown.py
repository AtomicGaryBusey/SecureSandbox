#!/usr/bin/env python3
"""Static contract tests for Control Center terminal teardown authority."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (
    ROOT
    / "macos/ControlCenter/Sources/SecureSandboxControlCenter/Views/TerminalWindowView.swift"
)


class TerminalShutdownContractTests(unittest.TestCase):
    def test_swiftterm_deinit_cannot_preempt_controller_cleanup(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        controller = re.search(
            r"controllerGraceSeconds:\s*TimeInterval\s*=\s*([0-9]+(?:\.[0-9]+)?)",
            source,
        )
        swiftterm = re.search(
            r"swiftTermGraceSeconds:\s*TimeInterval\s*=\s*([0-9]+(?:\.[0-9]+)?)",
            source,
        )
        self.assertIsNotNone(controller)
        self.assertIsNotNone(swiftterm)
        self.assertGreater(float(swiftterm.group(1)), float(controller.group(1)))
        self.assertIn(
            "view.process.killEscalationDelay = TerminalShutdownPolicy.swiftTermGraceSeconds",
            source,
        )
        self.assertIn(
            "afterDelay: TerminalShutdownPolicy.controllerGraceSeconds",
            source,
        )
        close_handler = source.index("func terminateForWindowClose()")
        close_end = source.index("@objc private func forceTerminateIfNeeded", close_handler)
        close_source = source[close_handler:close_end]
        guard = close_source.index("guard let terminalView, closingPID == 0 else { return }")
        retain = close_source.index("Self.closingCoordinators[pid] = self")
        signal = close_source.rindex("terminalView.terminate()")
        self.assertLess(guard, signal)
        self.assertLess(retain, signal)
        self.assertIn(
            "private static var closingCoordinators: [pid_t: Coordinator] = [:]",
            source,
        )
        self.assertIn("private var terminalView: LocalProcessTerminalView?", source)
        self.assertNotIn("private weak var terminalView", source)
        self.assertIn("Self.closingCoordinators.removeValue(forKey: pid)", source)


if __name__ == "__main__":
    unittest.main()
