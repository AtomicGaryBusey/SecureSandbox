#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class ControlCenterDDDCompletionTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_design_and_implementation_are_closed(self):
        design = self.text("docs/CONTROL_CENTER_DESIGN.md")
        implementation = self.text("docs/IMPLEMENTATION.md")
        self.assertIn("Status: **implemented design**", design)
        self.assertIn("DDD is implemented.", implementation)
        self.assertIn("Emergency containment acceptance", design)
        self.assertIn("complete 133-check boundary suite", design)

    def test_command_parity_has_no_unimplemented_or_unaccepted_rows(self):
        parity = self.text("docs/CONTROL_CENTER_COMMAND_PARITY.md")
        self.assertNotIn("| Prepared |", parity)
        self.assertNotIn("| Planned |", parity)
        self.assertIn("**Gated** means", parity)
        self.assertIn("| `panic` | Maintenance | Live |", parity)
        self.assertIn("| `finding apply` | Findings | Gated |", parity)
        self.assertIn("| `snapshots --apply` | Recovery | Gated |", parity)

    def test_panic_and_start_reharden_parallels_cable_side_effect(self):
        labctl = self.text("scripts/labctl")
        lifecycle = self.text("scripts/parallels-lifecycle.py")
        self.assertIn('state == "disconnected"', labctl)
        self.assertIn("--auto-share-gamepad off", labctl)
        self.assertIn('adapter.get("state") not in (None, "disconnected")', lifecycle)
        self.assertIn('"--auto-share-gamepad", "off"', lifecycle)
        self.assertIn("gateway_gamepad_sharing_disabled", lifecycle)


if __name__ == "__main__":
    unittest.main()
