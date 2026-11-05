#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path

from research import native_runtime_entry as entry


class NativeRuntimeEntryTests(unittest.TestCase):
    def test_only_fixed_root_installed_entrypoints_exist(self) -> None:
        self.assertEqual(set(entry.ENTRYPOINTS), {
            "native_provider_controller.py",
            "native_claude_login_channel.py",
            "native_claude_session_controller.py",
            "native_codex_session_controller.py",
            "native_harness_supervisor.py",
        })
        self.assertTrue(all(
            value.startswith("research.native_")
            for value in entry.ENTRYPOINTS.values()))

    def test_provider_wrapper_remains_root_only_for_hidden_supervisor(self) -> None:
        source = Path(entry.__file__).read_text(encoding="utf-8")
        self.assertIn('name != "native_harness_supervisor.py"', source)
        self.assertIn("os.geteuid() != 0", source)
        self.assertNotIn("nonroot_supervisor", source)


if __name__ == "__main__":
    unittest.main()
