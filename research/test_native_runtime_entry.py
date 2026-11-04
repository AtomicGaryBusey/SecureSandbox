#!/usr/bin/env python3

from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
