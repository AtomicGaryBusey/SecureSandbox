#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_parallels_closed_inventory",
    ROOT / "scripts/harness-lifecycle-acceptance-parallels-closed-inventory.py",
)
assert SPEC is not None and SPEC.loader is not None
bridge = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bridge
SPEC.loader.exec_module(bridge)
COMMIT = "a" * 40
NOW = 2_000_000_000


class BridgeRunner:
    def __init__(self, *, changed_gui: bool = False, lingering_runtime: bool = False):
        self.changed_gui = changed_gui
        self.lingering_runtime = lingering_runtime
        self.gui_probes = 0
        self.quit_called = False

    def __call__(self, command, **_kwargs):
        if command[:3] == ["/usr/bin/pgrep", "-x", "prl_client_app"]:
            self.gui_probes += 1
            if self.gui_probes == 1:
                return subprocess.CompletedProcess(command, 0, b"1234\n", b"")
            if self.gui_probes == 2:
                pid = b"5678\n" if self.changed_gui else b"1234\n"
                return subprocess.CompletedProcess(command, 0, pid, b"")
            return subprocess.CompletedProcess(command, 1, b"", b"")
        if command[:3] == ["/usr/bin/pgrep", "-x", "prl_vm_app"]:
            if self.lingering_runtime:
                return subprocess.CompletedProcess(command, 0, b"2468\n", b"")
            return subprocess.CompletedProcess(command, 1, b"", b"")
        if command[:2] == ["/usr/bin/osascript", "-e"]:
            self.quit_called = True
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command[:2] == ["/bin/ls", "-lde"]:
            return subprocess.CompletedProcess(command, 0, b"private directory\n", b"")
        raise AssertionError(command)


class ClosedInventoryBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def test_capture_binds_stable_gui_stopped_inventory_and_closed_runtime(self):
        output = self.root / "closed.json"
        runner = BridgeRunner()
        with mock.patch.object(
            bridge.PREFLIGHT, "source_checkout",
            return_value=(COMMIT, {"origin": COMMIT}),
        ), mock.patch.object(
            bridge.SUPERVISOR, "current_machine_identity", return_value="b" * 64,
        ), mock.patch.object(
            bridge.SUPERVISOR, "vm_inventory",
            return_value={
                "gateway": "stopped", "research": "stopped", "target": "stopped",
            },
        ), mock.patch.object(bridge.os, "geteuid", return_value=os.geteuid()):
            value = bridge.capture(
                output, now=mock.Mock(side_effect=(NOW, NOW, NOW)),
                runner=runner,
            )
        self.assertTrue(runner.quit_called)
        self.assertEqual(value["parallels_gui_pid"], 1234)
        self.assertTrue(value["parallels_gui_closed"])
        self.assertTrue(value["vm_runtime_processes_absent"])
        self.assertEqual(output.read_bytes(), bridge.PREFLIGHT.canonical(value))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_changed_gui_session_fails_before_quit_or_publication(self):
        output = self.root / "closed.json"
        runner = BridgeRunner(changed_gui=True)
        with mock.patch.object(
            bridge.PREFLIGHT, "source_checkout",
            return_value=(COMMIT, {"origin": COMMIT}),
        ), mock.patch.object(
            bridge.SUPERVISOR, "current_machine_identity", return_value="b" * 64,
        ), mock.patch.object(
            bridge.SUPERVISOR, "vm_inventory",
            return_value={
                "gateway": "stopped", "research": "stopped", "target": "stopped",
            },
        ), mock.patch.object(bridge.os, "geteuid", return_value=os.geteuid()), \
                self.assertRaisesRegex(
                    bridge.ClosedInventoryError, "gui_session_changed",
                ):
            bridge.capture(output, now=mock.Mock(return_value=NOW), runner=runner)
        self.assertFalse(runner.quit_called)
        self.assertFalse(output.exists())

    def test_existing_output_fails_before_checkout_or_gui_probe(self):
        output = self.root / "closed.json"
        output.write_text("retained", encoding="utf-8")
        runner = BridgeRunner()
        with mock.patch.object(
            bridge.PREFLIGHT, "source_checkout",
        ) as checkout, self.assertRaisesRegex(
            bridge.ClosedInventoryError, "output_invalid",
        ):
            bridge.capture(output, now=mock.Mock(return_value=NOW), runner=runner)
        checkout.assert_not_called()
        self.assertFalse(runner.quit_called)
        self.assertEqual(output.read_text(encoding="utf-8"), "retained")

    def test_running_vm_fails_before_gui_quit(self):
        output = self.root / "closed.json"
        runner = BridgeRunner()
        with mock.patch.object(
            bridge.PREFLIGHT, "source_checkout",
            return_value=(COMMIT, {"origin": COMMIT}),
        ), mock.patch.object(
            bridge.SUPERVISOR, "current_machine_identity", return_value="b" * 64,
        ), mock.patch.object(
            bridge.SUPERVISOR, "vm_inventory",
            return_value={
                "gateway": "stopped", "research": "running", "target": "stopped",
            },
        ), mock.patch.object(bridge.os, "geteuid", return_value=os.geteuid()), \
                self.assertRaisesRegex(
                    bridge.ClosedInventoryError, "not_all_stopped",
                ):
            bridge.capture(output, now=mock.Mock(return_value=NOW), runner=runner)
        self.assertFalse(runner.quit_called)
        self.assertFalse(output.exists())

    def test_lingering_vm_runtime_times_out_without_receipt(self):
        output = self.root / "closed.json"
        runner = BridgeRunner(lingering_runtime=True)
        clock = mock.Mock(side_effect=(NOW, NOW, NOW + 21))
        with mock.patch.object(
            bridge.PREFLIGHT, "source_checkout",
            return_value=(COMMIT, {"origin": COMMIT}),
        ), mock.patch.object(
            bridge.SUPERVISOR, "current_machine_identity", return_value="b" * 64,
        ), mock.patch.object(
            bridge.SUPERVISOR, "vm_inventory",
            return_value={
                "gateway": "stopped", "research": "stopped", "target": "stopped",
            },
        ), mock.patch.object(bridge.os, "geteuid", return_value=os.geteuid()), \
                self.assertRaisesRegex(
                    bridge.ClosedInventoryError, "processes_remain",
                ):
            bridge.capture(output, now=clock, sleep=mock.Mock(), runner=runner)
        self.assertTrue(runner.quit_called)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
