#!/usr/bin/env python3

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from scripts import native_research_installer as installer
from research import native_lifecycle_fence
from shared import native_guest_control
from shared import native_research_release as release


ROOT = Path(__file__).resolve().parents[1]


class NativeResearchInstallerTests(unittest.TestCase):
    def test_release_inventory_is_fully_installed_or_preexisting(self) -> None:
        installed = {str(path) for path in installer.destination_paths()}
        preexisting = {
            "/etc/claude-code/secure-sandbox-persona.md",
            "/etc/claude-code/managed-settings.json",
            "/etc/claude-code/managed-mcp.json",
        }
        transactional_nonrelease = {
            "/etc/nftables.conf",
            "/etc/secure-sandbox/native-research-release.json",
            "/var/lib/secure-sandbox/native-vendor/anthropic/account-binding.key",
        }
        self.assertEqual(
            set(release.EXPECTED_ARTIFACTS),
            (installed - transactional_nonrelease) | preexisting)
        self.assertLessEqual(len(installed), 64)

    def test_installer_is_transactional_and_projection_is_default_closed(self) -> None:
        text = (ROOT / "scripts/native_research_installer.py").read_text(
            encoding="utf-8")
        for required in (
            '"begin"', '"recover"', '"finalize-recovery"', '"commit"',
            "native_install_transaction.py", "source_manifest_sha256",
            "closed-pending-live-qualification-and-driver",
            "native-research-release.json", "native-codex", "native-claude",
            "native-harness", "systemd-tmpfiles", "nft", "daemon-reload",
        ):
            self.assertIn(required, text)
        self.assertNotIn('"start", SERVICE', text)
        self.assertNotIn('"enable", "--now"', text)
        self.assertNotIn("shell=True", text)

    def test_installer_holds_exact_admission_and_actuator_locks(self) -> None:
        self.assertEqual(
            installer.LIFECYCLE_LOCK,
            native_lifecycle_fence.ROOT / native_lifecycle_fence.LOCK_NAME,
        )
        self.assertEqual(
            installer.EGRESS_CONTROL_LOCK,
            native_guest_control.STATE_ROOT / ".lock",
        )
        text = (ROOT / "scripts/native_research_installer.py").read_text(
            encoding="utf-8"
        )
        acquisition = [
            text.index("install_lock = lock_file(LOCK_PATH)"),
            text.index("lifecycle_lock = lock_file(LIFECYCLE_LOCK)"),
            text.index("actuator_lock = lock_file(EGRESS_CONTROL_LOCK)"),
            text.index("            recover_pending()"),
            text.index("        require_no_processes(identities)"),
        ]
        self.assertEqual(acquisition, sorted(acquisition))
        self.assertLess(
            text.index("        closed = verify_default_closed()"),
            text.rindex('        helper_command(helper, "commit"'),
        )

    def test_expiry_watchdog_is_release_bound_and_boot_started(self) -> None:
        installed = {str(path) for path in installer.destination_paths()}
        self.assertIn(str(installer.WATCHDOG_UNIT), installed)
        self.assertIn(str(installer.WATCHDOG_DROPIN), installed)
        unit = (ROOT / "research/native-egress-watchdog.service").read_text()
        self.assertIn("installed watchdog", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("Before=network-online.target", unit)

    def test_shell_entry_is_root_only_and_has_no_free_arguments(self) -> None:
        path = ROOT / "scripts/install-native-research-runtime.sh"
        subprocess.run(["bash", "-n", str(path)], check=True)
        text = path.read_text(encoding="utf-8")
        self.assertIn('[[ "$#" -eq 0 ]]', text)
        self.assertIn("native_research_install_root_required", text)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", text)


if __name__ == "__main__":
    unittest.main()
