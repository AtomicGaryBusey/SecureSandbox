#!/usr/bin/env python3

from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import native_research_installer as installer
from research import native_lifecycle_fence
from shared import native_guest_control
from shared import native_research_release as release


ROOT = Path(__file__).resolve().parents[1]


class NativeResearchInstallerTests(unittest.TestCase):
    @staticmethod
    def _module_name(relative: str) -> str:
        path = relative.removesuffix(".py").replace("/", ".")
        return path.removesuffix(".__init__")

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
            "/etc/secure-sandbox/native-vendor-stacks.json",
            "/var/lib/secure-sandbox/native-vendor/anthropic/account-binding.key",
        }
        self.assertEqual(
            set(release.EXPECTED_ARTIFACTS),
            (installed - transactional_nonrelease) | preexisting)
        self.assertLessEqual(len(installed), 64)

    def test_initial_catalog_is_source_bound_and_transactionally_installed(self) -> None:
        self.assertIn("native-vendor-stacks.json", installer.source_names())
        self.assertIn(installer.CATALOG, installer.destination_paths())
        text = (ROOT / "scripts/native_research_installer.py").read_text(
            encoding="utf-8")
        self.assertLess(
            text.index("snapshot, source_manifest = snapshot_sources()"),
            text.index("stack_ids = catalog_stack_ids("),
        )
        self.assertIn(
            'snapshot / "native-vendor-stacks.json", mode=0o600', text)

    def test_installer_is_transactional_and_projection_is_default_closed(self) -> None:
        text = (ROOT / "scripts/native_research_installer.py").read_text(
            encoding="utf-8")
        for required in (
            '"begin"', '"recover"', '"finalize-recovery"', '"commit"',
            "native_install_transaction.py", "source_manifest_sha256",
            "closed-pending-live-qualification-and-driver",
            "native-research-release.json", "native-codex", "native-claude",
            "native-harness", "systemd-tmpfiles", "nft", "daemon-reload",
            "validate_predecessor(", "watchdog_generation_stale",
        ):
            self.assertIn(required, text)
        self.assertNotIn('"start", SERVICE', text)
        self.assertNotIn('"enable", "--now"', text)
        self.assertNotIn("shell=True", text)
        self.assertLess(
            text.index("        stop_watchdog(allow_absent=watchdog_pre is None)"),
            text.index("        install_files(snapshot, launcher)"),
        )

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
        self.assertIn(
            "lifecycle_root_fd = open_trusted_directory(LIFECYCLE_ROOT)",
            text)
        self.assertIn(
            "lifecycle_fd=lifecycle_root_fd", text)

    def test_expiry_watchdog_is_release_bound_and_boot_started(self) -> None:
        installed = {str(path) for path in installer.destination_paths()}
        self.assertIn(str(installer.WATCHDOG_UNIT), installed)
        self.assertIn(str(installer.WATCHDOG_DROPIN), installed)
        unit = (ROOT / "research/native-egress-watchdog.service").read_text()
        self.assertIn("installed watchdog", unit)
        self.assertIn("Restart=always", unit)
        self.assertIn("Before=network-online.target", unit)

    def test_fresh_absent_watchdog_is_typed_and_installable(self) -> None:
        absent = (
            b"LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
            b"MainPID=0\nExecMainStartTimestampMonotonic=0\nFragmentPath=\n"
        )
        with mock.patch.object(
            installer, "run",
            return_value=subprocess.CompletedProcess([], 4, absent, b""),
        ):
            self.assertIsNone(installer.watchdog_process(required=False))
            with self.assertRaisesRegex(
                installer.NativeResearchInstallError,
                "watchdog_not_active",
            ):
                installer.watchdog_process(required=True)

        stopped_absent = (
            b"LoadState=not-found\nActiveState=inactive\n"
            b"SubState=dead\nMainPID=0\n"
        )
        with mock.patch.object(installer, "run", side_effect=[
            subprocess.CompletedProcess([], 5, b"", b""),
            subprocess.CompletedProcess([], 4, stopped_absent, b""),
        ]):
            installer.stop_watchdog(allow_absent=True)
        with mock.patch.object(installer, "run", side_effect=[
            subprocess.CompletedProcess([], 5, b"", b""),
            subprocess.CompletedProcess([], 4, stopped_absent, b""),
        ]):
            with self.assertRaisesRegex(
                installer.NativeResearchInstallError,
                "watchdog_not_stopped",
            ):
                installer.stop_watchdog(allow_absent=False)

    def test_shell_entry_is_root_only_and_has_no_free_arguments(self) -> None:
        path = ROOT / "scripts/install-native-research-runtime.sh"
        subprocess.run(["bash", "-n", str(path)], check=True)
        text = path.read_text(encoding="utf-8")
        self.assertIn('[[ "$#" -eq 0 ]]', text)
        self.assertIn("native_research_install_root_required", text)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", text)

    def test_python_package_is_dependency_closed_and_imports_in_isolation(
        self,
    ) -> None:
        installed_modules = {
            self._module_name(destination)
            for destinations in installer.PACKAGE_SOURCES.values()
            for destination in destinations
            if destination.endswith(".py")
        }
        local_dependencies: dict[str, set[str]] = {}
        for destinations in installer.PACKAGE_SOURCES.values():
            source = ROOT / destinations[0]
            tree = ast.parse(source.read_bytes(), filename=str(source))
            dependencies: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module in {"research", "shared"}:
                        dependencies.update(
                            f"{node.module}.{alias.name}"
                            for alias in node.names
                        )
                    elif node.module.startswith(("research.", "shared.")):
                        dependencies.add(node.module)
                elif isinstance(node, ast.Import):
                    dependencies.update(
                        alias.name for alias in node.names
                        if alias.name.startswith(("research.", "shared."))
                    )
            local_dependencies[str(source.relative_to(ROOT))] = {
                dependency for dependency in dependencies
                if (ROOT / (dependency.replace(".", "/") + ".py")).is_file()
            }
        missing = {
            source: sorted(dependencies - installed_modules)
            for source, dependencies in local_dependencies.items()
            if dependencies - installed_modules
        }
        self.assertEqual(missing, {})

        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary)
            for destinations in installer.PACKAGE_SOURCES.values():
                source = ROOT / destinations[0]
                for destination in destinations:
                    target = stage / destination
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            modules = sorted(
                module for module in installed_modules
                if module not in {"research", "shared"}
            )
            completed = subprocess.run(
                [
                    sys.executable, "-I", "-c",
                    "import importlib,sys;sys.path.insert(0,sys.argv[1]);"
                    "[importlib.import_module(name) for name in sys.argv[2:]]",
                    str(stage), *modules,
                ],
                cwd=stage,
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
