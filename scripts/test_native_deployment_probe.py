#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts import native_deployment_probe as probe
from shared import native_deployment


class NativeDeploymentProbeTests(unittest.TestCase):
    @staticmethod
    def completed(stdout: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, stdout, b"")

    def test_exact_absence_is_distinct_from_partial_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = SimpleNamespace(
                MANIFEST=root / "manifest.json",
                EXPECTED_ARTIFACTS={str(root / "artifact"): 0o444},
            )
            result = probe.observe(
                "gateway", release, native_deployment, now=1000)
            self.assertEqual(result["state"], "absent")
            (root / "artifact").write_bytes(b"partial")
            with self.assertRaisesRegex(
                probe.NativeDeploymentProbeError, "partial_installation"
            ):
                probe.observe("gateway", release, native_deployment, now=1000)

    def test_verified_readback_binds_release_closed_state_and_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_bytes(b"present")
            catalog = "/etc/secure-sandbox/native-vendor-stacks.json"
            release = SimpleNamespace(
                MANIFEST=manifest,
                EXPECTED_ARTIFACTS={str(manifest): 0o444},
                verify_installed=lambda: {
                    "package_sha256": "1" * 64,
                    "release_id": "2" * 64,
                    "artifacts": [{
                        "path": catalog, "mode": 0o644,
                        "sha256": "3" * 64,
                    }],
                },
            )
            closed = native_deployment.canonical({
                "live_policy_sha256": "a" * 64,
                "persistent_policy_sha256": "b" * 64,
                "service": "inactive", "state": "closed",
            })

            def runner(command):
                if command[-1] == "verify-closed":
                    return self.completed(closed)
                if "is-active" in command:
                    return self.completed(b"active\n")
                return self.completed(
                    b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                    b"MainPID=0\nUnitFileState=disabled\n")

            result = probe.observe(
                "research", release, native_deployment,
                runner=runner, now=1000)
            self.assertEqual(result["state"], "verified")
            self.assertEqual(result["catalog_sha256"], "3" * 64)
            self.assertEqual(result["package_sha256"], "1" * 64)
            self.assertEqual(native_deployment.validate_status(result), result)

    def test_probe_shell_is_syntax_checked_and_fixed(self) -> None:
        path = Path(__file__).with_name("install-native-deployment-probe.sh")
        checked = subprocess.run(
            ["bash", "-n", str(path)], capture_output=True, text=True,
            check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        text = path.read_text(encoding="utf-8")
        self.assertIn("python3 -I /tmp/native_deployment_probe.py", text)
        self.assertNotIn("eval", text)


if __name__ == "__main__":
    unittest.main()
