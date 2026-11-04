#!/usr/bin/env python3

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts import native_deployment_probe as probe
from shared import native_deployment


class NativeDeploymentProbeTests(unittest.TestCase):
    @staticmethod
    def completed(stdout: bytes) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 0, stdout, b"")

    @staticmethod
    def process(_pid: int) -> tuple[list[bytes], Path]:
        python = shutil.which(
            "python3", path=(
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"))
        assert python is not None
        return ([
            b"python3",
            b"/usr/local/libexec/secure-sandbox/native_guest_control.py",
            b"installed", b"watchdog",
        ], Path(python).resolve())

    def test_exact_absence_is_distinct_from_partial_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = SimpleNamespace(
                MANIFEST=root / "manifest.json",
                EXPECTED_ARTIFACTS={str(root / "artifact"): 0o444},
            )
            result = probe.observe(
                "gateway", release, native_deployment, now=1000,
                lock_paths=())
            self.assertEqual(result["state"], "absent")
            (root / "artifact").write_bytes(b"partial")
            with self.assertRaisesRegex(
                probe.NativeDeploymentProbeError, "partial_installation"
            ):
                probe.observe(
                    "gateway", release, native_deployment, now=1000,
                    lock_paths=())

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
                "schema": "secure-sandbox-native-closed-state-v1",
                "live_policy_sha256": "a" * 64,
                "persistent_policy_sha256": "b" * 64,
                "service": "inactive", "state": "closed",
            })

            def runner(command):
                if command[-1] == "verify-closed":
                    return self.completed(closed)
                if "secure-sandbox-native-egress-watchdog.service" in command:
                    if "--property=LoadState" not in command:
                        return self.completed(
                            b"MainPID=123\n"
                            b"ExecMainStartTimestampMonotonic=456\n")
                    return self.completed(
                        b"LoadState=loaded\nActiveState=active\nSubState=running\n"
                        b"MainPID=123\nExecMainStartTimestampMonotonic=456\n"
                        b"FragmentPath=/etc/systemd/system/"
                        b"secure-sandbox-native-egress-watchdog.service\n")
                return self.completed(
                    b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                    b"MainPID=0\nUnitFileState=disabled\n")

            result = probe.observe(
                "research", release, native_deployment,
                runner=runner, now=1000, lock_paths=(),
                process_reader=self.process)
            self.assertEqual(result["state"], "verified")
            self.assertEqual(result["catalog_sha256"], "3" * 64)
            self.assertEqual(result["package_sha256"], "1" * 64)
            self.assertEqual(native_deployment.validate_status(result), result)

    def test_legacy_release_is_explicitly_typed_and_still_default_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.write_bytes(b"legacy")
            release = SimpleNamespace(
                MANIFEST=root / "missing-manifest.json",
                EXPECTED_ARTIFACTS={str(artifact): 0o644},
                verify_legacy_installed=lambda: {
                    "schema": "legacy", "package_sha256": "1" * 64,
                    "release_id": "2" * 64,
                    "artifacts": [{
                        "path": str(artifact), "mode": 0o644,
                        "sha256": "3" * 64,
                    }],
                },
            )
            closed = native_deployment.canonical({
                "schema": "secure-sandbox-native-closed-state-v1",
                "state": "closed", "service": "inactive",
                "live_policy_sha256": "a" * 64,
                "persistent_policy_sha256": "b" * 64,
            })

            def runner(command):
                if command[-1] == "verify-closed":
                    return self.completed(closed)
                if "secure-sandbox-native-egress-watchdog.service" in command:
                    if "--property=LoadState" not in command:
                        return self.completed(
                            b"MainPID=123\n"
                            b"ExecMainStartTimestampMonotonic=456\n")
                    return self.completed(
                        b"LoadState=loaded\nActiveState=active\nSubState=running\n"
                        b"MainPID=123\nExecMainStartTimestampMonotonic=456\n"
                        b"FragmentPath=/etc/systemd/system/"
                        b"secure-sandbox-native-egress-watchdog.service\n")
                return self.completed(
                    b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                    b"MainPID=0\nUnitFileState=disabled\n")

            result = probe.observe(
                "gateway", release, native_deployment,
                runner=runner, now=1000, lock_paths=(),
                process_reader=self.process)
            self.assertEqual(result["generation_kind"], "legacy")
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

    def test_probe_waits_for_installer_barrier_before_attesting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "install.lock"
            marker = root / "generation"
            ready = root / "ready"
            lock.write_bytes(b"")
            lock.chmod(0o600)
            marker.write_text("prior", encoding="ascii")
            code = (
                "import fcntl,os,sys,time;"
                "fd=os.open(sys.argv[1],os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX);"
                "open(sys.argv[3],'w').write('ready');time.sleep(.15);"
                "open(sys.argv[2],'w').write('candidate');"
                "fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)"
            )
            child = subprocess.Popen(
                [sys.executable, "-c", code, str(lock), str(marker), str(ready)])
            try:
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                release = SimpleNamespace(
                    MANIFEST=root / "manifest", EXPECTED_ARTIFACTS={},
                    current_release=lambda: (
                        "protected", {
                            "package_sha256": (
                                "2" * 64 if marker.read_text() == "candidate"
                                else "1" * 64),
                            "release_id": "3" * 64, "artifacts": [],
                        }),
                )
                closed = native_deployment.canonical({
                    "schema": "secure-sandbox-native-closed-state-v1",
                    "state": "closed", "service": "inactive",
                    "live_policy_sha256": "a" * 64,
                    "persistent_policy_sha256": "b" * 64,
                })

                def runner(command):
                    if command[-1] == "verify-closed":
                        return self.completed(closed)
                    if "secure-sandbox-native-egress-watchdog.service" in command:
                        if "--property=LoadState" not in command:
                            return self.completed(
                                b"MainPID=123\n"
                                b"ExecMainStartTimestampMonotonic=456\n")
                        return self.completed(
                            b"LoadState=loaded\nActiveState=active\nSubState=running\n"
                            b"MainPID=123\nExecMainStartTimestampMonotonic=456\n"
                            b"FragmentPath=/etc/systemd/system/"
                            b"secure-sandbox-native-egress-watchdog.service\n")
                    return self.completed(
                        b"LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                        b"MainPID=0\nUnitFileState=disabled\n")

                result = probe.observe(
                    "gateway", release, native_deployment, runner=runner,
                    now=1000, lock_paths=(lock,), process_reader=self.process)
                self.assertEqual(result["package_sha256"], "2" * 64)
            finally:
                child.wait(timeout=2)

    def test_exact_absent_planes_bootstrap_only_trusted_barriers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            base = parent / "secure-sandbox"
            release = SimpleNamespace(
                MANIFEST=base / "missing-manifest",
                EXPECTED_ARTIFACTS={},
                current_release=lambda: ("absent", None),
            )
            for role in ("gateway", "research"):
                locks = probe._bootstrap_role_barriers(role, base=base)
                self.assertEqual(
                    [path.stat().st_mode & 0o777 for path in locks],
                    [0o600] * len(locks),
                )
                result = probe.observe(
                    role, release, native_deployment, now=1000,
                    lock_paths=locks,
                )
                self.assertEqual(result["state"], "absent")
                self.assertEqual(result["generation_kind"], "absent")

    def test_watchdog_generation_change_during_readback_is_rejected(self) -> None:
        first = self.completed(
            b"LoadState=loaded\nActiveState=active\nSubState=running\n"
            b"MainPID=123\nExecMainStartTimestampMonotonic=456\n"
            b"FragmentPath=/etc/systemd/system/"
            b"secure-sandbox-native-egress-watchdog.service\n")
        changed = self.completed(
            b"MainPID=124\nExecMainStartTimestampMonotonic=457\n")
        with self.assertRaisesRegex(
            probe.NativeDeploymentProbeError,
            "watchdog_generation_changed",
        ):
            probe._watchdog(
                runner=lambda command: (
                    first if "--property=LoadState" in command else changed),
                process_reader=self.process,
            )

    def test_canonical_but_incomplete_closed_claim_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest"
            manifest.write_bytes(b"present")
            release = SimpleNamespace(
                MANIFEST=manifest,
                EXPECTED_ARTIFACTS={str(manifest): 0o644},
                verify_installed=lambda: {
                    "package_sha256": "1" * 64, "release_id": "2" * 64,
                    "artifacts": [],
                },
            )
            claimed = native_deployment.canonical({"state": "closed"})

            def runner(command):
                if command[-1] == "verify-closed":
                    return self.completed(claimed)
                raise AssertionError(command)

            with self.assertRaisesRegex(
                probe.NativeDeploymentProbeError, "closed_readback_invalid"
            ):
                probe.observe(
                    "gateway", release, native_deployment,
                    runner=runner, now=1000, lock_paths=())


if __name__ == "__main__":
    unittest.main()
