#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

from scripts import native_gateway_compensation as compensation
from shared import native_deployment, native_install_transaction


ROOT = Path(__file__).resolve().parents[1]


class NativeGatewayCompensationTests(unittest.TestCase):
    def _fixture(
        self, root: Path, *, predecessor_kind: str | None = "protected",
        predecessor_package: str | None = "5" * 64,
    ) -> tuple[Path, Path, Path, Path]:
        uid, gid = os.geteuid(), os.getegid()
        state = root / "state"
        state.mkdir(mode=0o700)
        destination = root / "installed"
        destination.write_bytes(b"prior")
        destination.chmod(0o600)
        package = "1" * 64
        plan = native_deployment.make_plan(
            deployment_id=str(uuid.uuid4()), host_release_id="2" * 64,
            catalog_sha256="3" * 64,
            gateway_package_sha256=package,
            research_package_sha256="4" * 64,
            previous_gateway_package_sha256="5" * 64,
            previous_research_package_sha256="6" * 64,
            created_at=1000, expires_at=1100)
        plan_path = root / "native-deployment-plan.json"
        plan_path.write_bytes(native_deployment.canonical(plan))
        plan_path.chmod(0o600)
        pending = state / "gateway-install.pending.json"
        backup = root / "backup"
        metadata = {
            "deployment_id": plan["deployment_id"],
            "deployment_plan_sha256": plan["plan_sha256"],
            "package_sha256": package,
        }
        if predecessor_kind is not None:
            metadata.update({
                "predecessor_kind": predecessor_kind,
                "predecessor_package_sha256": predecessor_package,
            })
        native_install_transaction.begin(
            pending, backup, [destination], expected_uid=uid,
            expected_gid=gid, now=1000,
            metadata=metadata)
        destination.write_bytes(b"candidate")
        native_install_transaction.commit(
            pending, expected_uid=uid, expected_gid=gid)
        transaction_source = root / "native_install_transaction.py"
        deployment_source = root / "native_deployment.py"
        shutil.copyfile(
            ROOT / "shared/native_install_transaction.py", transaction_source)
        shutil.copyfile(ROOT / "shared/native_deployment.py", deployment_source)
        transaction_source.chmod(0o600)
        deployment_source.chmod(0o600)
        return state, destination, plan_path, transaction_source

    def test_exact_committed_backup_is_rearmed_and_restores_prior(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, destination, plan, transaction_source = self._fixture(root)
            deployment_source = root / "native_deployment.py"
            record = compensation.arm(
                plan_path=plan, transaction_path=transaction_source,
                deployment_path=deployment_source, state_root=state,
                trusted_uid=uid, trusted_gid=gid)
            self.assertIsNone(record["decision"])
            pending = state / "gateway-install.pending.json"
            native_install_transaction.recover(
                pending, expected_uid=uid, expected_gid=gid)
            native_install_transaction.finalize_recovery(
                pending, expected_uid=uid, expected_gid=gid)
            self.assertEqual(destination.read_bytes(), b"prior")

    def test_changed_plan_cannot_select_backup(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, _destination, plan_path, transaction_source = self._fixture(root)
            plan = json.loads(plan_path.read_bytes())
            changed = native_deployment.make_plan(
                deployment_id=plan["deployment_id"],
                host_release_id=plan["host_release_id"],
                catalog_sha256=plan["catalog_sha256"],
                gateway_package_sha256="a" * 64,
                research_package_sha256=plan["research_package_sha256"],
                previous_gateway_package_sha256=
                    plan["previous_gateway_package_sha256"],
                previous_research_package_sha256=
                    plan["previous_research_package_sha256"],
                created_at=plan["created_at"], expires_at=plan["expires_at"])
            plan_path.write_bytes(native_deployment.canonical(changed))
            with self.assertRaisesRegex(
                compensation.NativeGatewayCompensationError, "not_unique"
            ):
                compensation.arm(
                    plan_path=plan_path, transaction_path=transaction_source,
                    deployment_path=root / "native_deployment.py",
                    state_root=state, trusted_uid=uid, trusted_gid=gid)

    def test_archive_must_bind_exact_predecessor_identity(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        for kind, package in ((None, None), ("legacy", "7" * 64),
                              ("absent", None)):
            with self.subTest(kind=kind, package=package):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    state, _destination, plan, transaction = self._fixture(
                        root, predecessor_kind=kind,
                        predecessor_package=package)
                    with self.assertRaisesRegex(
                        compensation.NativeGatewayCompensationError,
                        "archive_not_unique",
                    ):
                        compensation.arm(
                            plan_path=plan, transaction_path=transaction,
                            deployment_path=root / "native_deployment.py",
                            state_root=state, trusted_uid=uid,
                            trusted_gid=gid)

    def test_compensation_barriers_cover_arm_and_release_on_crash(self) -> None:
        uid, gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            install = root / "install.lock"
            guest = root / ".lock"
            for path in (install, guest):
                path.write_bytes(b"")
                path.chmod(0o600)
            descriptors = compensation.acquire_locks(
                install, guest, trusted_uid=uid, trusted_gid=gid)
            try:
                code = (
                    "import fcntl,os,sys;"
                    "fd=os.open(sys.argv[1],os.O_RDWR);"
                    "\ntry: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)"
                    "\nexcept BlockingIOError: raise SystemExit(73)"
                    "\nraise SystemExit(0)"
                )
                for path in (install, guest):
                    blocked = subprocess.run(
                        [sys.executable, "-c", code, str(path)], check=False)
                    self.assertEqual(blocked.returncode, 73)
            finally:
                for descriptor in reversed(descriptors):
                    os.close(descriptor)

            crash = subprocess.run([
                sys.executable, "-c",
                "import os,sys;from scripts import native_gateway_compensation as c;"
                "c.acquire_locks(__import__('pathlib').Path(sys.argv[1]),"
                "__import__('pathlib').Path(sys.argv[2]),"
                "trusted_uid=os.geteuid(),trusted_gid=os.getegid());os._exit(91)",
                str(install), str(guest),
            ], cwd=ROOT, check=False)
            self.assertEqual(crash.returncode, 91)
            after = compensation.acquire_locks(
                install, guest, trusted_uid=uid, trusted_gid=gid)
            for descriptor in reversed(after):
                os.close(descriptor)
            self.assertFalse((root / "gateway-install.pending.json").exists())

    def test_shell_wrapper_is_fixed_and_syntax_checked(self) -> None:
        path = ROOT / "scripts/install-native-gateway-compensation.sh"
        checked = subprocess.run(
            ["bash", "-n", str(path)], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        text = path.read_text(encoding="utf-8")
        self.assertIn(
            "python3 -I /tmp/native_gateway_compensation.py", text)
        self.assertLess(
            text.index("flock -x"),
            text.rindex("python3 -I /tmp/native_gateway_compensation.py"),
        )
        self.assertNotIn("eval", text)


if __name__ == "__main__":
    unittest.main()
