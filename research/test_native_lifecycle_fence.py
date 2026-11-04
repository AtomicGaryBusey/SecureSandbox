#!/usr/bin/env python3

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from research import native_lifecycle_fence as fence


PROMOTION_ID = "11111111-1111-4111-8111-111111111111"


class NativeLifecycleFenceTests(unittest.TestCase):
    def test_exact_fence_is_durable_idempotent_and_blocks_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            arguments = dict(
                promotion_id=PROMOTION_ID, plan_sha256="1" * 64,
                previous_catalog_sha256="0" * 64,
                catalog_sha256="2" * 64, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid())
            with fence.locked(root=root, trusted_uid=os.geteuid(),
                              trusted_gid=os.getegid()) as descriptor:
                first = fence.acquire_locked(descriptor, **arguments)
            with fence.locked(root=root, trusted_uid=os.geteuid(),
                              trusted_gid=os.getegid()) as descriptor:
                second = fence.acquire_locked(descriptor, **arguments)
            self.assertEqual(first, second)
            self.assertEqual((root / fence.FENCE_NAME).stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(
                fence.NativeLifecycleFenceError, "admission_fenced"):
                with fence.admission_open(
                    root=root, trusted_uid=os.geteuid(),
                    trusted_gid=os.getegid()):
                    self.fail("fenced admission opened")

            with fence.locked(root=root, trusted_uid=os.geteuid(),
                              trusted_gid=os.getegid()) as descriptor:
                evidence = fence.release_locked(descriptor, **arguments)
            self.assertRegex(evidence, r"^[0-9a-f]{64}$")
            with fence.admission_open(
                root=root, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid()):
                pass

    def test_conflicting_acquire_and_release_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            common = dict(
                promotion_id=PROMOTION_ID, plan_sha256="1" * 64,
                previous_catalog_sha256="0" * 64,
                catalog_sha256="2" * 64, trusted_uid=os.geteuid(),
                trusted_gid=os.getegid())
            with fence.locked(root=root, trusted_uid=os.geteuid(),
                              trusted_gid=os.getegid()) as descriptor:
                fence.acquire_locked(descriptor, **common)
            with fence.locked(root=root, trusted_uid=os.geteuid(),
                              trusted_gid=os.getegid()) as descriptor:
                with self.assertRaisesRegex(
                    fence.NativeLifecycleFenceError, "fence_conflict"):
                    fence.acquire_locked(
                        descriptor, **{**common, "catalog_sha256": "3" * 64})
            with fence.locked(root=root, trusted_uid=os.geteuid(),
                              trusted_gid=os.getegid()) as descriptor:
                with self.assertRaisesRegex(
                    fence.NativeLifecycleFenceError, "release_mismatch"):
                    fence.release_locked(
                        descriptor, **{**common, "plan_sha256": "4" * 64})
            self.assertTrue((root / fence.FENCE_NAME).exists())

    def test_durable_install_pending_closes_admission_without_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "lifecycle"
            root.mkdir(mode=0o700)
            pending = base / "native-research-install.pending.json"
            pending.write_bytes(b"ambiguous\n")
            with self.assertRaisesRegex(
                fence.NativeLifecycleFenceError,
                "install_recovery_required",
            ):
                with fence.admission_open(
                    root=root, install_pending=pending,
                    trusted_uid=os.geteuid(), trusted_gid=os.getegid()):
                    self.fail("pending installation opened admission")


if __name__ == "__main__":
    unittest.main()
