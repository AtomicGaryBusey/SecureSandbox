import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("legacy_continuity_control.py")
SPEC = importlib.util.spec_from_file_location("legacy_continuity_control", SCRIPT)
CONTROL = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CONTROL)


class LegacyContinuityControlTests(unittest.TestCase):
    def test_activate_binds_archive_plan_receipt_and_refreshes_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir(mode=0o700)
            archive = state / "research.tar.gz"
            archive.write_bytes(b"archive")
            plan = state / "continuity-plan.json"
            plan_value = {"blocking_conflicts": 0, "schema": "plan", "status": "ready"}
            plan.write_bytes((json.dumps(plan_value, separators=(",", ":"), sort_keys=True) + "\n").encode())
            receipt_path = state / "continuity-import.json"
            digest = "a" * 64
            receipt = {
                "archive_sha256": digest,
                "plan_sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
                "schema": "secure-sandbox-legacy-continuity-receipt-v1",
                "status": "imported",
            }
            lstat = mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
            with mock.patch.object(CONTROL, "STATE", state), \
                 mock.patch.object(CONTROL, "ARCHIVE", archive), \
                 mock.patch.object(CONTROL, "PLAN", plan), \
                 mock.patch.object(CONTROL, "RECEIPT", receipt_path), \
                 mock.patch.object(CONTROL.os, "geteuid", return_value=0), \
                 mock.patch.object(CONTROL.Path, "lstat", return_value=lstat), \
                 mock.patch.object(CONTROL, "trusted_regular"), \
                 mock.patch.object(CONTROL, "require_idle"), \
                 mock.patch.object(CONTROL, "atomic_plan"), \
                 mock.patch.object(CONTROL, "json_output", side_effect=[
                     {"archive_sha256": digest, "role": "research", "status": "verified"},
                     receipt,
                 ]), \
                 mock.patch.object(CONTROL, "run") as run:
                result = CONTROL.activate(digest)
            self.assertEqual(result, receipt)
            self.assertTrue(any(command[-1] == "refresh" for command in (call.args[0] for call in run.call_args_list)))

    def test_invalid_hash_is_rejected_before_archive_access(self):
        with mock.patch.object(CONTROL.os, "geteuid", return_value=0), \
             mock.patch.object(CONTROL, "require_idle") as idle:
            with self.assertRaisesRegex(CONTROL.ContinuityError, "archive_sha256_invalid"):
                CONTROL.activate("not-a-hash")
        idle.assert_not_called()


if __name__ == "__main__":
    unittest.main()
