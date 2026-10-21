#!/usr/bin/env python3

import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import manage_run_id


class RunIdManagerTests(unittest.TestCase):
    def test_boundary_and_lifecycle_publication_share_one_transaction_lock(self):
        self.assertEqual(manage_run_id.LOCK_FILE.name, "run-lease.lock")

    def test_accepts_only_uuid4_or_boundary_marker(self):
        value = str(uuid.uuid4())
        self.assertEqual(manage_run_id.canonical_run_id(value), value)
        self.assertEqual(manage_run_id.canonical_run_id("boundary-test"), "boundary-test")
        for rejected in ("preflight", "arbitrary", str(uuid.uuid1())):
            with self.assertRaises(ValueError):
                manage_run_id.canonical_run_id(rejected)

    def test_atomic_set_and_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            run_directory = Path(directory)
            run_file = run_directory / "run-id"
            value = str(uuid.uuid4())
            with mock.patch.object(manage_run_id, "RUN_DIRECTORY", run_directory), \
                 mock.patch.object(manage_run_id, "RUN_ID_FILE", run_file), \
                 mock.patch.object(manage_run_id, "EVIDENCE_RUN_ID_FILE", run_directory / "evidence-run-id"), \
                 mock.patch.object(manage_run_id, "LIFECYCLE_FILE", run_directory / "active.json"), \
                 mock.patch.object(manage_run_id, "LIFECYCLE_FAILURE_FILE", run_directory / "failure.json"), \
                 mock.patch.object(manage_run_id, "LOCK_FILE", run_directory / ".lock"), \
                 mock.patch("manage_run_id.os.chown"):
                manage_run_id.set_run_id(value)
                self.assertEqual(run_file.read_text(encoding="ascii"), value + "\n")
                self.assertEqual(run_file.stat().st_mode & 0o777, 0o644)
                with self.assertRaises(FileExistsError):
                    manage_run_id.set_run_id(str(uuid.uuid4()))
                with self.assertRaises(PermissionError):
                    manage_run_id.clear_run_id(str(uuid.uuid4()))
                manage_run_id.clear_run_id(value)
                self.assertFalse(run_file.exists())

    def test_boundary_evidence_marker_is_separate_from_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); admission = root / "run-id"; evidence = root / "evidence-run-id"
            with mock.patch.object(manage_run_id, "RUN_DIRECTORY", root), \
                    mock.patch.object(manage_run_id, "RUN_ID_FILE", admission), \
                    mock.patch.object(manage_run_id, "EVIDENCE_RUN_ID_FILE", evidence), \
                    mock.patch.object(manage_run_id, "LIFECYCLE_FILE", root / "active.json"), \
                    mock.patch.object(manage_run_id, "LIFECYCLE_FAILURE_FILE", root / "failure.json"), \
                    mock.patch.object(manage_run_id, "LOCK_FILE", root / ".lock"), \
                    mock.patch("manage_run_id.os.chown"):
                manage_run_id.set_evidence_run_id("boundary-test")
                self.assertFalse(admission.exists())
                self.assertEqual(evidence.read_text().strip(), "boundary-test")
                with self.assertRaises(FileExistsError):
                    manage_run_id.set_run_id(str(uuid.uuid4()))
                manage_run_id.clear_evidence_run_id()
                self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
