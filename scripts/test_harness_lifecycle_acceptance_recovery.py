#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock
from types import SimpleNamespace

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_recovery",
    ROOT / "scripts/harness-lifecycle-acceptance-recovery.py",
)
assert SPEC and SPEC.loader
recovery_cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery_cli)


class HarnessLifecycleAcceptanceRecoveryCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "campaign"
        self.root.mkdir(mode=0o700)
        now = int(time.time())
        self.campaign = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": now - 60, "expires_at": now + 86400,
            "environment": "disposable-mac", "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        self.campaign["campaign_sha256"] = acceptance.digest(self.campaign)
        self.campaign_path = self.root / "campaign.json"
        self.campaign_path.write_bytes(acceptance.canonical(self.campaign))
        self.campaign_path.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def test_checkpoint_stop_is_durable_and_recovery_is_content_bound(self):
        case_id = "process-loss-fenced"
        with mock.patch.object(recovery_cli.os, "kill") as kill, \
                mock.patch.object(recovery_cli.os, "_exit", side_effect=SystemExit("killed")), \
                mock.patch.object(recovery_cli.sys, "stdout",
                                  SimpleNamespace(buffer=io.BytesIO())):
            with self.assertRaisesRegex(SystemExit, "killed"):
                recovery_cli.run_fixture(self.campaign_path, case_id, int(time.time()))
        kill.assert_called_once_with(os.getpid(), recovery_cli.signal.SIGSTOP)
        workspace = self.root / "recovery-fixtures" / case_id
        checkpoint = json.loads((workspace / "checkpoint.json").read_text())
        self.assertEqual(checkpoint["checkpoint"], "fenced")
        result = recovery_cli.recover_fixture(self.campaign_path, case_id, int(time.time()))
        self.assertEqual(result["status"], "recovered")
        self.assertEqual(result["checkpoint_sha256"], checkpoint["checkpoint_sha256"])
        self.assertEqual(result["recovery"]["status"], "recovered")
        self.assertEqual(result["candidate_authority"], "none")
        self.assertFalse(result["production_material_used"])

    def test_case_root_is_fixed_and_unknown_case_rejects(self):
        with self.assertRaisesRegex(recovery_cli.AcceptanceFixtureError, "case_invalid"):
            recovery_cli.campaign_and_workspace(
                self.campaign_path, "touchid-cancel", int(time.time()), create=True,
            )
        _, workspace = recovery_cli.campaign_and_workspace(
            self.campaign_path, "power-loss-selector-written", int(time.time()), create=True,
        )
        self.assertEqual(workspace, self.root / "recovery-fixtures/power-loss-selector-written")

    def test_tampered_checkpoint_rejects_before_recovery(self):
        case_id = "process-loss-stage-created"
        with mock.patch.object(recovery_cli.os, "kill"), \
                mock.patch.object(recovery_cli.os, "_exit", side_effect=SystemExit("killed")), \
                mock.patch.object(recovery_cli.sys, "stdout",
                                  SimpleNamespace(buffer=io.BytesIO())):
            with self.assertRaises(SystemExit):
                recovery_cli.run_fixture(self.campaign_path, case_id, int(time.time()))
        checkpoint_path = self.root / "recovery-fixtures" / case_id / "checkpoint.json"
        value = json.loads(checkpoint_path.read_text())
        value["candidate_authority"] = "admission"
        checkpoint_path.write_bytes(acceptance.canonical(value))
        with self.assertRaisesRegex(recovery_cli.AcceptanceFixtureError, "checkpoint_invalid"):
            recovery_cli.recover_fixture(self.campaign_path, case_id, int(time.time()))


if __name__ == "__main__":
    unittest.main()
