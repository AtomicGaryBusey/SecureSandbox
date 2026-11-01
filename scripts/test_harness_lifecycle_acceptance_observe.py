#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
import uuid
from pathlib import Path

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_observe",
    ROOT / "scripts/harness-lifecycle-acceptance-observe.py",
)
assert SPEC and SPEC.loader
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)
NOW = 2_000_000_000


class HarnessLifecycleAcceptanceObserveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.output = self.root / "observations"
        self.output.mkdir(mode=0o700)
        self.source = self.root / "readback.json"
        self.source.write_bytes(acceptance.canonical({
            "schema": "secure-sandbox-harness-generation-boundary-v1",
            "status": "verified",
        }))
        self.source.chmod(0o600)
        self.campaign = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": NOW - 60,
            "expires_at": NOW + 3600,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        self.campaign["campaign_sha256"] = acceptance.digest(self.campaign)

    def tearDown(self):
        self.temporary.cleanup()

    def observe(self, **changes):
        arguments = dict(
            campaign=self.campaign,
            case_id="bootstrap-clean-install",
            kind="boundary-readback",
            collector="secure-sandbox-disposable-supervisor-v1",
            artifact_arguments=[[
                "protected-readback", "disposable-supervisor", str(self.source), "application/json",
            ]],
            output_directory=self.output,
            now=NOW,
        )
        return observer.observe(**{**arguments, **changes})

    def test_projects_bounded_protected_artifact_and_writes_exact_name(self):
        value = self.observe()
        expected = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.assertEqual(value["subject_sha256"], expected)
        self.assertEqual(value["evidence"]["source_sha256"], expected)
        self.assertEqual(value["evidence"]["artifacts"][0]["authority"],
                         "disposable-supervisor")
        path = self.output / "bootstrap-clean-install.boundary-readback.json"
        self.assertEqual(path.read_bytes(), acceptance.canonical(value))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            self.observe()

    def test_case_kind_collector_and_primary_authority_are_closed(self):
        for changes, reason in (
            ({"case_id": "missing"}, "case_or_kind"),
            ({"kind": "selector-readback"}, "case_or_kind"),
            ({"collector": "candidate"}, "collector"),
            ({"artifact_arguments": [["protected-readback", "candidate", str(self.source),
                                       "application/json"]]}, "argument"),
            ({"artifact_arguments": [["protected-readback", "protected-host", str(self.source),
                                       "application/json"]]}, "primary_authority"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(acceptance.AcceptanceError, reason):
                    self.observe(**changes)

    def test_untrusted_changed_or_malformed_primary_artifact_rejects(self):
        self.source.chmod(0o666)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "untrusted"):
            self.observe()
        self.source.chmod(0o600)
        self.source.write_text("not-json\n", encoding="utf-8")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "json"):
            self.observe()
        self.source.write_bytes(acceptance.canonical({"status": "verified"}))
        with self.assertRaisesRegex(acceptance.AcceptanceError, "schema"):
            self.observe()

    def test_source_status_cannot_be_normalized_into_a_different_outcome(self):
        self.source.write_bytes(acceptance.canonical({
            "schema": "secure-sandbox-harness-generation-boundary-v1",
            "status": "rejected",
        }))
        with self.assertRaisesRegex(acceptance.AcceptanceError, "evidence_source"):
            self.observe()

    def test_output_directory_must_be_exact_private_directory(self):
        self.output.chmod(0o755)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "directory_untrusted"):
            self.observe()


if __name__ == "__main__":
    unittest.main()
