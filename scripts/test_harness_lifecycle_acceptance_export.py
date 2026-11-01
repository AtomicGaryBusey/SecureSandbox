#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
import uuid
from pathlib import Path

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_export",
    ROOT / "scripts/harness-lifecycle-acceptance-export.py",
)
assert SPEC and SPEC.loader
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)
NOW = 2_000_000_000


class HarnessLifecycleAcceptanceExportTests(unittest.TestCase):
    def campaign(self) -> dict:
        value = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()), "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64, "source_commit": "2" * 40,
            "created_at": NOW - 60, "expires_at": NOW + 3600,
            "environment": "disposable-mac", "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        value["campaign_sha256"] = acceptance.digest(value)
        return value

    def manifest(self) -> dict:
        body = {
            "suite_sha256": acceptance.suite_sha256(),
            "files": [{
                "path": "scripts/harness-lifecycle-acceptance-export.py",
                "sha256": "3" * 64,
            }],
        }
        body["manifest_sha256"] = acceptance.digest(body)
        return body

    def records(self) -> list[dict]:
        return [{
            "name": name, "observation_sha256": f"{index:064x}",
            "file_sha256": f"{index + len(exporter.PRIOR_NAMES):064x}",
        } for index, name in enumerate(exporter.PRIOR_NAMES, 1)]

    def test_raw_records_are_fixed_self_digested_and_candidate_independent(self):
        campaign = self.campaign()
        case = acceptance.case_record(acceptance.CASE_BY_ID[exporter.CASE_ID])
        values = exporter.make_raw(
            campaign, case, self.manifest(), self.records(), NOW,
        )
        exporter.validate_raw(campaign, case, values, NOW)
        independence = values["candidate-independence-readback"]
        self.assertLessEqual(
            len(acceptance.canonical(values["export-readback"])),
            acceptance.MAX_DETAIL_BYTES,
        )
        self.assertFalse(independence["candidate_executable_invoked"])
        self.assertFalse(independence["candidate_statement_used"])
        self.assertFalse(independence["candidate_network_used"])
        self.assertEqual(independence["export_authority"], "acceptance-evidence-only")

    def test_raw_inventory_digest_is_order_sensitive(self):
        campaign = self.campaign()
        case = acceptance.case_record(acceptance.CASE_BY_ID[exporter.CASE_ID])
        records = self.records()
        first = exporter.make_raw(campaign, case, self.manifest(), records, NOW)
        records[0], records[1] = records[1], records[0]
        second = exporter.make_raw(campaign, case, self.manifest(), records, NOW)
        self.assertNotEqual(
            first["export-readback"]["prior_observation_inventory_sha256"],
            second["export-readback"]["prior_observation_inventory_sha256"],
        )

    def test_output_must_be_private_and_operator_owned(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); path.chmod(0o755)
            with self.assertRaisesRegex(exporter.ExportDriverError, "untrusted"):
                exporter.private_directory(path, "export_output_directory", os.geteuid())

    def test_protected_root_invocation_path_is_exact(self):
        exporter.require_protected_main_path(
            exporter.PROTECTED_RELEASES / ("a" * 40) / "scripts"
            / "harness-lifecycle-acceptance-export.py", 0,
        )
        with self.assertRaisesRegex(SystemExit, "protected_invocation"):
            exporter.require_protected_main_path(Path(__file__), 0)


if __name__ == "__main__":
    unittest.main()
