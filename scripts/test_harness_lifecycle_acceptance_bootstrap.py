#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_bootstrap",
    ROOT / "scripts/harness-lifecycle-acceptance-bootstrap.py",
)
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
NOW = 2_000_000_000


class Result:
    def __init__(self, returncode: int):
        self.returncode = returncode


class BootstrapAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.campaign_path = self.root / "campaign.json"
        self.observations = self.root / "observations"
        self.raw = self.root / "raw"
        self.home = self.root / "home"
        for path in (self.observations, self.raw, self.home):
            path.mkdir(mode=0o700)
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
        self.campaign_path.write_bytes(acceptance.canonical(self.campaign))
        self.campaign_path.chmod(0o600)
        self.enrollment_path = self.root / "enrollment.json"
        self.enrollment = {
            "schema": acceptance.ENROLLMENT_SCHEMA,
            "enrollment_id": str(uuid.uuid4()),
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "observed_at": NOW - 120, "disposable": True,
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "collector": "secure-sandbox-disposable-supervisor-v1",
        }
        self.enrollment["enrollment_sha256"] = acceptance.digest(self.enrollment)
        self.enrollment_path.write_bytes(acceptance.canonical(self.enrollment))
        self.enrollment_path.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def case(self, case_id: str) -> dict:
        return acceptance.case_record(acceptance.CASE_BY_ID[case_id])

    def boundary(self) -> dict:
        return {
            "schema": "secure-sandbox-harness-generation-boundary-v1",
            "status": "verified", "active_generation_id": None,
            "generation_count": 0, "catalog_sha256": "3" * 64,
            "selector_sha256": "4" * 64, "floor_sha256": "5" * 64,
        }

    def release(self) -> dict:
        return {
            "schema": bootstrap.HOST_RELEASE.SCHEMA, "status": "verified",
            "release_id": "6" * 64, "launcher_sha256": "7" * 64,
            "payloads": {"controller": "8" * 64},
        }

    def store_status(self, boundary: dict) -> dict:
        return {
            "schema": "secure-sandbox-harness-generation-status-v1",
            "status": "verified", "admission": "open",
            "recovery_pending": False, "active_generation_id": None,
            "predecessor_generation_id": None, "selector_epoch": 0,
            "highest_release_sequence": 0, "revoked_generation_ids": [],
            "generations": [], "boundary": boundary,
        }

    def preflight_patch(self, case: dict):
        return mock.patch.object(
            bootstrap, "preflight", return_value=(self.campaign, case),
        )

    def test_clean_install_collects_protected_readbacks_and_projects_all_kinds(self):
        case = self.case("bootstrap-clean-install")
        boundary = self.boundary()

        def control(operation: str):
            return {
                "control-status": {
                    "schema": "secure-sandbox-privileged-control-status-v1",
                    "role": "research",
                },
                "harness-generation-status": self.store_status(boundary),
                "harness-generation-verify-boundary": boundary,
            }[operation]

        with self.preflight_patch(case), \
                mock.patch.object(bootstrap.SUPERVISOR, "prerequisite"), \
                mock.patch.object(bootstrap.HOST_RELEASE, "verify",
                                  return_value=self.release()), \
                mock.patch.object(bootstrap, "control", side_effect=control):
            result = bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                None, NOW,
            )
        raw_directory = Path(result["raw_directory"])
        self.assertEqual(
            {item.name for item in raw_directory.iterdir()},
            set(bootstrap.CASE_FILES[case["case_id"]].values()),
        )
        with self.preflight_patch(case):
            projected = bootstrap.project(
                self.campaign_path, self.observations, case["case_id"],
                raw_directory, NOW,
            )
        self.assertEqual(projected["recorded_observation_kinds"], case["evidence_kinds"])
        for kind in case["evidence_kinds"]:
            value = json.loads(
                (self.observations / f"{case['case_id']}.{kind}.json").read_bytes(),
            )
            self.assertEqual(
                value["evidence"]["artifacts"][0]["authority"],
                bootstrap.AUTHORITIES[kind],
            )
            acceptance.validate_observation(
                value, self.campaign, acceptance.CASE_BY_ID[case["case_id"]],
            )

    def test_production_scan_binds_clean_enrollment_and_projects_both_kinds(self):
        case = self.case("bootstrap-no-production-material")
        runner = mock.Mock(return_value=Result(44))
        with self.preflight_patch(case):
            result = bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                self.enrollment_path, NOW, home=self.home, environment={}, runner=runner,
            )
        raw_directory = Path(result["raw_directory"])
        scan = json.loads((raw_directory / "production-material-scan.json").read_bytes())
        self.assertEqual(scan["status"], "absent")
        self.assertNotIn("values", scan)
        with self.preflight_patch(case):
            projected = bootstrap.project(
                self.campaign_path, self.observations, case["case_id"],
                raw_directory, NOW,
            )
        self.assertEqual(projected["recorded_observation_kinds"], case["evidence_kinds"])

    def test_production_marker_rejects_and_reserved_case_is_never_reused(self):
        case = self.case("bootstrap-no-production-material")
        runner = mock.Mock(return_value=Result(44))
        with self.preflight_patch(case), self.assertRaisesRegex(
                bootstrap.BootstrapError, "production_material_marker"):
            bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                self.enrollment_path, NOW, home=self.home,
                environment={"OPENAI_API_KEY": "synthetic-but-present"}, runner=runner,
            )
        reserved = self.raw / case["case_id"]
        self.assertTrue(reserved.is_dir())
        self.assertEqual(list(reserved.iterdir()), [])
        with self.preflight_patch(case), self.assertRaisesRegex(
                bootstrap.BootstrapError, "raw_case_exists"):
            bootstrap.collect(
                self.campaign_path, self.observations, case["case_id"], self.raw,
                self.enrollment_path, NOW, home=self.home, environment={}, runner=runner,
            )

    def test_surface_is_read_only_and_has_no_evidence_authority_override(self):
        source = (
            ROOT / "scripts/harness-lifecycle-acceptance-bootstrap.py"
        ).read_text()
        for forbidden in (
            'add_argument("--authority"', 'add_argument("--artifact"',
            'add_argument("--kind"', 'add_argument("--outcome"',
            'add_parser("install"', 'add_parser("authorize"',
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("HOST_RELEASE.verify(", source)
        self.assertIn('control("harness-generation-status")', source)
        self.assertIn('control("harness-generation-verify-boundary")', source)


if __name__ == "__main__":
    unittest.main()
