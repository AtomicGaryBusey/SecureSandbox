#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_archive",
    ROOT / "scripts/harness-lifecycle-acceptance-archive.py",
)
DRIVER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(DRIVER)
NOW = 2_000_000_000


class ArchiveDriverTests(unittest.TestCase):
    def test_privileged_checkout_invocation_rejects_before_local_imports(self) -> None:
        with self.assertRaisesRegex(
            SystemExit, "archive_driver_protected_invocation_required",
        ):
            DRIVER.require_protected_main_path(
                ROOT / "scripts/harness-lifecycle-acceptance-archive.py", 0,
            )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.observations = self.root / "observations"
        self.raw = self.root / "raw"
        self.observations.mkdir(mode=0o700); self.raw.mkdir(mode=0o700)
        self.campaign = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": "11111111-1111-4111-8111-111111111111",
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "a" * 64,
            "source_commit": "b" * 40,
            "created_at": NOW - 100, "expires_at": NOW + 3600,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        self.campaign["campaign_sha256"] = acceptance.digest(self.campaign)
        self.campaign_path = self.root / "campaign.json"
        self.campaign_path.write_bytes(acceptance.canonical(self.campaign))
        self.campaign_path.chmod(0o600)
        self.protected = self.root / "protected"
        release = self.protected / "releases" / self.campaign["source_commit"]
        release.mkdir(parents=True, mode=0o755)
        payloads = list(
            DRIVER.ACCEPTANCE_CLI.PROTECTED_DRIVER_PAYLOADS[
                "host-archive-fixture"
            ]
        )
        records = []
        for relative in payloads:
            source = ROOT / relative
            destination = release / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            shutil.copyfile(source, destination)
            mode = 0o555 if relative.startswith("scripts/") else 0o444
            destination.chmod(mode)
            raw = destination.read_bytes()
            records.append({
                "mode": mode, "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            })
        manifest = {
            "schema": DRIVER.ACCEPTANCE_CLI.PROTECTED_DRIVER_MANIFEST_SCHEMA,
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "source_commit": self.campaign["source_commit"],
            "drivers": {"host-archive-fixture": payloads},
            "files": sorted(records, key=lambda item: item["path"]),
        }
        manifest["manifest_sha256"] = acceptance.digest(manifest)
        path = release / "manifest.json"
        path.write_bytes(acceptance.canonical(manifest)); path.chmod(0o444)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def next_value(case_id: str) -> dict:
        case = acceptance.CASE_BY_ID[case_id]
        return {
            "status": "pending", "case": acceptance.case_record(case),
            "missing_evidence": list(case.evidence_kinds),
        }

    def run_case(self, case_id: str):
        with mock.patch.object(
            DRIVER.SUPERVISOR, "current_machine_identity", return_value="a" * 64,
        ), mock.patch.object(
            DRIVER.ACCEPTANCE_CLI, "next_case", return_value=self.next_value(case_id),
        ):
            return DRIVER.run(
                self.campaign_path, self.observations, self.raw, case_id, NOW,
                operator_uid=os.geteuid(), installation_root=self.protected,
                expected_install_uid=os.geteuid(),
            )

    def test_all_twelve_cases_emit_only_fixed_rejection_observations(self) -> None:
        cases = [case for case in acceptance.CASES if case.category == "archive"]
        self.assertEqual(len(cases), 12)
        for case in cases:
            with self.subTest(case_id=case.case_id):
                result = self.run_case(case.case_id)
                self.assertEqual(result["status"], "recorded")
                path = self.observations / f"{case.case_id}.archive-rejection.json"
                observation = DRIVER.SUPERVISOR.trusted_json(path)
                acceptance.validate_observation(observation, self.campaign, case)
                evidence = observation["evidence"]
                self.assertEqual(evidence["artifacts"][0]["authority"], "protected-host")
                self.assertEqual(observation["outcome"], "rejected")
                fixture = DRIVER.SUPERVISOR.trusted_json(
                    self.raw / case.case_id / DRIVER.RAW_FILENAME,
                )["fixture"]
                self.assertFalse(fixture["extracted"])
                self.assertFalse(fixture["executed"])
                self.assertEqual(
                    fixture["protected_state_before_sha256"],
                    fixture["protected_state_after_sha256"],
                )
                self.assertEqual(
                    fixture["production_boundary"], "HarnessStore.acquire",
                )
                self.assertTrue(fixture["production_boundary_invoked"])
                self.assertFalse(fixture["quarantine_generation_present"])

    def test_resume_requires_exact_record_and_extra_raw_evidence_rejects(self) -> None:
        case_id = "reject-archive-symlink"
        first = self.run_case(case_id)
        second = self.run_case(case_id)
        self.assertEqual(first["record_sha256"], second["record_sha256"])
        self.assertEqual(first["observation_sha256"], second["observation_sha256"])
        extra = self.raw / case_id / "candidate-claim.json"
        extra.write_text("{}\n", encoding="ascii"); extra.chmod(0o600)
        with self.assertRaisesRegex(DRIVER.ArchiveDriverError, "inventory"):
            self.run_case(case_id)

    def test_preflight_carries_operator_directory_and_root_observation_owners(self) -> None:
        case_id = "reject-archive-hardlink"
        operator_uid = os.geteuid() + 1
        with mock.patch.object(
            DRIVER.ACCEPTANCE_CLI, "trusted_json", return_value=self.campaign,
        ), mock.patch.object(
            DRIVER.ACCEPTANCE_CLI, "verify_protected_driver",
        ), mock.patch.object(
            DRIVER.SUPERVISOR, "current_machine_identity", return_value="a" * 64,
        ), mock.patch.object(
            DRIVER, "private_directory",
        ), mock.patch.object(
            DRIVER.ACCEPTANCE_CLI, "next_case", return_value=self.next_value(case_id),
        ) as next_case:
            DRIVER.preflight(
                self.campaign_path, self.observations, case_id, NOW,
                operator_uid, self.protected, os.geteuid(),
            )
        next_case.assert_called_once_with(
            self.campaign, self.observations, observation_uid=0,
            directory_uid=operator_uid,
        )

    def test_installed_driver_imports_without_manifest_contamination(self) -> None:
        release = self.protected / "releases" / self.campaign["source_commit"]
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        subprocess.run(
            ["python3", str(release / "scripts/harness-lifecycle-acceptance-archive.py"),
             "--help"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            env=environment,
        )
        self.assertFalse(any(
            path.name == "__pycache__" or path.suffix == ".pyc"
            for path in release.rglob("*")
        ))
        DRIVER.ACCEPTANCE_CLI.verify_protected_driver(
            self.protected, self.campaign["source_commit"],
            "host-archive-fixture", os.geteuid(),
        )


if __name__ == "__main__":
    unittest.main()
