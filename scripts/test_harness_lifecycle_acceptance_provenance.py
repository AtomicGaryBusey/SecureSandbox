#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
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
    "harness_lifecycle_acceptance_provenance",
    ROOT / "scripts/harness-lifecycle-acceptance-provenance.py",
)
DRIVER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(DRIVER)

NOW = 2_000_000_000


class ProvenanceDriverTests(unittest.TestCase):
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
                "host-provenance-fixture"
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
            "drivers": {"host-provenance-fixture": payloads},
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

    def test_all_sixteen_cases_emit_only_fixed_valid_observations(self) -> None:
        cases = [case for case in acceptance.CASES if case.category == "provenance"]
        self.assertEqual(len(cases), 16)
        for case in cases:
            with self.subTest(case_id=case.case_id):
                result = self.run_case(case.case_id)
                self.assertEqual(result["status"], "recorded")
                self.assertEqual(len(result["observation_sha256"]), len(case.evidence_kinds))
                for kind in case.evidence_kinds:
                    path = self.observations / f"{case.case_id}.{kind}.json"
                    observation = DRIVER.SUPERVISOR.trusted_json(path)
                    acceptance.validate_observation(observation, self.campaign, case)
                    self.assertEqual(
                        observation["evidence"]["artifacts"][0]["authority"],
                        "protected-host",
                    )
                    self.assertFalse(observation["candidate_statement_used"])

    def test_partial_projection_resumes_only_from_same_valid_raw_record(self) -> None:
        case_id = "acquire-clean-carrier"
        original = DRIVER.OBSERVER.observe
        calls = 0

        def interrupted(**kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated projection loss")
            return original(**kwargs)

        with mock.patch.object(
            DRIVER.SUPERVISOR, "current_machine_identity", return_value="a" * 64,
        ), mock.patch.object(
            DRIVER.ACCEPTANCE_CLI, "next_case", return_value=self.next_value(case_id),
        ), mock.patch.object(DRIVER.OBSERVER, "observe", side_effect=interrupted):
            with self.assertRaises(OSError):
                DRIVER.run(
                    self.campaign_path, self.observations, self.raw, case_id, NOW,
                    operator_uid=os.geteuid(), installation_root=self.protected,
                    expected_install_uid=os.geteuid(),
                )
        result = self.run_case(case_id)
        self.assertEqual(len(result["observation_sha256"]), 2)
        self.assertEqual(
            set(item.name for item in (self.raw / case_id).iterdir()),
            {DRIVER.RAW_FILENAME},
        )

    def test_extra_raw_evidence_rejects_without_overwrite(self) -> None:
        case_id = "reject-bad-signature"
        self.run_case(case_id)
        extra = self.raw / case_id / "candidate-claim.json"
        extra.write_text("{}\n", encoding="ascii"); extra.chmod(0o600)
        with self.assertRaisesRegex(DRIVER.ProvenanceDriverError, "inventory"):
            self.run_case(case_id)

    def test_preflight_carries_operator_directory_and_root_observation_owners(self) -> None:
        case_id = "reject-bad-signature"
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

    def test_installed_driver_imports_without_contaminating_manifest_inventory(self) -> None:
        release = self.protected / "releases" / self.campaign["source_commit"]
        environment = dict(os.environ)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        subprocess.run(
            ["python3", str(release / "scripts/harness-lifecycle-acceptance-provenance.py"),
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
            "host-provenance-fixture", os.geteuid(),
        )


if __name__ == "__main__":
    unittest.main()
