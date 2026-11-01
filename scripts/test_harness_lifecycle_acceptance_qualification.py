#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))

import harness_lifecycle_acceptance as acceptance


SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_qualification",
    ROOT / "scripts/harness-lifecycle-acceptance-qualification.py",
)
assert SPEC and SPEC.loader
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)
NOW = 2_000_000_000


class HarnessLifecycleAcceptanceQualificationTests(unittest.TestCase):
    def campaign(self) -> dict:
        value = {
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
        value["campaign_sha256"] = acceptance.digest(value)
        return value

    def properties(self, unit: str) -> dict[str, str]:
        return {
            "Id": unit,
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "exited",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
            "NRestarts": "0",
            "ControlGroup": "/system.slice/example.service",
            "TasksMax": "2",
            "PrivateNetwork": "yes",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "PrivateTmp": "yes",
            "PrivateDevices": "yes",
            "NoNewPrivileges": "yes",
            "DynamicUser": "yes",
            "RestrictAddressFamilies": "AF_UNIX",
            "IPAddressDeny": "any",
            "Environment": "LANG=C.UTF-8 PATH=/usr/bin:/bin PYTHONDONTWRITEBYTECODE=1",
            "UnsetEnvironment": " ".join(qualification.FORBIDDEN_ENVIRONMENT),
        }

    def test_worker_remains_non_admitting_until_outer_observation(self):
        value = qualification.worker("qualification-deny-network", NOW)
        self.assertEqual(value["status"], "verified")
        self.assertEqual(value["candidate_authority"], "none")
        self.assertFalse(value["physical_evidence_eligible"])
        self.assertEqual(len(value["report"]["case_results"]), 30)
        self.assertFalse(qualification.worker_result_invalid(
            value, "qualification-deny-network",
        ))

    def test_nonqualification_case_is_categorically_rejected(self):
        with self.assertRaisesRegex(
                qualification.QualificationDriverError, "case_invalid"):
            qualification.qualification_case(
                self.campaign(), "touchid-cancel",
            )

    def test_unit_readback_requires_every_isolation_property(self):
        unit = "secure-sandbox-qualification-1234-case.service"
        properties = self.properties(unit)
        value = qualification.validate_unit_properties(properties, unit)
        self.assertTrue(value["private_network"])
        self.assertEqual(value["tasks_max"], 2)
        for field, replacement in (
            ("PrivateNetwork", "no"),
            ("TasksMax", "3"),
            ("IPAddressDeny", ""),
            ("ProtectSystem", "full"),
            ("DynamicUser", "no"),
            ("ExecMainStatus", "1"),
        ):
            tampered = dict(properties)
            tampered[field] = replacement
            with self.assertRaisesRegex(
                    qualification.QualificationDriverError, "isolation_unverified"):
                qualification.validate_unit_properties(tampered, unit)

    def test_systemd_worker_has_fixed_network_process_filesystem_and_credential_bounds(self):
        campaign = self.campaign()
        unit = qualification.unit_name(campaign, "qualification-deny-network")
        argv = qualification.systemd_argv(
            unit, Path("/protected/release"), "qualification-deny-network",
            NOW, Path("/evidence/stdout"), Path("/evidence/stderr"),
        )
        joined = "\n".join(argv)
        for required in (
            "PrivateNetwork=yes", "RestrictAddressFamilies=AF_UNIX",
            "IPAddressDeny=any", "ProtectSystem=strict", "ProtectHome=yes",
            "DynamicUser=yes", "NoNewPrivileges=yes", "TasksMax=2",
            "UnsetEnvironment=ANTHROPIC_API_KEY",
        ):
            self.assertIn(required, joined)
        self.assertEqual(argv[-6:], [
            str(Path("/protected/release")
                / "scripts/harness-lifecycle-acceptance-qualification.py"),
            "worker", "--case", "qualification-deny-network",
            "--now", str(NOW),
        ])

    def test_worker_digest_or_physical_claim_tampering_is_rejected(self):
        value = qualification.worker("qualification-deny-login", NOW)
        value["physical_evidence_eligible"] = True
        self.assertTrue(qualification.worker_result_invalid(
            value, "qualification-deny-login",
        ))

    def test_readiness_keeps_partial_driver_source_incomplete(self):
        readiness = importlib.util.spec_from_file_location(
            "acceptance_cli", ROOT / "scripts/harness-lifecycle-acceptance.py",
        )
        assert readiness and readiness.loader
        module = importlib.util.module_from_spec(readiness)
        readiness.loader.exec_module(module)
        report = module.driver_readiness(ROOT)
        record = next(item for item in report["drivers"]
                      if item["driver"] == "research-qualification-fixture")
        self.assertFalse(record["source_complete"])
        self.assertTrue(record["physical_eligibility"])
        self.assertEqual(record["installation_error"], None)
        self.assertEqual(record["missing"], [
            "scripts/harness-lifecycle-acceptance-qualification-supervisor.py",
            "scripts/harness-lifecycle-acceptance-qualification-observe.py",
        ])


if __name__ == "__main__":
    unittest.main()
