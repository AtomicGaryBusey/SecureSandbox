#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
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
SUPERVISOR_SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_qualification_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-qualification-supervisor.py",
)
assert SUPERVISOR_SPEC and SUPERVISOR_SPEC.loader
supervisor = importlib.util.module_from_spec(SUPERVISOR_SPEC)
SUPERVISOR_SPEC.loader.exec_module(supervisor)
PROJECTOR_SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_qualification_projector",
    ROOT / "scripts/harness-lifecycle-acceptance-qualification-observe.py",
)
assert PROJECTOR_SPEC and PROJECTOR_SPEC.loader
projector = importlib.util.module_from_spec(PROJECTOR_SPEC)
PROJECTOR_SPEC.loader.exec_module(projector)
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

    def outer_result(self, campaign: dict, case_id: str) -> dict:
        case = acceptance.case_record(acceptance.CASE_BY_ID[case_id])
        core = qualification.worker(case_id, NOW)
        unit = qualification.unit_name(campaign, case_id)
        isolation = qualification.validate_unit_properties(
            self.properties(unit), unit,
        )
        value = {
            "schema": qualification.RESULT_SCHEMA,
            "status": case["expected"],
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "machine_identity_sha256": campaign["machine_identity_sha256"],
            "source_commit": campaign["source_commit"],
            "case_id": case_id,
            "procedure_sha256": case["procedure"]["procedure_sha256"],
            "qualification_case_id": qualification.ACCEPTANCE_CASES[case_id],
            "core_result": core, "core_result_sha256": acceptance.digest(core),
            "systemd_isolation": isolation,
            "cgroup_readback": {"cgroup_procs": [], "populated": False},
            "research_boot_sha256": "3" * 64,
            "observer_scope": "protected-research-systemd",
            "network_connections": [], "child_processes_after_completion": [],
            "production_credential_environment": [],
            "candidate_authority": "none", "production_material_used": False,
            "physical_evidence_eligible": True,
        }
        value["result_sha256"] = acceptance.digest(value)
        return value

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

    def test_outer_result_binds_independent_isolation_and_campaign(self):
        campaign = self.campaign()
        case = acceptance.case_record(
            acceptance.CASE_BY_ID["qualification-deny-child-process"],
        )
        value = self.outer_result(campaign, case["case_id"])
        qualification.validate_result(value, campaign, case)
        value["systemd_isolation"]["tasks_max"] = 3
        value["result_sha256"] = acceptance.digest({
            key: item for key, item in value.items() if key != "result_sha256"
        })
        with self.assertRaisesRegex(
                qualification.QualificationDriverError, "result_invalid"):
            qualification.validate_result(value, campaign, case)

    def test_production_scan_rejects_markers_and_requires_absent_keychain(self):
        absent = lambda command, **kwargs: subprocess.CompletedProcess(
            command, 44, b"", b"",
        )
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            value = supervisor.production_scan(home, {}, absent)
            self.assertEqual(value["present_environment"], [])
            with self.assertRaisesRegex(
                    supervisor.QualificationSupervisorError, "material_present"):
                supervisor.production_scan(home, {"OPENAI_API_KEY": "set"}, absent)

    def test_projector_revalidates_complete_mixed_authority_raw_set(self):
        campaign = self.campaign()
        case = acceptance.case_record(
            acceptance.CASE_BY_ID["qualification-deny-network"],
        )
        research = self.outer_result(campaign, case["case_id"])
        fixture = {
            "path": "fixtures/harness-qualification/malicious_harness.py",
            "sha256": "4" * 64, "size": 100, "mode": 0o444,
            "owner_uid": 0, "link_count": 1, "executable": False,
            "manifest_sha256": "5" * 64, "state": "inert-protected-payload",
        }
        quarantine = supervisor.record(
            supervisor.QUARANTINE_SCHEMA, campaign, case, NOW, "passed",
            {"before": fixture, "after": fixture, "unchanged": True,
             "host_execution": False}, "quarantine_sha256",
        )
        authority = supervisor.record(
            supervisor.AUTHORITY_SCHEMA, campaign, case, NOW, "passed",
            {"research_result_sha256": research["result_sha256"],
             "research_candidate_authority": "none",
             "admission_performed": False, "activation_performed": False,
             "selector_changed": False, "session_migrated": False},
            "authority_sha256",
        )
        production = supervisor.record(
            supervisor.SCAN_SCHEMA, campaign, case, NOW, "passed",
            {"checked_environment": sorted(supervisor.ENROLLER.PROVIDER_ENVIRONMENT),
             "checked_home_paths": list(supervisor.PRODUCTION_HOME_PATHS),
             "checked_keychain_services": list(supervisor.ENROLLER.KEYCHAIN_SERVICES),
             "present_environment": [], "present_home_paths": [],
             "present_keychain_services": [], "production_data_present": False,
             "production_credentials_present": False}, "scan_sha256",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            for name, value in {
                "research-result.json": research,
                "quarantine-readback.json": quarantine,
                "authority-readback.json": authority,
                "production-material-scan.json": production,
            }.items():
                path = root / name
                path.write_bytes(acceptance.canonical(value)); path.chmod(0o600)
            paths, values, raw = projector.raw_set(campaign, case, root, NOW)
            self.assertEqual(values["research"]["status"], "rejected")
            self.assertEqual(set(raw), set(projector.RAW_FILES))
            arguments = projector.artifact_arguments("network-observation", paths)
            self.assertEqual(arguments[0][1], "protected-research")
            self.assertEqual({item[1] for item in arguments[1:]}, {
                "protected-host", "disposable-supervisor",
            })

    def test_readiness_reports_complete_source_but_no_protected_installation(self):
        readiness = importlib.util.spec_from_file_location(
            "acceptance_cli", ROOT / "scripts/harness-lifecycle-acceptance.py",
        )
        assert readiness and readiness.loader
        module = importlib.util.module_from_spec(readiness)
        readiness.loader.exec_module(module)
        report = module.driver_readiness(ROOT)
        record = next(item for item in report["drivers"]
                      if item["driver"] == "research-qualification-fixture")
        self.assertTrue(record["source_complete"])
        self.assertTrue(record["physical_eligibility"])
        self.assertEqual(
            record["installation_error"],
            "protected_driver_source_commit_required",
        )
        self.assertEqual(record["missing"], [])


if __name__ == "__main__":
    unittest.main()
