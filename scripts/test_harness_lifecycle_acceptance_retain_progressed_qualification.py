#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "retain_progressed_qualification",
    ROOT / "scripts/harness-lifecycle-acceptance-retain-progressed-qualification.py",
)
assert SPEC and SPEC.loader
retention = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retention)
acceptance = retention.sys.modules["harness_lifecycle_acceptance"]


class ProgressedQualificationRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.uid = os.geteuid()
        now = int(time.time())
        self.campaign = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": now - 60,
            "expires_at": now + 3600,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        self.campaign["campaign_sha256"] = acceptance.digest(self.campaign)
        self.root = self.home / retention.RETENTION.CAMPAIGN_RELATIVE
        observations = self.root / "observations"
        bootstrap = self.root / "raw/bootstrap"
        qualification = self.root / "raw/qualification"
        recovery = self.root / "raw/recovery"
        for path in (
            self.root, observations, self.root / "raw", bootstrap,
            qualification, recovery,
        ):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)
        (self.root / "campaign.json").write_bytes(
            acceptance.canonical(self.campaign),
        )
        (self.root / "campaign.json").chmod(0o600)
        reserved_bootstrap = bootstrap / retention.RETENTION.RESERVED_CASE_ID
        reserved_bootstrap.mkdir(mode=0o700)
        for name in retention.RETENTION.OWNER_PROJECTION_RAW_FILES.values():
            path = reserved_bootstrap / name
            path.write_bytes(acceptance.canonical({"name": name}))
            path.chmod(0o600)
        home_bootstrap = bootstrap / retention.RETENTION.HOME_REJECTION_CASE_ID
        home_bootstrap.mkdir(mode=0o700)
        for name in ("machine-enrollment.json", "production-material-scan.json"):
            path = home_bootstrap / name
            path.write_bytes(acceptance.canonical({"name": name}))
            path.chmod(0o600)
        completed = qualification / retention.COMPLETED_CASE_ID
        completed.mkdir(mode=0o700)
        for name in retention.QUALIFICATION_RAW:
            path = completed / name
            path.write_bytes(acceptance.canonical({"name": name}))
            path.chmod(0o600)
        (qualification / retention.RESERVED_CASE_ID).mkdir(mode=0o700)
        reserved_index = next(
            index for index, case in enumerate(acceptance.CASES)
            if case.case_id == retention.RESERVED_CASE_ID
        )
        for case in acceptance.CASES[:reserved_index]:
            for kind in case.evidence_kinds:
                path = observations / f"{case.case_id}.{kind}.json"
                path.write_bytes(acceptance.canonical({
                    "case_id": case.case_id, "kind": kind,
                }))
                path.chmod(0o444)
        handoff = self.home / retention.RETENTION.RETAINED_RELATIVE.parent
        handoff.mkdir(mode=0o700)
        handoff.chmod(0o700)
        self.supervisor = self.home / "supervisor.txt"
        self.supervisor.write_text(
            "Traceback (most recent call last):\n"
            "SupervisorError: supervisor_command_rejected\n",
        )
        self.supervisor.chmod(0o600)
        self.audit = self.home / "audit.json"
        failed_request = str(uuid.uuid4())
        audit = {
            "authority": "diagnostic-only",
            "campaign_id": self.campaign["campaign_id"],
            "case_id": retention.RESERVED_CASE_ID,
            "claude_process_present": False,
            "control_audit_tail": [
                {
                    "timestamp": now - 10, "outcome": "accepted",
                    "kind": "deploy",
                    "operation": "install-harness-lifecycle-acceptance-qualification.sh",
                    "error": "", "request_id": str(uuid.uuid4()),
                },
                {
                    "timestamp": now - 5, "outcome": "started",
                    "kind": "deploy",
                    "operation": "install-harness-lifecycle-acceptance-qualification.sh",
                    "error": "", "request_id": failed_request,
                },
                {
                    "timestamp": now - 5, "outcome": "command_failed",
                    "kind": "deploy",
                    "operation": "install-harness-lifecycle-acceptance-qualification.sh",
                    "error": "status_1", "request_id": failed_request,
                },
            ],
            "files": {},
            "fixture_inventory": [retention.COMPLETED_CASE_ID],
            "guard_path_presence": {
                "/run/secure-sandbox/evidence-run-id": False,
                "/run/secure-sandbox/run-id": False,
                "/var/lib/secure-sandbox/run-lifecycle/active.json": False,
                "/var/lib/secure-sandbox/run-lifecycle/failure-latched.json": False,
            },
            "installed_release_mismatches": [],
            "release": self.campaign["source_commit"],
            "research_campaign_match": True,
            "schema": "secure-sandbox-qualification-research-diagnostic-v1",
            "status": "observed",
        }
        self.audit.write_bytes(acceptance.canonical(audit))
        self.audit.chmod(0o600)
        self.diagnostic_source = self.home / "diagnostic.sh"
        self.diagnostic_source.write_bytes((
            ROOT / "scripts/"
            "install-harness-lifecycle-acceptance-qualification-control-diagnostic.sh"
        ).read_bytes())
        self.diagnostic_source.chmod(0o700)
        self.reviewed_diagnostic = self.diagnostic_source.read_bytes()

    @staticmethod
    def next_case() -> dict:
        case = acceptance.CASE_BY_ID[retention.RESERVED_CASE_ID]
        return {"status": "pending", "case": acceptance.case_record(case)}

    @staticmethod
    def rename(source: int, source_name: str,
               destination: int, destination_name: str) -> None:
        os.rename(
            source_name, destination_name,
            src_dir_fd=source, dst_dir_fd=destination,
        )

    def test_retains_exact_progressed_layout_without_rewriting_evidence(self):
        evidence_before = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in self.root.rglob("*.json")
        }
        replacement = "3" * 40
        tips = {
            name: replacement
            for name, _url in retention.RETENTION.PREFLIGHT.AUTHORIZED_REMOTES
        }
        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(retention.RETENTION, "acl_absent", return_value=True), \
                mock.patch.object(retention.RETENTION, "_is_ancestor"), \
                mock.patch.object(
                    retention, "verify_completed_binding",
                    return_value="5" * 64), \
                mock.patch.object(
                    retention.ACCEPTANCE_CLI, "next_case",
                    return_value=self.next_case()):
            result = retention.retain(
                expected_campaign_id=self.campaign["campaign_id"],
                expected_source_commit=self.campaign["source_commit"],
                acknowledgement=retention.ACKNOWLEDGEMENT,
                supervisor_output=self.supervisor,
                control_audit=self.audit,
                diagnostic_source=self.diagnostic_source,
                home=self.home,
                protected_uid=self.uid,
                source_probe=lambda: (replacement, tips),
                identity_probe=lambda: self.campaign["machine_identity_sha256"],
                predecessor_probe=lambda _commit: "4" * 64,
                diagnostic_probe=lambda _commit: self.reviewed_diagnostic,
                rename=self.rename,
            )
        destination = (
            self.home / retention.RETENTION.RETAINED_RELATIVE
            / self.campaign["campaign_id"]
        )
        self.assertFalse(self.root.exists())
        self.assertEqual(result["status"], "retained")
        self.assertEqual(result["completed_case_count"], 31)
        self.assertEqual(result["completed_observation_count"], 36)
        self.assertEqual(result["reserved_case_id"], retention.RESERVED_CASE_ID)
        for relative, payload in evidence_before.items():
            self.assertEqual((destination / relative).read_bytes(), payload)
        failure = json.loads((
            destination / "raw/qualification" / retention.RESERVED_CASE_ID
            / retention.FAILURE_NAME
        ).read_bytes())
        self.assertIs(failure["retry_permitted"], False)
        self.assertEqual(result["failure_record_sha256"], failure["rejection_sha256"])

    def test_retains_current_canonical_supervisor_rejection_without_overwrite(self):
        audit = json.loads(self.audit.read_bytes())
        failed_at = audit["control_audit_tail"][-1]["timestamp"]
        case = acceptance.CASE_BY_ID[retention.RESERVED_CASE_ID]
        rejection = {
            "schema": retention.SUPERVISOR_REJECTION_SCHEMA,
            "status": "rejected",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "source_commit": self.campaign["source_commit"],
            "case_id": retention.RESERVED_CASE_ID,
            "procedure_sha256": acceptance.case_record(case)["procedure"][
                "procedure_sha256"
            ],
            "observed_at": failed_at,
            "error": retention.SUPERVISOR_ERROR,
            "control_boundary": "authenticated-privileged-control",
            "research_case_state": "unresolved-before-result",
            "retry_permitted": False,
            "candidate_authority": "none",
            "production_material_used": False,
        }
        rejection["rejection_sha256"] = acceptance.digest(rejection)
        reservation = (
            self.root / "raw/qualification" / retention.RESERVED_CASE_ID
        )
        rejection_path = reservation / retention.FAILURE_NAME
        rejection_payload = acceptance.canonical(rejection)
        rejection_path.write_bytes(rejection_payload)
        rejection_path.chmod(0o600)
        self.supervisor.write_bytes(acceptance.canonical({
            "schema": retention.SUPERVISOR_ERROR_SCHEMA,
            "status": "rejected",
            "error": retention.SUPERVISOR_OUTPUT_ERROR,
        }))
        replacement = "3" * 40
        tips = {
            name: replacement
            for name, _url in retention.RETENTION.PREFLIGHT.AUTHORIZED_REMOTES
        }
        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(retention.RETENTION, "acl_absent", return_value=True), \
                mock.patch.object(retention.RETENTION, "_is_ancestor"), \
                mock.patch.object(retention, "verify_completed_binding",
                                  return_value="5" * 64), \
                mock.patch.object(retention.ACCEPTANCE_CLI, "next_case",
                                  return_value=self.next_case()):
            result = retention.retain(
                expected_campaign_id=self.campaign["campaign_id"],
                expected_source_commit=self.campaign["source_commit"],
                acknowledgement=retention.ACKNOWLEDGEMENT,
                supervisor_output=self.supervisor,
                control_audit=self.audit,
                diagnostic_source=self.diagnostic_source,
                home=self.home,
                protected_uid=self.uid,
                source_probe=lambda: (replacement, tips),
                identity_probe=lambda: self.campaign["machine_identity_sha256"],
                predecessor_probe=lambda _commit: "4" * 64,
                diagnostic_probe=lambda _commit: self.reviewed_diagnostic,
                rename=self.rename,
            )
        destination = (
            self.home / retention.RETENTION.RETAINED_RELATIVE
            / self.campaign["campaign_id"] / "raw/qualification"
            / retention.RESERVED_CASE_ID
        )
        self.assertEqual((destination / retention.FAILURE_NAME).read_bytes(),
                         rejection_payload)
        diagnostic = json.loads((
            destination / retention.RETENTION_DIAGNOSTIC_NAME
        ).read_bytes())
        self.assertEqual(diagnostic["schema"], retention.FAILURE_SCHEMA_V2)
        self.assertEqual(diagnostic["supervisor_rejection_sha256"],
                         rejection["rejection_sha256"])
        self.assertEqual(result["failure_record_sha256"],
                         diagnostic["rejection_sha256"])

    def test_rejects_audit_without_exact_failed_control_event(self):
        audit = json.loads(self.audit.read_bytes())
        audit["control_audit_tail"] = audit["control_audit_tail"][:1]
        self.audit.write_bytes(acceptance.canonical(audit))
        with mock.patch.object(retention.RETENTION, "acl_absent", return_value=True), \
                self.assertRaisesRegex(
                    retention.ProgressedQualificationRetentionError,
                    "progressed_qualification_control_audit_invalid"):
            retention.failure_record(
                self.campaign, self.supervisor, self.audit,
                self.diagnostic_source,
                self.reviewed_diagnostic, self.uid, int(time.time()),
            )

    def test_rejects_substituted_diagnostic_source(self):
        self.diagnostic_source.write_bytes(
            self.diagnostic_source.read_bytes() + b"\n# substituted\n",
        )
        with mock.patch.object(retention.RETENTION, "acl_absent", return_value=True), \
                self.assertRaisesRegex(
                    retention.ProgressedQualificationRetentionError,
                    "progressed_qualification_diagnostic_source_mismatch"):
            retention.failure_record(
                self.campaign, self.supervisor, self.audit,
                self.diagnostic_source,
                self.reviewed_diagnostic, self.uid, int(time.time()),
            )

    def test_source_preflight_failure_precedes_first_campaign_mutation(self):
        reservation = (
            self.root / "raw/qualification" / retention.RESERVED_CASE_ID
        )
        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(
                    retention.RETENTION, "acl_absent", return_value=True), \
                self.assertRaisesRegex(
                    retention.ProgressedQualificationRetentionError,
                    "progressed_qualification_source_preflight_failed"):
            retention.retain(
                expected_campaign_id=self.campaign["campaign_id"],
                expected_source_commit=self.campaign["source_commit"],
                acknowledgement=retention.ACKNOWLEDGEMENT,
                supervisor_output=self.supervisor,
                control_audit=self.audit,
                diagnostic_source=self.diagnostic_source,
                home=self.home,
                protected_uid=self.uid,
                source_probe=mock.Mock(side_effect=
                    retention.RETENTION.PREFLIGHT.PreflightError("unavailable")),
            )
        self.assertEqual(list(reservation.iterdir()), [])

    def test_existing_plan_resumes_after_pre_rename_interruption(self):
        replacement = "3" * 40
        tips = {
            name: replacement
            for name, _url in retention.RETENTION.PREFLIGHT.AUTHORIZED_REMOTES
        }
        common = {
            "expected_campaign_id": self.campaign["campaign_id"],
            "expected_source_commit": self.campaign["source_commit"],
            "acknowledgement": retention.ACKNOWLEDGEMENT,
            "supervisor_output": self.supervisor,
            "control_audit": self.audit,
            "diagnostic_source": self.diagnostic_source,
            "home": self.home,
            "protected_uid": self.uid,
            "source_probe": lambda: (replacement, tips),
            "identity_probe": lambda: self.campaign["machine_identity_sha256"],
            "predecessor_probe": lambda _commit: "4" * 64,
            "diagnostic_probe": lambda _commit: self.reviewed_diagnostic,
        }
        def interrupted(*_args):
            raise OSError("injected-before-rename")

        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(retention.RETENTION, "acl_absent", return_value=True), \
                mock.patch.object(retention.RETENTION, "_is_ancestor"), \
                mock.patch.object(retention, "verify_completed_binding",
                                  return_value="5" * 64), \
                mock.patch.object(retention.ACCEPTANCE_CLI, "next_case",
                                  return_value=self.next_case()), \
                self.assertRaisesRegex(OSError, "injected-before-rename"):
            retention.retain(**common, rename=interrupted)
        self.assertTrue((self.root / retention.RETENTION.PLAN_NAME).is_file())
        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(retention.RETENTION, "acl_absent", return_value=True), \
                mock.patch.object(retention.RETENTION, "_is_ancestor"), \
                mock.patch.object(retention, "verify_completed_binding",
                                  return_value="5" * 64), \
                mock.patch.object(retention.ACCEPTANCE_CLI, "next_case",
                                  return_value=self.next_case()):
            result = retention.retain(**common, rename=self.rename)
        self.assertEqual(result["status"], "retained")


if __name__ == "__main__":
    unittest.main()
