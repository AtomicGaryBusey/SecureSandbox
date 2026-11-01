#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_scenario_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-scenario-supervisor.py",
)
supervisor = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(supervisor)
PROJECTION_SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_scenario_projection",
    ROOT / "scripts/harness-lifecycle-acceptance-scenario-observe.py",
)
projection = importlib.util.module_from_spec(PROJECTION_SPEC)
assert PROJECTION_SPEC.loader is not None
PROJECTION_SPEC.loader.exec_module(projection)

import harness_generation_store as generation_store  # noqa: E402
import harness_lifecycle_acceptance as acceptance  # noqa: E402
import harness_lifecycle_acceptance_scenarios as scenarios  # noqa: E402


NOW = 2_000_000_000
OPERATOR_UID = os.geteuid() or 501
SCAN = {
    "schema": "secure-sandbox-harness-lifecycle-acceptance-scenario-scan-v1",
    "status": "absent", "present_environment": [], "present_paths": [],
    "present_keychain_services": [],
}


class ScenarioSupervisorTests(unittest.TestCase):
    def campaign(self) -> dict:
        value = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": str(uuid.uuid4()),
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "2" * 40,
            "created_at": NOW - 60, "expires_at": NOW + 3600,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        value["campaign_sha256"] = acceptance.digest(value)
        return value

    def authorization(self, plan: dict) -> dict:
        value = {
            "schema": generation_store.AUTHORIZATION_SCHEMA,
            "authorization_id": str(uuid.uuid4()),
            "plan_id": plan["plan_id"], "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"],
            "operation": plan["operation"], "method": "touch-id",
            "password_fallback": False, "authorized_at": NOW,
            "expires_at": NOW + 120,
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
        }
        value["authorization_sha256"] = generation_store.sha256_value(value)
        return value

    def test_projection_map_covers_every_scenario_evidence_authority(self):
        paths = {
            name: Path("/protected") / f"{name}.json" for name in (
                "broker-receipt", "research-result", "host-readback",
                "control-readback",
            )
        }
        for case_id in scenarios.SCENARIO_CASES:
            for kind in acceptance.CASE_BY_ID[case_id].evidence_kinds:
                arguments = projection.artifacts(kind, paths)
                collector = acceptance.EVIDENCE_KIND_COLLECTOR[kind]
                self.assertEqual(
                    arguments[0][1],
                    acceptance.COLLECTOR_PRIMARY_AUTHORITY[collector],
                )

    def test_production_scan_uses_complete_shared_provider_path_inventory(self):
        absent = lambda command, **_kwargs: subprocess.CompletedProcess(
            command, 44, b"", b"",
        )
        self.assertIn(
            ".config/gcloud/credentials.db",
            supervisor.ENROLLER.PROVIDER_HOME_PATHS,
        )
        self.assertIn(
            ".azure/msal_token_cache.json",
            supervisor.ENROLLER.PROVIDER_HOME_PATHS,
        )
        for relative in (
            ".config/gcloud/credentials.db",
            ".azure/msal_token_cache.json",
        ):
            with self.subTest(relative=relative), \
                    tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                marker = home / relative
                marker.parent.mkdir(parents=True)
                marker.touch()
                with self.assertRaisesRegex(
                    supervisor.ScenarioSupervisorError,
                    "production_material_present",
                ):
                    supervisor.production_scan(home, {}, absent)

    def receipt(self, campaign: dict, plan: dict, authorization: dict,
                result: dict) -> dict:
        return {
            "schema": "secure-sandbox-operator-authorization-receipt-v1",
            "request_id": authorization["authorization_id"],
            "request_sha256": "5" * 64, "status": "succeeded",
            "started_at": NOW, "completed_at": NOW,
            "operation": "harness-acceptance-authorize",
            "declared_agent": "Codex", "declared_session": "scenario-test",
            "identity_evidence": "operator-declared",
            "authorization_method": "touch-id", "ceremony": "approve",
            "purpose": "Verify isolated lifecycle scenario",
            "resource": "Disposable harness lifecycle acceptance plan",
            "exit_status": 0,
            "stdout_sha256": hashlib.sha256(
                acceptance.canonical(result),
            ).hexdigest(),
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "host_release_id": "6" * 64,
            "acceptance_campaign_sha256": campaign["campaign_sha256"],
            "acceptance_case_id": plan["case_id"],
            "acceptance_generation_id": plan["generation_id"],
            "acceptance_operator_uid": plan["operator_uid"],
            "acceptance_plan_sha256": plan["plan_sha256"],
            "acceptance_source_commit": campaign["source_commit"],
        }

    def test_prepare_and_execute_noninteractive_research_result(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"; root.mkdir(mode=0o700)
            home = Path(temporary) / "home"; home.mkdir(mode=0o700)
            with mock.patch.object(
                    supervisor.AUTH, "protected_context", return_value=campaign), \
                    mock.patch.object(
                        supervisor.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))):
                prepared = supervisor.prepare(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    deployer=lambda *_args: None, scanner=lambda *_args: SCAN,
                )
                result = supervisor.execute(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    research_runner=lambda c, i, _g, p, a: scenarios.execute_case(
                        c, i, scenarios.initial_state(c, i, now=NOW),
                        plan=p, authorization=a, now=NOW,
                    ),
                )
            self.assertIsNone(prepared["plan"])
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["candidate_authority"], "none")

    def test_touchid_plan_is_exactly_bound_before_research_execution(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"; root.mkdir(mode=0o700)
            home = Path(temporary) / "home"; home.mkdir(mode=0o700)
            with mock.patch.object(
                    supervisor.AUTH, "protected_context", return_value=campaign), \
                    mock.patch.object(
                        supervisor.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))):
                prepared = supervisor.prepare(
                    "management", "rollback-explicit", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    deployer=lambda *_args: None, scanner=lambda *_args: SCAN,
                )
                plan = prepared["plan"]
                authorization = self.authorization(plan)
                result = supervisor.execute(
                    "management", "rollback-explicit", OPERATOR_UID,
                    plan=plan, authorization=authorization,
                    root=root, uid=os.geteuid(), now=NOW,
                    research_runner=lambda c, i, _g, p, a: scenarios.execute_case(
                        c, i, scenarios.initial_state(c, i, now=NOW),
                        plan=p, authorization=a, now=NOW,
                    ),
                )
                changed = dict(plan); changed["generation_id"] = "f" * 64
                with self.assertRaisesRegex(
                        supervisor.ScenarioSupervisorError, "plan_changed"):
                    supervisor.execute(
                        "management", "rollback-explicit", OPERATOR_UID,
                        plan=changed, authorization=self.authorization(plan),
                        root=root, uid=os.geteuid(), now=NOW,
                        research_runner=lambda *_args: result,
                    )
                different_authorization = self.authorization(plan)
                with mock.patch.object(supervisor, "run_research") as rerun, \
                        self.assertRaisesRegex(
                            supervisor.AUTH.AuthorizationDriverError,
                            "existing_record_mismatch"):
                    supervisor.execute(
                        "management", "rollback-explicit", OPERATOR_UID,
                        plan=plan, authorization=different_authorization,
                        root=root, uid=os.geteuid(), now=NOW,
                        research_runner=rerun,
                    )
                rerun.assert_not_called()
            self.assertEqual(
                result["authorization_sha256"],
                authorization["authorization_sha256"],
            )
            self.assertEqual(result["after_state"]["active_generation_id"],
                             prepared["plan"]["generation_id"])

    def test_finalize_binds_broker_receipt_and_honest_host_projection(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"; root.mkdir(mode=0o700)
            receipts = Path(temporary) / "receipts"; receipts.mkdir(mode=0o700)
            home = Path(temporary) / "home"; home.mkdir(mode=0o700)
            with mock.patch.object(
                    supervisor.AUTH, "protected_context", return_value=campaign), \
                    mock.patch.object(
                        supervisor.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))):
                prepared = supervisor.prepare(
                    "management", "rollback-explicit", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    deployer=lambda *_args: None, scanner=lambda *_args: SCAN,
                )
                plan = prepared["plan"]; authorization = self.authorization(plan)
                result = supervisor.execute(
                    "management", "rollback-explicit", OPERATOR_UID,
                    plan=plan, authorization=authorization,
                    root=root, uid=os.geteuid(), now=NOW,
                    research_runner=lambda c, i, _g, p, a: scenarios.execute_case(
                        c, i, scenarios.initial_state(c, i, now=NOW),
                        plan=p, authorization=a, now=NOW,
                    ),
                )
                receipt = self.receipt(campaign, plan, authorization, result)
                receipt_path = receipts / f"{authorization['authorization_id']}.json"
                receipt_path.write_bytes(acceptance.canonical(receipt)); receipt_path.chmod(0o600)
                finalized = supervisor.finalize(
                    "management", "rollback-explicit", OPERATOR_UID,
                    request_id=authorization["authorization_id"], root=root,
                    receipt_root=receipts, uid=os.geteuid(), now=NOW,
                )
            state = (root / campaign["campaign_id"] / "interactive"
                     / "management" / "rollback-explicit")
            host = json.loads((state / "host-readback.json").read_text())
            self.assertEqual(finalized["status"], "verified")
            self.assertEqual(host["research_result_sha256"], result["result_sha256"])
            self.assertEqual(host["evidence"], result["evidence"])
            self.assertNotIn("authority", host)

    def test_noninteractive_finalize_rejects_request_id(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"; root.mkdir(mode=0o700)
            home = Path(temporary) / "home"; home.mkdir(mode=0o700)
            with mock.patch.object(
                    supervisor.AUTH, "protected_context", return_value=campaign), \
                    mock.patch.object(
                        supervisor.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))):
                supervisor.prepare(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    deployer=lambda *_args: None, scanner=lambda *_args: SCAN,
                )
                supervisor.execute(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    research_runner=lambda c, i, _g, p, a: scenarios.execute_case(
                        c, i, scenarios.initial_state(c, i, now=NOW),
                        plan=p, authorization=a, now=NOW,
                    ),
                )
                first = supervisor.finalize(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                )
                resumed = supervisor.finalize(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW + 1,
                )
                self.assertEqual(resumed, first)
                with self.assertRaisesRegex(
                        supervisor.ScenarioSupervisorError, "request_id_forbidden"):
                    supervisor.finalize(
                        "runtime", "activate-future-session", OPERATOR_UID,
                        request_id=str(uuid.uuid4()), root=root,
                        uid=os.geteuid(), now=NOW,
                    )

    def test_projection_preserves_collector_authority_assignments(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"; root.mkdir(mode=0o700)
            home = Path(temporary) / "home"; home.mkdir(mode=0o700)
            observations = (home / supervisor.AUTH.CAMPAIGN_RELATIVE
                            / "observations")
            observations.mkdir(mode=0o700, parents=True)
            with mock.patch.object(
                    supervisor.AUTH, "protected_context", return_value=campaign), \
                    mock.patch.object(
                        projection.SUPERVISOR.AUTH, "protected_context",
                        return_value=campaign), \
                    mock.patch.object(
                        supervisor.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))), \
                    mock.patch.object(
                        projection.SUPERVISOR.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))):
                supervisor.prepare(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    deployer=lambda *_args: None, scanner=lambda *_args: SCAN,
                )
                supervisor.execute(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                    research_runner=lambda c, i, _g, p, a: scenarios.execute_case(
                        c, i, scenarios.initial_state(c, i, now=NOW),
                        plan=p, authorization=a, now=NOW,
                    ),
                )
                supervisor.finalize(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                )
                projected = projection.project(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                )
            selector = json.loads(
                (observations / "activate-future-session.selector-readback.json")
                .read_text()
            )
            session = json.loads(
                (observations / "activate-future-session.session-binding.json")
                .read_text()
            )
            self.assertEqual(projected["status"], "recorded")
            self.assertEqual(
                selector["evidence"]["artifacts"][0]["authority"],
                "protected-research",
            )
            self.assertEqual(
                session["evidence"]["artifacts"][0]["authority"],
                "protected-host",
            )
            state = (root / campaign["campaign_id"] / "interactive"
                     / "runtime" / "activate-future-session")
            host_path = state / "host-readback.json"
            host = json.loads(host_path.read_text())
            host["evidence"] = {"forged": True}
            host["readback_sha256"] = acceptance.digest({
                name: item for name, item in host.items()
                if name != "readback_sha256"
            })
            host_path.chmod(0o600)
            host_path.write_bytes(acceptance.canonical(host)); host_path.chmod(0o400)
            with mock.patch.object(
                    projection.SUPERVISOR.AUTH, "protected_context",
                    return_value=campaign), \
                    mock.patch.object(
                        projection.SUPERVISOR.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))), \
                    self.assertRaisesRegex(
                        projection.ScenarioProjectionError,
                        "projection_finalized_invalid"):
                projection.project(
                    "runtime", "activate-future-session", OPERATOR_UID,
                    root=root, uid=os.geteuid(), now=NOW,
                )

    def test_deployment_failure_is_reserved_and_blocks_execution(self):
        campaign = self.campaign()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"; root.mkdir(mode=0o700)
            home = Path(temporary) / "home"; home.mkdir(mode=0o700)
            def fail_deploy(*_args):
                raise RuntimeError("deployment failed")
            with mock.patch.object(
                    supervisor.AUTH, "protected_context", return_value=campaign), \
                    mock.patch.object(
                        supervisor.AUTH.pwd, "getpwuid",
                        return_value=SimpleNamespace(pw_dir=str(home))):
                with self.assertRaisesRegex(RuntimeError, "deployment failed"):
                    supervisor.prepare(
                        "runtime", "activate-future-session", OPERATOR_UID,
                        root=root, uid=os.geteuid(), now=NOW,
                        deployer=fail_deploy,
                        scanner=lambda *_args: SCAN,
                    )
                state = (root / campaign["campaign_id"] / "interactive"
                         / "runtime" / "activate-future-session")
                self.assertTrue((state / "failure.json").is_file())
                with self.assertRaisesRegex(
                        supervisor.ScenarioSupervisorError, "prior_failure"):
                    supervisor.execute(
                        "runtime", "activate-future-session", OPERATOR_UID,
                        root=root, uid=os.geteuid(), now=NOW,
                        research_runner=lambda *_args: {},
                    )


if __name__ == "__main__":
    unittest.main()
