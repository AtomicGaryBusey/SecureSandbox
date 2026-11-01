#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import harness_generation_store as store
import harness_lifecycle_acceptance as acceptance
import harness_lifecycle_acceptance_interactive as interactive


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_authorization",
    ROOT / "scripts/harness-lifecycle-acceptance-authorization.py",
)
assert SPEC and SPEC.loader
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)
PROJECTION_SPEC = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_authorization_observe",
    ROOT / "scripts/harness-lifecycle-acceptance-authorization-observe.py",
)
assert PROJECTION_SPEC and PROJECTION_SPEC.loader
projection = importlib.util.module_from_spec(PROJECTION_SPEC)
PROJECTION_SPEC.loader.exec_module(projection)
NOW = 2_000_000_000


class AuthorizationConsumerTests(unittest.TestCase):
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

    @staticmethod
    def authorization(plan: dict) -> dict:
        value = {
            "schema": store.AUTHORIZATION_SCHEMA,
            "authorization_id": str(uuid.uuid4()), "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"],
            "transaction_id": plan["transaction_id"], "operation": plan["operation"],
            "method": "touch-id", "password_fallback": False,
            "authorized_at": NOW, "expires_at": NOW + 120,
            "requesting_agent_sha256": "3" * 64,
            "requesting_session_sha256": "4" * 64,
        }
        value["authorization_sha256"] = store.sha256_value(value)
        return value

    @staticmethod
    def broker_receipt(plan: dict, request_id: str, *, status: str,
                       stdout: bytes = b"", stderr: bytes = b"",
                       cancelled: bool = False) -> dict:
        value = {
            "schema":"secure-sandbox-operator-authorization-receipt-v1",
            "request_id":request_id, "request_sha256":"6" * 64,
            "status":"cancelled" if cancelled else status,
            "started_at":NOW, "completed_at":NOW,
            "operation":"harness-acceptance-authorize",
            "declared_agent":"Codex", "declared_session":"acceptance-test",
            "identity_evidence":"operator-declared", "authorization_method":"touch-id",
            "ceremony":"cancel-test" if cancelled else "approve",
            "purpose":"Verify disposable acceptance authorization",
            "resource":"Disposable harness lifecycle acceptance plan",
            "exit_status":20 if cancelled else (0 if status == "succeeded" else 1),
            "stdout_sha256":hashlib.sha256(stdout).hexdigest(),
            "stderr_sha256":hashlib.sha256(stderr).hexdigest(),
            "host_release_id":"7" * 64,
            "acceptance_campaign_sha256":plan["campaign_sha256"],
            "acceptance_case_id":plan["case_id"],
            "acceptance_generation_id":plan["generation_id"],
            "acceptance_operator_uid":plan["operator_uid"],
            "acceptance_plan_sha256":plan["plan_sha256"],
            "acceptance_source_commit":plan["source_commit"],
        }
        if cancelled:
            value.update({
                "authorization_ui_bundle_sha256":"8" * 64,
                "outcome":"cancelled",
            })
        return value

    def state(self, root: Path, campaign: dict, plan: dict) -> Path:
        state = (root / campaign["campaign_id"] / "interactive" / "authorization"
                 / plan["case_id"])
        state.mkdir(mode=0o700, parents=True)
        for parent in (
                root, root / campaign["campaign_id"],
                root / campaign["campaign_id"] / "interactive", state.parent, state):
            parent.chmod(0o700)
        store = driver.isolated_store(root, campaign["campaign_id"], os.geteuid())
        store.prepare()
        store_status = driver.validate_isolated_store(store.inspect_status())
        files = {
            "campaign.json": (campaign, 0o400), "plan.json": (plan, 0o400),
            "ledger.json": (interactive.empty_ledger(campaign), 0o600),
            "store-before.json": (store_status, 0o400),
        }
        for name, (value, mode) in files.items():
            path = state / name; path.write_bytes(acceptance.canonical(value)); path.chmod(mode)
        return state

    def test_consumer_atomically_advances_ledger_and_publishes_immutable_result(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-approve-exact-plan", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        authorization = self.authorization(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            state = self.state(root, campaign, plan)
            result = driver.consume_request(
                plan, authorization, root=root, uid=os.geteuid(), now=NOW,
            )
            ledger = json.loads((state / "ledger.json").read_text())
            output = state / f"result-{authorization['authorization_sha256']}.json"
            self.assertEqual(ledger["epoch"], 1)
            self.assertEqual(output.stat().st_mode & 0o777, 0o400)
            self.assertEqual(result["candidate_authority"], "none")
            self.assertFalse(result["production_store_access"])
            with self.assertRaisesRegex(driver.AuthorizationDriverError, "replayed"):
                driver.consume_request(
                    plan, authorization, root=root, uid=os.geteuid(), now=NOW,
                )

    def test_publish_exact_recovers_completed_link_after_interrupted_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            value = {"schema": "secure-sandbox-test-v1", "status": "verified"}
            alias = root / ".record.json.publish-interrupted"
            alias.write_bytes(acceptance.canonical(value))
            alias.chmod(0o400)
            destination = root / "record.json"
            os.link(alias, destination)
            self.assertEqual(destination.stat().st_nlink, 2)

            driver.publish_exact(destination, value, os.geteuid(), 0o400)

            self.assertFalse(alias.exists())
            self.assertEqual(destination.stat().st_nlink, 1)
            self.assertEqual(
                driver.trusted_json(destination, os.geteuid(), 0o400), value,
            )

    def test_changed_plan_rejects_without_advancing_ledger(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-changed-plan", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        changed = interactive.make_plan(
            campaign, "touchid-changed-plan", "authorize", "6" * 64,
            os.geteuid() or 501, NOW,
            plan_id=plan["plan_id"], transaction_id=plan["transaction_id"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            state = self.state(root, campaign, plan)
            before = (state / "ledger.json").read_bytes()
            with self.assertRaisesRegex(driver.AuthorizationDriverError, "plan_changed"):
                driver.consume_request(
                    changed, self.authorization(changed), root=root,
                    uid=os.geteuid(), now=NOW,
                )
            self.assertEqual((state / "ledger.json").read_bytes(), before)
            self.assertFalse(list(state.glob("result-*.json")))

    def test_transaction_recovery_finishes_ledger_and_result_before_replay_rejects(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-replay", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        authorization = self.authorization(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            state = self.state(root, campaign, plan)
            prior = interactive.empty_ledger(campaign)
            result, next_ledger = interactive.consume(
                plan, plan, authorization, prior, campaign, NOW,
            )
            journal = {
                "schema":
                    "secure-sandbox-harness-lifecycle-acceptance-authorization-transaction-v1",
                "campaign_id": campaign["campaign_id"],
                "campaign_sha256": campaign["campaign_sha256"],
                "prior_ledger_sha256": prior["ledger_sha256"],
                "next_ledger": next_ledger, "result": result,
            }
            journal["journal_sha256"] = acceptance.digest(journal)
            path = state / "transaction.json"
            path.write_bytes(acceptance.canonical(journal)); path.chmod(0o600)
            driver.recover_transaction(state, campaign, os.geteuid())
            self.assertFalse(path.exists())
            self.assertEqual(
                json.loads((state / "ledger.json").read_text()), next_ledger,
            )
            self.assertTrue(
                (state / f"result-{authorization['authorization_sha256']}.json").is_file(),
            )
            with self.assertRaisesRegex(driver.AuthorizationDriverError, "replayed"):
                driver.consume_request(
                    plan, authorization, root=root, uid=os.geteuid(), now=NOW,
                )

    def test_replay_case_consumes_once_then_rejects_without_second_authorization(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-replay", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        authorization = self.authorization(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            state = self.state(root, campaign, plan)
            with self.assertRaisesRegex(
                    driver.AuthorizationDriverError, "authorization_replayed"):
                driver.consume_request(
                    plan, authorization, root=root, uid=os.geteuid(), now=NOW,
                )
            ledger = json.loads((state / "ledger.json").read_text())
            self.assertEqual(ledger["epoch"], 1)
            self.assertEqual(
                ledger["consumed_authorization_sha256"],
                [authorization["authorization_sha256"]],
            )
            self.assertTrue(
                (state / f"result-{authorization['authorization_sha256']}.json").is_file(),
            )

    def test_cli_has_no_state_root_or_campaign_override(self):
        help_text = driver.parser().format_help()
        self.assertNotIn("state-root", help_text)
        self.assertNotIn("campaign", help_text)

    def test_operator_uid_mismatch_rejects_before_state_access(self):
        campaign = self.campaign()
        plan = interactive.make_plan(
            campaign, "touchid-approve-exact-plan", "authorize", "5" * 64,
            os.geteuid() or 501, NOW,
        )
        with self.assertRaisesRegex(driver.AuthorizationDriverError, "operator_uid_mismatch"):
            driver.consume_request(
                plan, self.authorization(plan), root=Path("/does/not/exist"),
                uid=os.geteuid(), operator_uid=plan["operator_uid"] + 1, now=NOW,
            )

    def test_prepare_creates_distinct_closed_case_state_and_request_variants(self):
        campaign = self.campaign()
        operator_uid = os.geteuid() or 501
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o700)
            changed = driver.prepare_case(
                campaign, "touchid-changed-plan", operator_uid,
                root=root, uid=os.geteuid(), now=NOW,
            )
            wrong = driver.prepare_case(
                campaign, "touchid-wrong-generation", operator_uid,
                root=root, uid=os.geteuid(), now=NOW,
            )
            changed_state = (root / campaign["campaign_id"] / "interactive"
                             / "authorization" / "touchid-changed-plan")
            stored = json.loads((changed_state / "plan.json").read_text())
            requested = json.loads((changed_state / "request-plan.json").read_text())
            self.assertNotEqual(stored["plan_sha256"], requested["plan_sha256"])
            self.assertEqual(stored["generation_id"], requested["generation_id"])
            wrong_state = changed_state.parent / "touchid-wrong-generation"
            wrong_stored = json.loads((wrong_state / "plan.json").read_text())
            wrong_requested = json.loads((wrong_state / "request-plan.json").read_text())
            self.assertEqual(wrong_stored["plan_id"], wrong_requested["plan_id"])
            self.assertNotEqual(wrong_stored["generation_id"], wrong_requested["generation_id"])
            self.assertEqual(changed["candidate_authority"], "none")
            self.assertEqual(wrong["production_store_access"], False)
            store_status = driver.isolated_store(
                root, campaign["campaign_id"], os.geteuid(),
            ).inspect_status()
            self.assertEqual(store_status["generations"], [])
            self.assertIsNone(store_status["active_generation_id"])
            with self.assertRaisesRegex(
                    driver.AuthorizationDriverError, "already_prepared"):
                driver.prepare_case(
                    campaign, "touchid-changed-plan", operator_uid,
                    root=root, uid=os.geteuid(), now=NOW,
                )

    def test_protected_prepare_uses_fixed_operator_campaign_and_exact_next_case(self):
        campaign = self.campaign()
        operator_uid = os.geteuid() or 501
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); home = base / "home"; home.mkdir(mode=0o700)
            campaign_root = home / driver.CAMPAIGN_RELATIVE
            observations = campaign_root / "observations"
            observations.mkdir(mode=0o700, parents=True)
            campaign_root.chmod(0o700)
            campaign_path = campaign_root / "campaign.json"
            campaign_path.write_bytes(acceptance.canonical(campaign)); campaign_path.chmod(0o600)
            protected_root = base / "protected"; protected_root.mkdir(mode=0o700)
            status_store = driver.generation_store.GenerationStore(
                base / "research-release", base / "research-state", uid=os.geteuid(),
            )
            status_store.prepare(); research = status_store.inspect_status()
            case = acceptance.case_record(
                acceptance.CASE_BY_ID["touchid-approve-exact-plan"],
            )
            cli = SimpleNamespace(
                verify_protected_driver=lambda *_args, **_kwargs: {
                    "source_commit": campaign["source_commit"],
                },
                next_case=lambda *_args, **_kwargs: {"case": case},
            )
            supervisor = SimpleNamespace(
                SupervisorError=RuntimeError,
                current_machine_identity=lambda: campaign["machine_identity_sha256"],
            )
            with mock.patch.object(
                    driver.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(home))), \
                    mock.patch.object(
                        driver, "load_script", side_effect=[cli, supervisor],
                    ):
                result = driver.protected_prepare(
                    "touchid-approve-exact-plan", operator_uid,
                    root=protected_root, uid=os.geteuid(), now=NOW,
                    research_reader=lambda: research,
                )
            self.assertEqual(result["case_id"], "touchid-approve-exact-plan")
            state = (protected_root / campaign["campaign_id"] / "interactive"
                     / "authorization" / "touchid-approve-exact-plan")
            self.assertEqual(
                json.loads((state / "research-before.json").read_text()), research,
            )
            self.assertNotIn("campaign", driver.parser().format_help())
            self.assertNotIn("state-root", driver.parser().format_help())

    def test_all_six_cases_finalize_from_broker_bound_receipts_and_unchanged_research(self):
        campaign = self.campaign(); operator_uid = os.geteuid() or 501
        cases = {
            "touchid-approve-exact-plan": "authorized",
            "touchid-cancel": "cancelled",
            "touchid-expired-plan": "rejected",
            "touchid-replay": "rejected",
            "touchid-changed-plan": "rejected",
            "touchid-wrong-generation": "rejected",
        }
        for index, (case_id, expected_outcome) in enumerate(cases.items(), 1):
            with self.subTest(case_id=case_id), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); root.chmod(0o700)
                prepared = driver.prepare_case(
                    campaign, case_id, operator_uid,
                    root=root, uid=os.geteuid(), now=NOW,
                )
                plan = prepared["request_plan"]
                request_id = str(uuid.uuid4())
                state = (root / campaign["campaign_id"] / "interactive"
                         / "authorization" / case_id)
                stdout = b""; stderr = b""; status = "failed"; cancelled = False
                if case_id == "touchid-approve-exact-plan":
                    result = driver.consume_request(
                        plan, self.authorization(plan), root=root,
                        uid=os.geteuid(), operator_uid=operator_uid, now=NOW,
                    )
                    stdout = acceptance.canonical(result); status = "succeeded"
                elif case_id == "touchid-replay":
                    with self.assertRaisesRegex(
                            driver.AuthorizationDriverError, "authorization_replayed"):
                        driver.consume_request(
                            plan, self.authorization(plan), root=root,
                            uid=os.geteuid(), operator_uid=operator_uid, now=NOW,
                        )
                    stderr = driver.expected_error_bytes(case_id, request_id)
                elif case_id in {"touchid-changed-plan", "touchid-wrong-generation"}:
                    with self.assertRaisesRegex(
                            driver.AuthorizationDriverError, "plan_changed"):
                        driver.consume_request(
                            plan, self.authorization(plan), root=root,
                            uid=os.geteuid(), operator_uid=operator_uid, now=NOW,
                        )
                    stderr = driver.expected_error_bytes(case_id, request_id)
                elif case_id == "touchid-expired-plan":
                    stderr = driver.expected_error_bytes(case_id, request_id)
                else:
                    cancelled = True; status = "cancelled"
                receipt = self.broker_receipt(
                    plan, request_id, status=status, stdout=stdout,
                    stderr=stderr, cancelled=cancelled,
                )
                research = json.loads((state / "research-before.json").read_text())
                finalized = driver.finalize_case(
                    campaign, case_id, request_id, receipt, research,
                    root=root, uid=os.geteuid(), now=NOW,
                )
                self.assertEqual(finalized["outcome"], expected_outcome)
                self.assertFalse(finalized["production_store_access"])
                self.assertEqual((state / "finalized.json").stat().st_mode & 0o777, 0o400)
                resumed = driver.finalize_case(
                    campaign, case_id, request_id, receipt, research,
                    root=root, uid=os.geteuid(), now=NOW + 1,
                )
                self.assertEqual(resumed, finalized)
                paths, _raw, _finalized = projection.finalized_artifacts(
                    campaign, case_id, root, os.geteuid(), now=NOW,
                )
                projected = state / "projected-test"; projected.mkdir(mode=0o700)
                for kind in acceptance.CASE_BY_ID[case_id].evidence_kinds:
                    arguments = projection.artifact_arguments(
                        case_id, kind, paths,
                    )
                    if kind == "selector-readback":
                        self.assertEqual(arguments[0][0:2], [
                            "research-after", "protected-research",
                        ])
                        self.assertIn(
                            ["readback", "privileged-control",
                             str(paths["readback"]), projection.MEDIA_TYPE],
                            arguments,
                        )
                    if kind == "broker-rejection":
                        readback = next(
                            item for item in arguments if item[0] == "readback"
                        )
                        self.assertEqual(readback[1], "privileged-control")
                    observation = projection.OBSERVER.observe(
                        campaign=campaign, case_id=case_id, kind=kind,
                        artifact_arguments=arguments,
                        output_directory=projected, now=NOW,
                        output_directory_uid=os.geteuid(), output_mode=0o444,
                    )
                    self.assertEqual(observation["outcome"],
                                     acceptance.CASE_BY_ID[case_id].expected)
                operator_home = root / "operator-home"
                observations = operator_home / driver.CAMPAIGN_RELATIVE / "observations"
                observations.mkdir(mode=0o700, parents=True)
                observations.parent.chmod(0o700)
                with mock.patch.object(
                        projection.AUTH, "protected_context", return_value=campaign), \
                        mock.patch.object(
                            projection.AUTH.pwd, "getpwuid",
                            return_value=SimpleNamespace(pw_dir=str(operator_home)),
                        ):
                    first = projection.project(
                        case_id, operator_uid, root=root,
                        uid=os.geteuid(), now=NOW,
                    )
                    second = projection.project(
                        case_id, operator_uid, root=root,
                        uid=os.geteuid(), now=NOW,
                    )
                self.assertEqual(
                    first["recorded_observation_kinds"],
                    list(acceptance.CASE_BY_ID[case_id].evidence_kinds),
                )
                self.assertEqual(
                    second["resumed_observation_kinds"],
                    list(acceptance.CASE_BY_ID[case_id].evidence_kinds),
                )


if __name__ == "__main__":
    unittest.main()
