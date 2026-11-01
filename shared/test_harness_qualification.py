#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared"))

import claude_core_adapter as CLAUDE  # noqa: E402
import harness_qualification as QUALIFICATION  # noqa: E402
from harness_qualification_fixture import SyntheticDisposableSupervisor  # noqa: E402


CLI_SPEC = importlib.util.spec_from_file_location(
    "harness_qualification_cli", ROOT / "scripts/harness-qualification.py",
)
assert CLI_SPEC and CLI_SPEC.loader
CLI = importlib.util.module_from_spec(CLI_SPEC)
CLI_SPEC.loader.exec_module(CLI)


class HarnessQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = 2_000_000_000
        self.plan = CLI.fixture_plan(self.now)

    def run_fixture(self, faults=None):
        backend = SyntheticDisposableSupervisor(faults=faults or {})
        return QUALIFICATION.QualificationRunner(self.now).run(self.plan, backend)

    def test_complete_malicious_fixture_is_qualified_but_has_no_authority(self) -> None:
        report = self.run_fixture()
        self.assertEqual(report["status"], "fixture_qualified")
        self.assertEqual(report["authority"], "none")
        self.assertEqual(report["note"], "fixture_qualified_not_admitted")
        self.assertEqual(len(report["case_results"]), len(QUALIFICATION.CASE_IDS))
        self.assertTrue(all(item["status"] == "passed" for item in report["case_results"]))
        self.assertRegex(report["report_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(QUALIFICATION.validate_report(report, self.plan), report)

    def test_report_tampering_and_retargeting_fail_closed(self) -> None:
        report = self.run_fixture()
        for field, value in (
            ("generation_id", "f" * 64),
            ("authority", "admit"),
            ("report_sha256", "f" * 64),
        ):
            broken = json.loads(json.dumps(report))
            broken[field] = value
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION.validate_report(broken, self.plan)

    def test_plan_is_exact_complete_expiring_and_content_bound(self) -> None:
        self.assertEqual(QUALIFICATION.validate_plan(self.plan, self.now), self.plan)
        for mutation in (
            lambda value: value["cases"].pop(),
            lambda value: value["cases"].reverse(),
            lambda value: value.update(expires_at=self.now),
            lambda value: value.update(adapter_sha256="bad"),
        ):
            broken = json.loads(json.dumps(self.plan))
            mutation(broken)
            with self.assertRaises(QUALIFICATION.QualificationError):
                QUALIFICATION.validate_plan(broken, self.now)

    def test_outer_binding_cannot_be_replaced_by_candidate_claim(self) -> None:
        class ForgedObserver(SyntheticDisposableSupervisor):
            def observe(self, plan, case_id, sequence):
                value = super().observe(plan, case_id, sequence)
                value["observer"] = "candidate-authored-report"
                return value

        with self.assertRaisesRegex(QUALIFICATION.QualificationError, "observation_binding"):
            QUALIFICATION.QualificationRunner(self.now).run(self.plan, ForgedObserver())

    def test_fixture_bytes_must_match_the_exact_plan(self) -> None:
        self.plan["fixture_corpus_sha256"] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "fixture_digest_mismatch"):
            self.run_fixture()

    def test_network_child_secret_and_file_effects_reject(self) -> None:
        cases = {
            "protocol-start": {"network_connections": ["203.0.113.1:443"]},
            "protocol-prompt": {"child_processes": ["bin/sh"]},
            "protocol-steering": {"secret_markers": ["api-key-marker"]},
            "lifecycle-cancel": {"file_changes": ["home/.claude/settings.json"]},
        }
        report = self.run_fixture(cases)
        self.assertEqual(report["status"], "rejected")
        failures = {item["case_id"]: item["failures"] for item in report["case_results"]}
        self.assertIn("network_connection", failures["protocol-start"])
        self.assertIn("child_process", failures["protocol-prompt"])
        self.assertIn("secret_exposure", failures["protocol-steering"])
        self.assertIn("filesystem_change", failures["lifecycle-cancel"])

    def test_protocol_drift_timeout_and_semantic_loss_reject(self) -> None:
        report = self.run_fixture({
            "protocol-start": {"events": ["assistant_output"]},
            "protocol-prompt": {"unknown_events": ["vendor-new-event"]},
            "protocol-steering": {"semantic_loss": True},
            "lifecycle-cancel": {"timed_out": True},
        })
        failures = {item["case_id"]: item["failures"] for item in report["case_results"]}
        self.assertIn("event_sequence", failures["protocol-start"])
        self.assertIn("unknown_event", failures["protocol-prompt"])
        self.assertIn("semantic_loss", failures["protocol-steering"])
        self.assertIn("timeout", failures["lifecycle-cancel"])

    def test_catalog_drift_and_unexercised_denial_reject(self) -> None:
        report = self.run_fixture({
            "tool-catalog-stability": {"tool_catalog_after_sha256": "f" * 64},
            "deny-login": {"attempts": []},
            "deny-self-update": {"blocked": False, "events": []},
        })
        failures = {item["case_id"]: item["failures"] for item in report["case_results"]}
        self.assertIn("tool_catalog_drift", failures["tool-catalog-stability"])
        self.assertIn("denial_not_exercised", failures["deny-login"])
        self.assertIn("denial_not_enforced", failures["deny-self-update"])

    def test_runner_has_no_candidate_execution_surface(self) -> None:
        source = (ROOT / "shared/harness_qualification.py").read_text(encoding="utf-8")
        cli = (ROOT / "scripts/harness-qualification.py").read_text(encoding="utf-8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("Popen", cli)
        self.assertNotIn("executable", CLI.parser().format_help())


class ClaudeCoreAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = str(uuid.uuid4())

    def test_launch_is_fixed_and_cannot_add_vendor_authority(self) -> None:
        value = CLAUDE.launch_vector("/usr/local/bin/claude", self.session, "new")
        self.assertEqual(CLAUDE.validate_launch_vector(value), value)
        for broken in (
            ["/tmp/claude", *value[1:]],
            [*value, "--plugin-dir"],
            value[:-2] + ["--model", "other"],
        ):
            with self.assertRaises(CLAUDE.ClaudeAdapterError):
                CLAUDE.validate_launch_vector(broken)

    def test_environment_requires_disable_controls_and_rejects_credentials(self) -> None:
        environment = dict(CLAUDE.REQUIRED_ENVIRONMENT)
        self.assertEqual(CLAUDE.validate_environment(environment), environment)
        for name in ("ANTHROPIC_API_KEY", "NODE_OPTIONS"):
            with self.assertRaisesRegex(CLAUDE.ClaudeAdapterError, "forbidden"):
                CLAUDE.validate_environment({**environment, name: "marker"})
        environment.pop("DISABLE_UPDATES")
        with self.assertRaisesRegex(CLAUDE.ClaudeAdapterError, "required_environment"):
            CLAUDE.validate_environment(environment)

    def test_projection_binds_policy_and_declares_no_semantic_loss(self) -> None:
        value = CLAUDE.projection("a" * 64, "b" * 64, "c" * 64, "d" * 64)
        self.assertEqual(value["adapter_id"], "claude-core-v1")
        self.assertEqual(value["authority"], "none")
        self.assertEqual(value["semantic_loss"], [])
        self.assertIn(".mcp.json", value["ambient_project_paths"])
        self.assertRegex(value["projection_sha256"], r"^[0-9a-f]{64}$")

    def test_stream_translation_is_bounded_bound_and_fail_closed(self) -> None:
        event = {"type": "system", "subtype": "init", "session_id": self.session}
        self.assertEqual(CLAUDE.translate_stream_event(event, self.session)["event"], "session_started")
        with self.assertRaisesRegex(CLAUDE.ClaudeAdapterError, "session_mismatch"):
            CLAUDE.translate_stream_event(event, str(uuid.uuid4()))
        with self.assertRaisesRegex(CLAUDE.ClaudeAdapterError, "event_unknown"):
            CLAUDE.translate_stream_event(
                {"type": "new-vendor-event", "session_id": self.session}, self.session,
            )


if __name__ == "__main__":
    unittest.main()
