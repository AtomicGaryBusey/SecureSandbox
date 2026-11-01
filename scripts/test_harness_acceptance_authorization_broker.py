#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import unittest
import uuid
from pathlib import Path
from unittest import mock

import harness_lifecycle_acceptance as acceptance
import harness_lifecycle_acceptance_interactive as interactive


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "harness_acceptance_operator_authorization",
    ROOT / "scripts/operator-authorization.py",
)
assert SPEC and SPEC.loader
broker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(broker)
NOW = 2_000_000_000


class HarnessAcceptanceAuthorizationBrokerTests(unittest.TestCase):
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

    def plan(self) -> dict:
        return interactive.make_plan(
            self.campaign(), "touchid-approve-exact-plan", "authorize",
            "5" * 64, 501, NOW,
        )

    def test_broker_accepts_only_closed_current_authorization_plan(self):
        plan = self.plan()
        with mock.patch.object(broker.time, "time", return_value=NOW):
            broker.validate_parameters(
                "harness-acceptance-authorize", {"plan": plan}, Path("/Users/test"),
            )
        changed = dict(plan); changed["production_store_access"] = True
        changed["plan_sha256"] = acceptance.digest(
            {name: item for name, item in changed.items() if name != "plan_sha256"},
        )
        with mock.patch.object(broker.time, "time", return_value=NOW), \
                self.assertRaisesRegex(broker.AuthorizationError, "plan_invalid"):
            broker.validate_parameters(
                "harness-acceptance-authorize", {"plan": changed}, Path("/Users/test"),
            )

    def test_dispatch_path_is_exact_commit_and_not_caller_selected(self):
        plan = self.plan()
        authorization = {"schema": "test-only"}
        command = broker.operation_command({
            "operation": "harness-acceptance-authorize",
            "parameters": {"plan": plan},
        }, Path("/protected/host/release"), operator_uid=501,
            authorization=authorization)
        self.assertEqual(command[:2], ["/usr/bin/python3", "-I"])
        self.assertEqual(
            command[2],
            "/usr/local/libexec/secure-sandbox-harness-acceptance/releases/"
            + "2" * 40 + "/scripts/harness-lifecycle-acceptance-authorization.py",
        )
        self.assertNotIn("/protected/host/release", command)
        self.assertEqual(command[-2:], ["--operator-uid", "501"])
        with self.assertRaisesRegex(broker.AuthorizationError, "operator_uid_mismatch"):
            broker.operation_command({
                "operation": "harness-acceptance-authorize",
                "parameters": {"plan": plan},
            }, Path("/protected/host/release"), operator_uid=502,
                authorization=authorization)

    def test_prompt_discloses_acceptance_only_and_production_store_forbidden(self):
        details = broker.operation_details({
            "operation": "harness-acceptance-authorize",
            "parameters": {"plan": self.plan()},
        })
        rendered = "\n".join(details)
        self.assertIn("acceptance-only authorization", rendered)
        self.assertIn("Production generation store access: forbidden", rendered)

    def test_operation_is_touchid_only_in_both_native_ui_gates(self):
        source = (ROOT / "scripts/operator-authorization.py").read_text()
        self.assertGreaterEqual(source.count('"harness-acceptance-authorize"'), 9)
        self.assertIn('value["operation"] == "harness-acceptance-authorize"', source)
        self.assertIn('and authorization_method != "touch-id"', source)


if __name__ == "__main__":
    unittest.main()
