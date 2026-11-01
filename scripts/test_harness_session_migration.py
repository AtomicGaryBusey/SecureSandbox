#!/usr/bin/env python3

import importlib.util
import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path

from shared.harness_runtime_binding import make_binding


SPEC = importlib.util.spec_from_file_location(
    "harness_session_migration", Path(__file__).with_name("harness-session-migration.py")
)
MIGRATION = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MIGRATION)


class HarnessSessionMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.catalog = self.root / "session-runs.json"
        self.session = str(uuid.uuid4())
        self.run = str(uuid.uuid4())
        self.record = {
            "adapter": "anthropic-messages-v1", "model": "model",
            "model_profile_id": "profile", "model_profile_sha256": "1" * 64,
            "vendor_id": "vendor", "last_started_at": 100, "runs": 1,
            "run_ids": [self.run],
        }
        self.catalog.write_bytes(MIGRATION.canonical({
            "schema": "secure-sandbox-session-runs-v3",
            "sessions": {self.session: self.record},
        }))
        self.catalog.chmod(0o600)
        self.binding = make_binding(
            harness_id="claude-code", generation_id="2" * 64,
            manifest_sha256="3" * 64, executable_sha256="4" * 64,
            inventory_sha256="5" * 64, adapter_id="claude-core-v1",
            adapter_sha256="6" * 64,
        )
        evidence_body = {
            "schema": MIGRATION.EVIDENCE_SCHEMA, "attestation_id": str(uuid.uuid4()),
            "session_id": self.session, "observed_run_ids": [self.run],
            "legacy_executable_sha256": self.binding["harness_executable_sha256"],
            "observer": "secure-sandbox-legacy-harness-attestor-v1",
            "observed_at": 900, "status": "attested",
        }
        self.evidence = {**evidence_body, "evidence_sha256": MIGRATION.digest(evidence_body)}

    def tearDown(self):
        self.temporary.cleanup()

    def authorization(self, plan, *, password_fallback=False):
        body = {
            "schema": MIGRATION.MIGRATION_AUTHORIZATION_SCHEMA,
            "authorization_id": str(uuid.uuid4()), "plan_id": plan["plan_id"],
            "plan_sha256": plan["plan_sha256"], "method": "touch-id",
            "password_fallback": password_fallback, "authorized_at": 1000,
            "expires_at": 1100, "requesting_agent_sha256": "7" * 64,
            "requesting_session_sha256": "8" * 64,
        }
        return {**body, "authorization_sha256": MIGRATION.digest(body)}

    def test_exact_attested_legacy_session_migrates_once(self):
        plan = MIGRATION.create_plan(
            self.catalog, self.session, self.binding, self.evidence, now=1000,
        )
        receipt = MIGRATION.apply_plan(
            self.catalog, plan, self.authorization(plan), self.evidence, now=1001,
        )
        value = json.loads(self.catalog.read_text())
        record = value["sessions"][self.session]
        self.assertEqual(value["schema"], "secure-sandbox-session-runs-v4")
        self.assertEqual(record["harness_generation_id"], "2" * 64)
        self.assertEqual(record["harness_binding_sha256"], self.binding["binding_sha256"])
        self.assertEqual(receipt["status"], "committed")
        with self.assertRaisesRegex(MIGRATION.MigrationError, "already_harness_bound"):
            MIGRATION.create_plan(
                self.catalog, self.session, self.binding, self.evidence, now=1002,
            )

    def test_migration_refuses_password_fallback_and_changed_catalog(self):
        plan = MIGRATION.create_plan(
            self.catalog, self.session, self.binding, self.evidence, now=1000,
        )
        with self.assertRaisesRegex(MIGRATION.MigrationError, "authorization_invalid"):
            MIGRATION.apply_plan(
                self.catalog, plan,
                self.authorization(plan, password_fallback=True), self.evidence, now=1001,
            )
        value = json.loads(self.catalog.read_text()); value["sessions"][self.session]["runs"] = 2
        self.catalog.write_bytes(MIGRATION.canonical(value)); self.catalog.chmod(0o600)
        with self.assertRaisesRegex(MIGRATION.MigrationError, "catalog_changed"):
            MIGRATION.apply_plan(
                self.catalog, plan, self.authorization(plan), self.evidence, now=1001,
            )

    def test_migration_never_infers_generation_from_current_selector(self):
        evidence = dict(self.evidence); evidence["legacy_executable_sha256"] = "9" * 64
        body = dict(evidence); body.pop("evidence_sha256")
        evidence["evidence_sha256"] = MIGRATION.digest(body)
        with self.assertRaisesRegex(MIGRATION.MigrationError, "executable_binding_mismatch"):
            MIGRATION.create_plan(
                self.catalog, self.session, self.binding, evidence, now=1000,
            )


if __name__ == "__main__":
    unittest.main()
