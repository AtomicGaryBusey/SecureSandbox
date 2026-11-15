from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
specification = importlib.util.spec_from_file_location(
    "retention_under_test",
    ROOT / "scripts/harness-lifecycle-acceptance-retain-empty-campaign.py",
)
retention = importlib.util.module_from_spec(specification)
assert specification.loader is not None
specification.loader.exec_module(retention)
acceptance = retention.sys.modules["harness_lifecycle_acceptance"]


class EmptyCampaignRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name) / "home"
        self.home.mkdir(mode=0o700)
        self.root = self.home / retention.CAMPAIGN_RELATIVE
        self.root.mkdir(parents=True, mode=0o700)
        for parent in (
            self.home / "Library",
            self.home / "Library/Application Support",
        ):
            parent.chmod(0o700)
        # The existing application-support parent is intentionally traversable;
        # only the campaign/evidence leaves are owner-private.
        (self.home / "Library/Application Support/SecureSandbox").chmod(0o755)
        (self.root / "observations").mkdir(mode=0o700)
        (self.root / "raw").mkdir(mode=0o700)
        for name in retention.EXPECTED_RAW:
            (self.root / "raw" / name).mkdir(mode=0o700)
        self.handoff = self.home / retention.RETAINED_RELATIVE.parent
        self.handoff.mkdir(mode=0o700)
        now = int(time.time())
        self.campaign = {
            "schema": acceptance.CAMPAIGN_SCHEMA,
            "campaign_id": "11111111-1111-4111-8111-111111111111",
            "suite_id": acceptance.SUITE_ID,
            "suite_sha256": acceptance.suite_sha256(),
            "machine_identity_sha256": "1" * 64,
            "source_commit": "a" * 40,
            "created_at": now - 60,
            "expires_at": now + 3600,
            "environment": "disposable-mac",
            "production_data_present": False,
            "production_credentials_present": False,
            "synthetic_credentials_only": True,
            "authority": "acceptance-evidence-only",
        }
        self.campaign["campaign_sha256"] = acceptance.digest(self.campaign)
        campaign_path = self.root / "campaign.json"
        campaign_path.write_bytes(acceptance.canonical(self.campaign))
        campaign_path.chmod(0o600)

    @staticmethod
    def rename(source_parent: int, source: str,
               destination_parent: int, destination: str) -> None:
        os.rename(
            source, destination,
            src_dir_fd=source_parent, dst_dir_fd=destination_parent,
        )

    def execute(self, **overrides):
        git_side_effect = overrides.pop("git_side_effect", None)
        arguments = {
            "expected_campaign_id": self.campaign["campaign_id"],
            "expected_source_commit": self.campaign["source_commit"],
            "acknowledgement": retention.ACKNOWLEDGEMENT,
            "now": int(time.time()),
            "home": self.home,
            "rename": self.rename,
            "source_probe": lambda: (
                "b" * 40, {"origin": "b" * 40},
            ),
            "identity_probe": lambda: self.campaign["machine_identity_sha256"],
        }
        arguments.update(overrides)
        readiness = {
            "status": "ready",
            "available_driver_count": len(acceptance.DRIVER_ENTRYPOINTS),
        }
        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(retention, "acl_absent", return_value=True), \
                mock.patch.object(retention.PREFLIGHT, "git_command",
                                  side_effect=git_side_effect), \
                mock.patch.object(retention.ACCEPTANCE_CLI, "driver_readiness",
                                  return_value=readiness):
            return retention.retain(**arguments)

    def seed_plan(self, replacement: str = "b" * 40) -> dict:
        inventory = {
            "campaign_sha256": acceptance.digest(self.campaign),
            "directories": [
                ".", "observations", "raw", "raw/bootstrap",
                "raw/qualification", "raw/recovery",
            ],
            "files": ["campaign.json"],
        }
        plan = {
            "schema": retention.SCHEMA,
            "status": "prepared",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "campaign_source_commit": self.campaign["source_commit"],
            "replacement_source_commit": replacement,
            "remote_tips": {"origin": replacement},
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "operator_uid": os.geteuid(),
            "reason": "preflight-failed-before-evidence",
            "observed_at": int(time.time()) - 30,
            "inventory_sha256": acceptance.digest(inventory),
            "destination_name": self.campaign["campaign_id"],
        }
        plan["plan_sha256"] = acceptance.digest(plan)
        path = self.root / retention.PLAN_NAME
        path.write_bytes(acceptance.canonical(plan))
        path.chmod(0o600)
        return plan

    def seed_supersession(self, prior: dict, replacement: str,
                           *, prior_authority: str | None = None) -> dict:
        supersession = {
            "schema": retention.SUPERSESSION_SCHEMA,
            "status": "prepared",
            "campaign_id": self.campaign["campaign_id"],
            "campaign_sha256": self.campaign["campaign_sha256"],
            "campaign_source_commit": self.campaign["source_commit"],
            "prior_replacement_source_commit": prior["replacement_source_commit"],
            "replacement_source_commit": replacement,
            "prior_authority_sha256": prior_authority or (
                prior.get("supersession_sha256") or prior["plan_sha256"]
            ),
            "remote_tips": {"origin": replacement},
            "machine_identity_sha256": self.campaign["machine_identity_sha256"],
            "operator_uid": os.geteuid(),
            "reason": "retention-plan-compatible-descendant",
            "observed_at": int(time.time()) - 10,
            "inventory_sha256": prior["inventory_sha256"],
            "destination_name": self.campaign["campaign_id"],
        }
        supersession["supersession_sha256"] = acceptance.digest(supersession)
        path = self.root / (
            f"{retention.SUPERSESSION_PREFIX}{replacement}.json"
        )
        path.write_bytes(acceptance.canonical(supersession))
        path.chmod(0o600)
        return supersession

    def test_empty_campaign_is_moved_without_deletion_or_overwrite(self):
        result = self.execute()
        destination = (
            self.home / retention.RETAINED_RELATIVE / self.campaign["campaign_id"]
        )
        self.assertEqual(result["status"], "retained")
        self.assertFalse(self.root.exists())
        self.assertEqual(
            json.loads((destination / "campaign.json").read_bytes()), self.campaign,
        )
        plan = json.loads((destination / retention.PLAN_NAME).read_bytes())
        self.assertEqual(plan["campaign_sha256"], self.campaign["campaign_sha256"])
        self.assertEqual(plan["replacement_source_commit"], "b" * 40)

        readiness = {
            "status": "ready",
            "available_driver_count": len(acceptance.DRIVER_ENTRYPOINTS),
        }
        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(retention, "acl_absent", return_value=True), \
                mock.patch.object(retention.PREFLIGHT, "git_command", return_value=b""), \
                mock.patch.object(retention.ACCEPTANCE_CLI, "driver_readiness",
                                  return_value=readiness):
            verified = retention.verify_retained(
                expected_campaign_id=self.campaign["campaign_id"],
                expected_source_commit=self.campaign["source_commit"],
                expected_replacement_commit="b" * 40,
                home=self.home,
                source_probe=lambda: (
                    "b" * 40, {"origin": "b" * 40},
                ),
                identity_probe=lambda: self.campaign["machine_identity_sha256"],
            )
        self.assertEqual(verified, result)

    def test_new_plan_mode_is_exact_even_under_restrictive_umask(self):
        previous = os.umask(0o777)
        try:
            self.execute()
        finally:
            os.umask(previous)
        plan = (
            self.home / retention.RETAINED_RELATIVE
            / self.campaign["campaign_id"] / retention.PLAN_NAME
        )
        self.assertEqual(plan.stat().st_mode & 0o777, 0o600)

    def test_any_raw_case_entry_rejects_before_move(self):
        artifact = self.root / "raw/bootstrap/rejected-attempt"
        artifact.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_campaign_not_empty",
        ):
            self.execute()
        self.assertTrue(self.root.exists())
        self.assertFalse((self.root / retention.PLAN_NAME).exists())

    def test_existing_plan_is_preserved_and_superseded_append_only(self):
        plan = self.seed_plan()
        plan_bytes = (self.root / retention.PLAN_NAME).read_bytes()
        current = "c" * 40
        result = self.execute(source_probe=lambda: (
            current, {"origin": current},
        ))
        destination = (
            self.home / retention.RETAINED_RELATIVE / self.campaign["campaign_id"]
        )
        self.assertEqual((destination / retention.PLAN_NAME).read_bytes(), plan_bytes)
        supersession_path = destination / (
            f"{retention.SUPERSESSION_PREFIX}{current}.json"
        )
        supersession = json.loads(supersession_path.read_bytes())
        self.assertEqual(supersession["prior_authority_sha256"], plan["plan_sha256"])
        self.assertEqual(supersession["replacement_source_commit"], current)
        self.assertEqual(
            result["supersession_sha256s"],
            [supersession["supersession_sha256"]],
        )
        self.assertEqual(
            result["retention_authority_sha256"],
            supersession["supersession_sha256"],
        )

        readiness = {
            "status": "ready",
            "available_driver_count": len(acceptance.DRIVER_ENTRYPOINTS),
        }
        with mock.patch.object(retention.platform, "system", return_value="Darwin"), \
                mock.patch.object(retention, "acl_absent", return_value=True), \
                mock.patch.object(retention.PREFLIGHT, "git_command", return_value=b""), \
                mock.patch.object(retention.ACCEPTANCE_CLI, "driver_readiness",
                                  return_value=readiness):
            verified = retention.verify_retained(
                expected_campaign_id=self.campaign["campaign_id"],
                expected_source_commit=self.campaign["source_commit"],
                expected_replacement_commit=current,
                home=self.home,
                source_probe=lambda: (
                    current, {"origin": current},
                ),
                identity_probe=lambda: self.campaign["machine_identity_sha256"],
            )
        self.assertEqual(verified, result)

    def test_supersession_chain_can_advance_without_rewriting_prior_records(self):
        plan = self.seed_plan()
        middle = "c" * 40
        supersession = self.seed_supersession(plan, middle)
        before = {
            retention.PLAN_NAME: (self.root / retention.PLAN_NAME).read_bytes(),
            f"{retention.SUPERSESSION_PREFIX}{middle}.json": (
                self.root / f"{retention.SUPERSESSION_PREFIX}{middle}.json"
            ).read_bytes(),
        }
        current = "d" * 40
        result = self.execute(source_probe=lambda: (
            current, {"origin": current},
        ))
        destination = (
            self.home / retention.RETAINED_RELATIVE / self.campaign["campaign_id"]
        )
        for name, raw in before.items():
            self.assertEqual((destination / name).read_bytes(), raw)
        self.assertEqual(len(result["supersession_sha256s"]), 2)
        self.assertEqual(result["supersession_sha256s"][0],
                         supersession["supersession_sha256"])

    def test_supersession_with_wrong_prior_authority_rejects(self):
        plan = self.seed_plan()
        current = "c" * 40
        self.seed_supersession(plan, current, prior_authority="f" * 64)
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_supersession_chain_invalid",
        ):
            self.execute(source_probe=lambda: (
                current, {"origin": current},
            ))
        self.assertTrue(self.root.exists())

    def test_plan_that_did_not_advance_campaign_commit_rejects(self):
        self.seed_plan(self.campaign["source_commit"])
        current = "c" * 40
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_plan_mismatch",
        ):
            self.execute(source_probe=lambda: (
                current, {"origin": current},
            ))
        self.assertTrue(self.root.exists())

    def test_recreated_live_path_rejects_after_atomic_move(self):
        def rename_then_recreate(source_parent: int, source: str,
                                 destination_parent: int,
                                 destination: str) -> None:
            self.rename(source_parent, source, destination_parent, destination)
            os.symlink("missing-retention-source", source, dir_fd=source_parent)

        with self.assertRaisesRegex(
            retention.RetentionError, "retention_source_still_present",
        ):
            self.execute(rename=rename_then_recreate)
        self.assertTrue(os.path.lexists(self.root))

    def test_non_descendant_supersession_rejects_without_move(self):
        self.seed_plan()
        current = "c" * 40

        def ancestry(arguments, cwd):
            if arguments[-2:] == ["b" * 40, current]:
                raise retention.PREFLIGHT.PreflightError(
                    "retention_test_non_descendant",
                )
            return b""

        with self.assertRaisesRegex(
            retention.RetentionError, "retention_replacement_not_descendant",
        ):
            self.execute(
                source_probe=lambda: (
                    current, {"origin": current},
                ),
                git_side_effect=ancestry,
            )
        self.assertTrue(self.root.exists())

    def test_same_commit_is_not_a_repair_transition(self):
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_replacement_commit_required",
        ):
            self.execute(source_probe=lambda: (
                self.campaign["source_commit"],
                {"origin": self.campaign["source_commit"]},
            ))
        self.assertTrue(self.root.exists())

    def test_wrong_expected_campaign_rejects(self):
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_expected_campaign_mismatch",
        ):
            self.execute(expected_campaign_id="22222222-2222-4222-8222-222222222222")
        self.assertTrue(self.root.exists())

    def test_verify_rejects_while_live_source_still_exists(self):
        with mock.patch.object(retention.platform, "system", return_value="Darwin"):
            with self.assertRaisesRegex(
                retention.RetentionError, "retention_source_still_present",
            ):
                retention.verify_retained(
                    expected_campaign_id=self.campaign["campaign_id"],
                    expected_source_commit=self.campaign["source_commit"],
                    expected_replacement_commit="b" * 40,
                    home=self.home,
                )

    def test_group_writable_application_parent_still_rejects(self):
        parent = self.home / "Library/Application Support/SecureSandbox"
        parent.chmod(0o775)
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_directory_untrusted",
        ):
            self.execute()
        self.assertFalse((self.root / retention.PLAN_NAME).exists())


if __name__ == "__main__":
    unittest.main()
