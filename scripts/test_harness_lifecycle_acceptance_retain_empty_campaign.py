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
        arguments = {
            "expected_campaign_id": self.campaign["campaign_id"],
            "expected_source_commit": self.campaign["source_commit"],
            "acknowledgement": retention.ACKNOWLEDGEMENT,
            "now": int(time.time()),
            "home": self.home,
            "rename": self.rename,
            "source_probe": lambda: (
                "b" * 40, {"origin": "b" * 40, "hobby": "b" * 40},
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
                mock.patch.object(retention.PREFLIGHT, "git_command", return_value=b""), \
                mock.patch.object(retention.ACCEPTANCE_CLI, "driver_readiness",
                                  return_value=readiness):
            return retention.retain(**arguments)

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
                    "b" * 40, {"origin": "b" * 40, "hobby": "b" * 40},
                ),
                identity_probe=lambda: self.campaign["machine_identity_sha256"],
            )
        self.assertEqual(verified, result)

    def test_any_raw_case_entry_rejects_before_move(self):
        artifact = self.root / "raw/bootstrap/rejected-attempt"
        artifact.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_campaign_not_empty",
        ):
            self.execute()
        self.assertTrue(self.root.exists())
        self.assertFalse((self.root / retention.PLAN_NAME).exists())

    def test_same_commit_is_not_a_repair_transition(self):
        with self.assertRaisesRegex(
            retention.RetentionError, "retention_replacement_commit_required",
        ):
            self.execute(source_probe=lambda: (
                self.campaign["source_commit"],
                {"origin": self.campaign["source_commit"],
                 "hobby": self.campaign["source_commit"]},
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


if __name__ == "__main__":
    unittest.main()
