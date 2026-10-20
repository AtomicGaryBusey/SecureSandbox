import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import review_bundle
import review_bundle_publisher as publisher


class ReviewBundlePublisherTests(unittest.TestCase):
    @staticmethod
    def rename_noreplace(source, destination):
        if destination.exists():
            raise publisher.PublishError("bundle_already_exists")
        os.rename(source, destination)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.staging_root = self.base / "tmp"; self.staging_root.mkdir()
        self.review_root = self.base / "review-bundles"
        self.bundle_id = "test-review"
        self.staging = self.staging_root / (self.bundle_id + ".staging")
        self.staging.mkdir(); (self.staging / "DESIGN.md").write_text("safe\n")
        patches = [
            mock.patch.object(publisher, "STAGING_ROOT", self.staging_root),
            mock.patch.object(publisher, "REVIEW_ROOT", str(self.review_root)),
            mock.patch.object(publisher, "require_root_and_idle"),
            mock.patch.object(publisher, "TRUSTED_UID", os.geteuid()),
            mock.patch.object(publisher, "rename_noreplace", side_effect=self.rename_noreplace),
            mock.patch.object(review_bundle, "REVIEW_ROOT", str(self.review_root)),
            mock.patch.object(review_bundle, "TRUSTED_UID", os.geteuid()),
        ]
        for item in patches:
            item.start(); self.addCleanup(item.stop)

    def test_publish_then_verify(self):
        result = publisher.publish(self.bundle_id, self.staging)
        self.assertEqual(result["file_count"], 1)
        verified = review_bundle.verify_review_bundle(self.bundle_id)
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["files"][0]["path"], "DESIGN.md")

    def test_no_overwrite(self):
        publisher.publish(self.bundle_id, self.staging)
        with self.assertRaisesRegex(publisher.PublishError, "bundle_already_exists"):
            publisher.publish(self.bundle_id, self.staging)

    def test_rejects_symlink_and_reserved_files(self):
        os.symlink("DESIGN.md", self.staging / "link")
        with self.assertRaisesRegex(publisher.PublishError, "invalid_staging_file"):
            publisher.publish(self.bundle_id, self.staging)
        (self.staging / "link").unlink(); (self.staging / "SHA256SUMS").write_text("forged\n")
        with self.assertRaisesRegex(publisher.PublishError, "reserved_bundle_path"):
            publisher.publish(self.bundle_id, self.staging)

    def test_cleans_strict_crash_temporary_before_publication(self):
        self.review_root.mkdir()
        orphan = self.review_root / ".old-review.11111111-1111-4111-8111-111111111111.tmp"
        orphan.mkdir(); (orphan / "partial").write_text("partial")
        os.chmod(orphan / "partial", 0o444); os.chmod(orphan, 0o555)
        publisher.publish(self.bundle_id, self.staging)
        self.assertFalse(orphan.exists())

    def test_capacity_is_bounded(self):
        self.review_root.mkdir()
        existing = self.review_root / "old-review"; existing.mkdir(); os.chmod(existing, 0o555)
        with mock.patch.object(publisher, "MAX_BUNDLES", 1):
            with self.assertRaisesRegex(publisher.PublishError, "review_root_capacity_exceeded"):
                publisher.publish(self.bundle_id, self.staging)


if __name__ == "__main__":
    unittest.main()
