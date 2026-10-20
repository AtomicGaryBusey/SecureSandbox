import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import review_bundle


class ReviewBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = os.path.join(self.temp.name, "review-bundles")
        self.bundle_id = "evidence-receipts-review"
        self.bundle = os.path.join(self.root, self.bundle_id)
        os.makedirs(os.path.join(self.bundle, "code"))
        files = {
            ".bundle-id": (self.bundle_id + "\n").encode(),
            "DESIGN.md": b"design\n",
            "code/verifier.py": b"print('safe')\n",
        }
        for relative, data in files.items():
            path = os.path.join(self.bundle, relative)
            with open(path, "wb") as handle:
                handle.write(data)
        manifest = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {path}\n"
            for path, data in sorted(files.items())
        ).encode()
        with open(os.path.join(self.bundle, "SHA256SUMS"), "wb") as handle:
            handle.write(manifest)
        self.trust = mock.patch.object(review_bundle, "TRUSTED_UID", os.geteuid())
        self.location = mock.patch.object(review_bundle, "REVIEW_ROOT", self.root)
        self.trust.start(); self.location.start()
        self.addCleanup(self.trust.stop); self.addCleanup(self.location.stop)

    def verify(self):
        return review_bundle.verify_review_bundle(self.bundle_id)

    def test_verified_inventory(self):
        result = self.verify()
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["file_count"], 2)
        self.assertEqual([item["path"] for item in result["files"]], ["DESIGN.md", "code/verifier.py"])

    def test_rejects_arbitrary_identifier(self):
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "invalid_bundle_id"):
            review_bundle.verify_review_bundle("../etc")
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "invalid_bundle_id"):
            review_bundle.verify_review_bundle("a" * 58 + "-review")

    def test_rejects_modified_file(self):
        with open(os.path.join(self.bundle, "DESIGN.md"), "wb") as handle:
            handle.write(b"changed\n")
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_digest_mismatch"):
            self.verify()

    def test_rejects_missing_and_unexpected_files(self):
        os.unlink(os.path.join(self.bundle, "DESIGN.md"))
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_inventory_mismatch"):
            self.verify()
        with open(os.path.join(self.bundle, "DESIGN.md"), "wb") as handle:
            handle.write(b"design\n")
        with open(os.path.join(self.bundle, "extra"), "wb") as handle:
            handle.write(b"extra\n")
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_inventory_mismatch"):
            self.verify()

    def test_rejects_unexpected_empty_directory(self):
        os.mkdir(os.path.join(self.bundle, "empty"))
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_inventory_mismatch"):
            self.verify()

    def test_rejects_symlink_and_hardlink(self):
        os.symlink("DESIGN.md", os.path.join(self.bundle, "link"))
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_tree_untrusted"):
            self.verify()
        os.unlink(os.path.join(self.bundle, "link"))
        os.link(os.path.join(self.bundle, "DESIGN.md"), os.path.join(self.bundle, "hard"))
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_file_untrusted"):
            self.verify()

    def test_rejects_relabelled_bundle(self):
        other = os.path.join(self.root, "renamed-review")
        os.rename(self.bundle, other)
        with mock.patch.object(self, "bundle", other):
            with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_identity_mismatch"):
                review_bundle.verify_review_bundle("renamed-review")

    def test_rejects_writable_control_tree(self):
        os.chmod(self.bundle, 0o777)
        with self.assertRaisesRegex(review_bundle.ReviewBundleError, "bundle_directory_untrusted"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
