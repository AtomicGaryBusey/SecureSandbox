import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import source_integrity as integrity
import source_integrity_mcp as mcp


class SourceIntegrityTests(unittest.TestCase):
    @staticmethod
    def read_uncontrolled(path, maximum):
        with open(path, "rb") as handle:
            return handle.read(maximum + 1)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        workspace = self.temp.name
        os.makedirs(os.path.join(workspace, "repos", "repo"))
        os.makedirs(os.path.join(workspace, "baselines", "source"))
        os.makedirs(os.path.join(workspace, "source-manifests"))
        self.source_id = "11111111-1111-4111-8111-111111111111"
        baseline = os.path.join(workspace, "baselines", "source")
        worktree = os.path.join(workspace, "repos", "repo")
        for root in (baseline, worktree):
            with open(os.path.join(root, "README"), "wb") as handle:
                handle.write(b"safe\n")
        digest = hashlib.sha256(b"safe\n").hexdigest()
        self.entries = [{"path": "README", "type": "file", "bytes": 5, "sha256": digest, "git_mode": 0o644}]
        tree_hash = hashlib.sha256(integrity.canonical(self.entries)).hexdigest()
        manifest = {
            "schema": "secure-sandbox-source-integrity-v1",
            "source_id": self.source_id,
            "repository": "owner/repo",
            "resolved_commit": "a" * 40,
            "tree_manifest_sha256": tree_hash,
            "entries": self.entries,
        }
        with open(os.path.join(workspace, "source-manifests", self.source_id + ".json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle)
        self.record = {
            "source_id": self.source_id,
            "repository": "owner/repo",
            "resolved_commit": "a" * 40,
            "tree_manifest_sha256": tree_hash,
            "baseline_path": "baselines/source",
            "worktree_path": "repos/repo",
            "integrity_manifest_path": f"source-manifests/{self.source_id}.json",
        }
        with open(os.path.join(workspace, "repos", "INDEX.json"), "w", encoding="utf-8") as handle:
            json.dump({"schema": "secure-sandbox-source-registry-v1", "sources": [self.record]}, handle)
        self.patches = [
            mock.patch.object(integrity, "WORKSPACE", workspace),
            mock.patch.object(integrity, "INDEX", os.path.join(workspace, "repos", "INDEX.json")),
            mock.patch.object(integrity, "controlled_file", side_effect=self.read_uncontrolled),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_anchored_baseline_and_worktree_match(self):
        result = integrity.verify_source(self.source_id)
        self.assertEqual(result["overall_status"], "match")
        self.assertTrue(result["manifest_tree_hash_verified"])
        self.assertEqual(result["baseline"]["status"], "match")
        self.assertEqual(result["worktree"]["status"], "match")

    def test_worktree_modification_is_reported(self):
        with open(os.path.join(self.temp.name, "repos", "repo", "README"), "wb") as handle:
            handle.write(b"changed\n")
        result = integrity.verify_source(self.source_id)
        self.assertEqual(result["overall_status"], "changed_or_unverified")
        self.assertEqual(result["worktree"]["modified"], 1)
        self.assertEqual(result["worktree"]["changes"], [{"change": "modified", "path": "README"}])

    def test_baseline_modification_is_reported(self):
        with open(os.path.join(self.temp.name, "baselines", "source", "README"), "wb") as handle:
            handle.write(b"changed\n")
        result = integrity.verify_source(self.source_id)
        self.assertEqual(result["overall_status"], "changed_or_unverified")
        self.assertEqual(result["baseline"]["modified"], 1)

    def test_tampered_manifest_is_rejected(self):
        self.record["tree_manifest_sha256"] = "0" * 64
        with open(os.path.join(self.temp.name, "repos", "INDEX.json"), "w", encoding="utf-8") as handle:
            json.dump({"schema": "secure-sandbox-source-registry-v1", "sources": [self.record]}, handle)
        with self.assertRaisesRegex(integrity.IntegrityError, "integrity_manifest_hash_mismatch"):
            integrity.verify_source(self.source_id)

    def test_legacy_source_is_explicitly_unanchored(self):
        del self.record["integrity_manifest_path"]
        with open(os.path.join(self.temp.name, "repos", "INDEX.json"), "w", encoding="utf-8") as handle:
            json.dump({"schema": "secure-sandbox-source-registry-v1", "sources": [self.record]}, handle)
        result = integrity.verify_source(self.source_id)
        self.assertEqual(result["anchor_status"], "legacy_manifest_unavailable")
        self.assertEqual(result["overall_status"], "legacy_unanchored_match")

    def test_rejects_arbitrary_path_in_registry(self):
        self.record["baseline_path"] = "../../etc"
        with open(os.path.join(self.temp.name, "repos", "INDEX.json"), "w", encoding="utf-8") as handle:
            json.dump({"schema": "secure-sandbox-source-registry-v1", "sources": [self.record]}, handle)
        with self.assertRaisesRegex(integrity.IntegrityError, "unsafe_registered_path"):
            integrity.verify_source(self.source_id)

    def test_manifest_derives_implicit_archive_directories(self):
        manifest = {"entries": [{"path": "dist/api/index.js", "type": "file", "bytes": 1, "sha256": "a" * 64}]}
        records = integrity.expected_records(manifest)
        self.assertEqual(records["dist"], {"path": "dist", "type": "directory"})
        self.assertEqual(records["dist/api"], {"path": "dist/api", "type": "directory"})


class McpTests(unittest.TestCase):
    def test_tool_list_exposes_bounded_tools(self):
        response = mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual([tool["name"] for tool in response["result"]["tools"]], ["verify_source", "verify_review_bundle"])

    def test_tool_call_has_no_arbitrary_arguments(self):
        response = mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "verify_source", "arguments": {"source_id": "x", "path": "/etc"}}})
        self.assertEqual(response["error"]["message"], "invalid_tool_arguments")

    def test_review_bundle_tool_has_no_path_argument(self):
        response = mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "verify_review_bundle", "arguments": {"bundle_id": "x-review", "path": "/etc"}}})
        self.assertEqual(response["error"]["message"], "invalid_tool_arguments")

    @mock.patch.object(mcp, "audit_review_bundle")
    @mock.patch.object(mcp, "verify_review_bundle", return_value={"status": "verified", "bundle_id": "x-review"})
    def test_review_bundle_tool_returns_structured_verification(self, _verify, audit):
        response = mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "verify_review_bundle", "arguments": {"bundle_id": "x-review"}}})
        self.assertFalse(response["result"]["isError"])
        self.assertEqual(response["result"]["structuredContent"]["status"], "verified")
        audit.assert_called_once()

    @mock.patch.object(mcp, "audit_review_bundle")
    @mock.patch.object(mcp, "verify_review_bundle", side_effect=mcp.ReviewBundleError("bundle_digest_mismatch"))
    def test_review_bundle_tool_preserves_fixed_rejection(self, _verify, audit):
        response = mcp.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "verify_review_bundle", "arguments": {"bundle_id": "x-review"}}})
        self.assertTrue(response["result"]["isError"])
        self.assertIn("bundle_digest_mismatch", response["result"]["content"][0]["text"])
        audit.assert_called_once_with("x-review", "rejected")


if __name__ == "__main__":
    unittest.main()
