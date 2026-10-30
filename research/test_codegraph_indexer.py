#!/usr/bin/env python3

import fcntl
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


RESEARCH = Path(__file__).resolve().parent
sys.path.insert(0, str(RESEARCH))
SPEC = importlib.util.spec_from_file_location("codegraph_indexer", RESEARCH / "codegraph_indexer.py")
indexer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(indexer)


class CodeGraphIndexerRecoveryTests(unittest.TestCase):
    source_id = "11111111-1111-4111-8111-111111111111"

    def fixture(self, directory: str):
        root = Path(directory) / "indexes"
        markers = Path(directory) / "markers"
        builds = Path(directory) / "builds"
        destination = root / self.source_id
        graph = destination / "project/.codegraph"
        for path in (graph, markers, builds):
            path.mkdir(parents=True, exist_ok=True)
        (graph / "graph.db").write_bytes(b"sealed graph")
        record = {"repository": "owner/repo", "resolved_commit": "a" * 40,
                  "tree_manifest_sha256": "b" * 64}
        metadata = {
            "schema": "secure-sandbox-codegraph-index-v1", "source_id": self.source_id,
            **record, "corpus_index_content_sha256": "c" * 64,
            "codegraph_version": "1.6.2", "codegraph_build_commit": indexer.BUILD_COMMIT,
            "codegraph_bundle_sha256": indexer.BUNDLE_SHA256,
            "codegraph_index_sha256": indexer.directory_digest(str(graph)),
            "source_files": 1, "source_bytes": 12, "files_processed": 1,
            "nodes_created": 1, "edges_created": 0, "index_errors": [],
            "created_at": "2026-10-27T00:00:00Z",
        }
        metadata_path = destination / "metadata.json"
        metadata_path.write_bytes(indexer.canonical(metadata) + b"\n")
        metadata_path.chmod(0o444)
        return root, markers, builds, destination, record, metadata

    def test_recovers_exact_marker_after_index_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root, markers, builds, destination, record, metadata = self.fixture(directory)
            with mock.patch.multiple(indexer, ROOT=str(root), MARKER_ROOT=str(markers), BUILD_ROOT=str(builds)):
                recovered = indexer.validate_recoverable_index(self.source_id, str(destination), record)
                again = indexer.validate_recoverable_index(self.source_id, str(destination), record)
            self.assertEqual(recovered, metadata)
            self.assertEqual(again, metadata)
            self.assertEqual(json.loads((markers / f"{self.source_id}.json").read_text()), metadata)

    def test_recovery_refuses_mismatched_existing_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root, markers, builds, destination, record, metadata = self.fixture(directory)
            changed = dict(metadata); changed["nodes_created"] = 2
            marker = markers / f"{self.source_id}.json"
            marker.write_bytes(indexer.canonical(changed) + b"\n"); marker.chmod(0o444)
            with mock.patch.multiple(indexer, ROOT=str(root), MARKER_ROOT=str(markers), BUILD_ROOT=str(builds)), \
                 self.assertRaisesRegex(indexer.GraphIndexError, "codegraph_marker_recovery_mismatch"):
                indexer.validate_recoverable_index(self.source_id, str(destination), record)

    def test_abandoned_build_cleanup_is_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            builds = Path(directory)
            abandoned = builds / f".build-{self.source_id}-123"
            abandoned.mkdir(); (abandoned / "partial").write_text("x")
            with mock.patch.object(indexer, "BUILD_ROOT", str(builds)):
                indexer.cleanup_build_temporaries(self.source_id)
            self.assertFalse(abandoned.exists())
            untrusted = builds / f".build-{self.source_id}-456"
            untrusted.symlink_to(builds / "elsewhere")
            with mock.patch.object(indexer, "BUILD_ROOT", str(builds)), \
                 self.assertRaisesRegex(indexer.GraphIndexError, "codegraph_build_recovery_untrusted"):
                indexer.cleanup_build_temporaries(self.source_id)

    def test_second_indexer_is_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / f".index-{self.source_id}.lock"
            descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with mock.patch.object(indexer, "BUILD_ROOT", directory), \
                     mock.patch.object(indexer.os, "geteuid", return_value=0), \
                     mock.patch.object(indexer, "_build_locked") as build, \
                     self.assertRaisesRegex(indexer.GraphIndexError, "codegraph_index_in_progress"):
                    indexer.build(self.source_id)
                build.assert_not_called()
            finally:
                os.close(descriptor)

    def test_status_recovers_existing_index_and_reports_absence(self):
        with tempfile.TemporaryDirectory() as directory:
            root, markers, builds, destination, record, metadata = self.fixture(directory)
            with mock.patch.multiple(indexer, ROOT=str(root), MARKER_ROOT=str(markers), BUILD_ROOT=str(builds)), \
                 mock.patch.object(indexer.os, "geteuid", return_value=0), \
                 mock.patch.object(indexer, "registered_source", return_value=record), \
                 mock.patch.object(indexer, "validate_recoverable_index", return_value=metadata) as validate:
                present = indexer.index_status(self.source_id)
                self.assertEqual(present["status"], "indexed")
                self.assertEqual(present["codegraph_index_sha256"], metadata["codegraph_index_sha256"])
                validate.assert_called_once_with(self.source_id, str(destination), record)
                destination.rename(root / "removed")
                absent = indexer.index_status(self.source_id)
                self.assertEqual(absent["status"], "not_indexed")

    def test_status_rejects_marker_without_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "indexes"; root.mkdir()
            markers = Path(directory) / "markers"; markers.mkdir()
            (markers / f"{self.source_id}.json").write_text("{}")
            with mock.patch.multiple(indexer, ROOT=str(root), MARKER_ROOT=str(markers)), \
                 mock.patch.object(indexer.os, "geteuid", return_value=0), \
                 mock.patch.object(indexer, "registered_source", return_value={}):
                with self.assertRaisesRegex(indexer.GraphIndexError, "codegraph_marker_without_index"):
                    indexer.index_status(self.source_id)


if __name__ == "__main__":
    unittest.main()
