#!/usr/bin/env python3

import json
import subprocess
import unittest
from unittest import mock

import codegraph_adapter as adapter
import codegraph_query_service as service


SOURCE_ID = "11111111-1111-4111-8111-111111111111"
METADATA = {
    "repository": "owner/repository",
    "resolved_commit": "a" * 40,
    "tree_manifest_sha256": "b" * 64,
    "corpus_index_content_sha256": "c" * 64,
    "codegraph_index_sha256": "d" * 64,
    "codegraph_build_commit": "build-one",
    "codegraph_bundle_sha256": "e" * 64,
}


class CodeGraphReachabilityTests(unittest.TestCase):
    def request(self):
        return {
            "operation": "reachability",
            "source_id": SOURCE_ID,
            "entrypoint": {"symbol": "main", "file_path": "src/main.py"},
            "target": {"symbol": "sink", "file_path": "src/sink.py"},
            "max_depth": 8,
        }

    def test_service_passes_only_validated_selectors_to_runner(self):
        runner_result = {
            "status": "ok",
            "reachable": True,
            "path": [],
            "nodesExamined": 2,
            "edgeProfile": "calls-callbacks-instantiation-navigation-v1",
        }
        completed = subprocess.CompletedProcess([], 0, json.dumps(runner_result).encode(), b"")
        with mock.patch.object(service, "validate_graph", return_value=("/sealed/project", METADATA)), \
             mock.patch.object(service.subprocess, "run", return_value=completed) as run:
            response = service.handle(self.request())
        self.assertEqual(response["status"], "ok")
        self.assertTrue(response["result"]["reachable"])
        command = run.call_args.args[0]
        self.assertEqual(command[4:6], ["reachability", "/sealed/project"])
        selectors = json.loads(command[6])
        self.assertEqual(selectors["entrypoint"], {"symbol": "main", "filePath": "src/main.py"})
        self.assertEqual(command[7], "8")

    def test_service_rejects_traversal_and_unknown_fields(self):
        request = self.request()
        request["entrypoint"]["file_path"] = "../main.py"
        self.assertEqual(service.handle(request)["error"], "invalid_entrypoint_selector")
        request = self.request()
        request["project_path"] = "/etc"
        self.assertEqual(service.handle(request)["error"], "invalid_request")

    def test_service_preserves_allowlisted_runner_selector_errors(self):
        completed = subprocess.CompletedProcess(
            [], 1, b"", b'{"status":"rejected","error":"ambiguous_entrypoint"}\n'
        )
        with mock.patch.object(service, "validate_graph", return_value=("/sealed/project", METADATA)), \
             mock.patch.object(service.subprocess, "run", return_value=completed):
            response = service.handle(self.request())
        self.assertEqual(response, {"status": "rejected", "error": "ambiguous_entrypoint"})

    def test_service_does_not_forward_unrecognized_runner_errors(self):
        completed = subprocess.CompletedProcess(
            [], 1, b"", b'{"status":"rejected","error":"sensitive_internal_detail"}\n'
        )
        with mock.patch.object(service, "validate_graph", return_value=("/sealed/project", METADATA)), \
             mock.patch.object(service.subprocess, "run", return_value=completed):
            response = service.handle(self.request())
        self.assertEqual(response, {"status": "rejected", "error": "codegraph_query_failed"})

    def test_adapter_labels_static_result_separately_from_execution(self):
        runner_result = {
            "reachable": True,
            "path": [{"node": {"name": "main"}, "via": None}],
            "nodesExamined": 4,
            "truncated": False,
            "edgeProfile": "calls-callbacks-instantiation-navigation-v1",
            "entrypoint": {"name": "main"},
            "target": {"name": "sink"},
        }
        with mock.patch.object(adapter, "request_graph", return_value=(runner_result, METADATA)):
            result = adapter.analyze_reachability(
                SOURCE_ID, "main", "src/main.py", "sink", "src/sink.py", 8
            )
        self.assertEqual(result["evidence_class"], "static_graph_reachability")
        self.assertFalse(result["measured_execution"])
        self.assertFalse(result["exhaustive"])
        self.assertEqual(result["outcome"], "static_path_found")
        self.assertEqual(len(result["analysis_id"]), 64)
        self.assertIn("does not prove", " ".join(result["limitations"]))

    def test_analysis_id_changes_with_sealed_graph_identity(self):
        runner_result = {
            "reachable": False,
            "path": [],
            "nodesExamined": 1,
            "truncated": False,
            "edgeProfile": "calls-callbacks-instantiation-navigation-v1",
            "entrypoint": {"name": "main"},
            "target": {"name": "sink"},
        }
        with mock.patch.object(adapter, "request_graph", return_value=(runner_result, METADATA)):
            first = adapter.analyze_reachability(SOURCE_ID, "main", "src/main.py", "sink", "src/sink.py", 8)
        changed = {**METADATA, "codegraph_index_sha256": "f" * 64}
        with mock.patch.object(adapter, "request_graph", return_value=(runner_result, changed)):
            second = adapter.analyze_reachability(SOURCE_ID, "main", "src/main.py", "sink", "src/sink.py", 8)
        self.assertNotEqual(first["analysis_id"], second["analysis_id"])


if __name__ == "__main__":
    unittest.main()
