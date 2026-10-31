#!/usr/bin/env python3

import json
import os
import pwd
import subprocess
import tempfile
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
    def test_socket_uses_agent_primary_gid_for_cleared_group_run_scope(self):
        agent = pwd.struct_passwd(("agent", "x", 1001, 1001, "", "/home/agent", "/bin/sh"))
        query = pwd.struct_passwd(("codegraph-query", "x", 1002, 1002, "", "/nonexistent", "/bin/false"))
        with mock.patch.object(service.os, "makedirs"), \
             mock.patch.object(service, "cleanup_analysis_temporaries"), \
             mock.patch.object(service.pwd, "getpwnam", side_effect=lambda name: agent if name == "agent" else query), \
             mock.patch.object(service, "serve_bounded") as serve:
            service.main()
        self.assertEqual(serve.call_args.kwargs["socket_gid"], agent.pw_gid)
        self.assertEqual(serve.call_args.kwargs["allowed_uids"], {0, agent.pw_uid})

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
             mock.patch.object(service.subprocess, "run", return_value=completed) as run, \
             mock.patch.object(service, "publish_analysis") as publish:
            response = service.handle(self.request())
        self.assertEqual(response["status"], "ok")
        self.assertTrue(response["result"]["reachable"])
        command = run.call_args.args[0]
        self.assertEqual(command[4:6], ["reachability", "/sealed/project"])
        selectors = json.loads(command[6])
        self.assertEqual(selectors["entrypoint"], {"symbol": "main", "filePath": "src/main.py"})
        self.assertEqual(command[7], "8")
        projection = publish.call_args.args[0]
        self.assertRegex(projection["analysis_id"], service.ANALYSIS_ID_RE)
        self.assertEqual(response["result"]["analysis_id"], projection["analysis_id"])

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
             mock.patch.object(service.subprocess, "run", return_value=completed), \
             mock.patch.object(service, "publish_analysis"):
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
            "analysis_id": "11111111-1111-5111-8111-111111111111",
        }
        with mock.patch.object(adapter, "request_graph", return_value=(runner_result, METADATA)):
            result = adapter.analyze_reachability(
                SOURCE_ID, "main", "src/main.py", "sink", "src/sink.py", 8
            )
        self.assertEqual(result["evidence_class"], "static_graph_reachability")
        self.assertFalse(result["measured_execution"])
        self.assertFalse(result["exhaustive"])
        self.assertEqual(result["outcome"], "static_path_found")
        self.assertEqual(result["analysis_id"], runner_result["analysis_id"])
        self.assertEqual(result["finding_evidence_pointer"], {
            "class":"static_graph_reachability","source_id":SOURCE_ID,
            "analysis_id":runner_result["analysis_id"],
        })
        self.assertIn("dddddddd dddddddd",result["digest_display"]["codegraph_index_sha256"])
        self.assertEqual(result["codegraph_index_sha256"],"d"*64)
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
        first_projection=service.reachability_projection(SOURCE_ID,self.request(),METADATA,runner_result)
        first_result={**runner_result,"analysis_id":first_projection["analysis_id"]}
        with mock.patch.object(adapter, "request_graph", return_value=(first_result, METADATA)):
            first = adapter.analyze_reachability(SOURCE_ID, "main", "src/main.py", "sink", "src/sink.py", 8)
        changed = {**METADATA, "codegraph_index_sha256": "f" * 64}
        second_projection=service.reachability_projection(SOURCE_ID,self.request(),changed,runner_result)
        second_result={**runner_result,"analysis_id":second_projection["analysis_id"]}
        with mock.patch.object(adapter, "request_graph", return_value=(second_result, changed)):
            second = adapter.analyze_reachability(SOURCE_ID, "main", "src/main.py", "sink", "src/sink.py", 8)
        self.assertNotEqual(first["analysis_id"], second["analysis_id"])

    def test_analysis_publication_is_immutable_and_replay_safe(self):
        projection=service.reachability_projection(SOURCE_ID,self.request(),METADATA,{"edgeProfile":"v1"})
        with tempfile.TemporaryDirectory() as root:
            service.publish_analysis(dict(projection),root)
            path=os.path.join(root,projection["analysis_id"]+".json")
            self.assertEqual(os.stat(path).st_mode & 0o777,0o444)
            service.publish_analysis(dict(projection),root)
            changed=dict(projection); changed["codegraph_index_sha256"]="f"*64
            with self.assertRaisesRegex(ValueError,"analysis_record_conflict"):
                service.publish_analysis(changed,root)
            os.chmod(path,0o666)
            with self.assertRaisesRegex(ValueError,"analysis_registry_untrusted"):
                service.publish_analysis(dict(projection),root)

    def test_analysis_registry_rejects_unknown_entries_and_cleans_safe_remnants(self):
        projection=service.reachability_projection(SOURCE_ID,self.request(),METADATA,{"edgeProfile":"v1"})
        with tempfile.TemporaryDirectory() as root:
            unexpected=os.path.join(root,"unexpected")
            open(unexpected,"wb").close()
            with self.assertRaisesRegex(ValueError,"analysis_registry_untrusted"):
                service.publish_analysis(dict(projection),root)
            os.unlink(unexpected)
            temporary=os.path.join(root,f'.{projection["analysis_id"]}.abcdefgh.new')
            open(temporary,"wb").close(); os.chmod(temporary,0o444)
            service.cleanup_analysis_temporaries(root)
            self.assertFalse(os.path.exists(temporary))


if __name__ == "__main__":
    unittest.main()
