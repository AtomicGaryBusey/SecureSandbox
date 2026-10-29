import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "control_center_api", Path(__file__).with_name("control-center-api.py")
)
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


class CatalogTests(unittest.TestCase):
    def test_session_catalog_preserves_content_free_fields(self):
        raw = (
            "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL\n"
            "11111111-1111-1111-1111-111111111111\t2026-10-28T01:00:00Z\t"
            "2026-10-28T02:00:00Z\t2\t0\t1\tExample\n"
        )
        with patch.object(API, "run_labctl", return_value=raw):
            result = API.catalog("sessions")
        self.assertEqual(result[0]["label"], "Example")
        self.assertEqual(result[0]["id"], "11111111-1111-1111-1111-111111111111")

    def test_session_catalog_rejects_extra_fields(self):
        raw = "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL\n" + "x\t" * 7
        with patch.object(API, "run_labctl", return_value=raw):
            with self.assertRaises(ValueError):
                API.catalog("sessions")

    def test_source_catalog_rejects_invalid_commit(self):
        raw = "2026-10-28T01:00:00Z\t11111111-1111-1111-1111-111111111111\towner/repo\tbad\tpath\n"
        with patch.object(API, "run_labctl", return_value=raw):
            with self.assertRaises(ValueError):
                API.catalog("sources")

    def test_artifact_catalog_accepts_verified_metadata_and_rejects_extra_fields(self):
        artifact_id = "11111111-1111-4111-8111-111111111111"
        run_id = "22222222-2222-4222-8222-222222222222"
        raw = f"2026-10-28T01:00:00Z\t{artifact_id}\tv2\treport.md\t{run_id}\t{'a' * 64}\n"
        with patch.object(API, "run_labctl", return_value=raw):
            self.assertEqual(API.catalog("artifacts")[0]["file_name"], "report.md")
        with patch.object(API, "run_labctl", return_value=raw.replace(run_id, "preflight")):
            self.assertEqual(API.catalog("artifacts")[0]["run_id"], "preflight")
        with patch.object(API, "run_labctl", return_value=raw.replace(run_id, "invalid")):
            with self.assertRaisesRegex(ValueError, "identity"):
                API.catalog("artifacts")
        with patch.object(API, "run_labctl", return_value=raw.rstrip() + "\textra\n"):
            with self.assertRaises(ValueError):
                API.catalog("artifacts")

    def test_artifact_detail_requires_selected_identity_and_verified_render(self):
        artifact_id = "11111111-1111-4111-8111-111111111111"
        run_id = "22222222-2222-4222-8222-222222222222"
        raw = (f"Artifact: {artifact_id}\nCaptured: 2026-10-28T01:00:00Z\n"
               f"Source: report.md (version 2)\nRun: {run_id}\nSHA-256: {'a' * 64}\n"
               "---\nReport text\n")
        with patch.object(API, "run_labctl", return_value=raw) as command:
            detail = API.artifact_detail(artifact_id)
        self.assertEqual(detail["content"], "Report text\n")
        command.assert_called_once_with("artifact", artifact_id)
        with patch.object(API, "run_labctl", return_value=raw.replace(run_id, "preflight")):
            self.assertEqual(API.artifact_detail(artifact_id)["run_id"], "preflight")
        with patch.object(API, "run_labctl", return_value=raw.replace(artifact_id, run_id)):
            with self.assertRaises(ValueError):
                API.artifact_detail(artifact_id)

    def test_status_requires_versioned_record(self):
        with patch.object(API, "run_labctl", return_value='{"schema":"wrong"}'):
            with self.assertRaises(ValueError):
                API.catalog("overview")

    def test_github_url_rejects_credentials_query_and_subpaths(self):
        for url in (
            "https://github.com/owner/repo?x=1",
            "https://github.com/owner/repo/tree/main",
            "http://github.com/owner/repo",
            "https://github.com:443/owner/repo",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                API.normalize_github_url(url)
        self.assertEqual(API.normalize_github_url("https://github.com/owner/repo"), "owner/repo")

    def test_plan_binds_exact_repository_and_ref(self):
        raw = (
            "Plan:       11111111-1111-4111-8111-111111111111\n"
            "Repository: owner/repo\nRequested:  main\n"
            "Commit:     " + "a" * 40 + "\nExpires:    2026-10-28T02:00:00Z\n"
        )
        with patch.object(API, "run_labctl", return_value=raw) as command:
            plan = API.plan_source("https://github.com/owner/repo", "main")
        command.assert_called_once_with("source", "plan", "owner/repo", "main")
        self.assertEqual(plan["resolved_commit"], "a" * 40)

    def test_npm_plan_binds_exact_package_and_version(self):
        raw = ("Plan:       11111111-1111-4111-8111-111111111111\n"
               "Package:    @scope/package\nVersion:    1.2.3\n"
               "Integrity:  " + "a" * 40 + "\nExpires:    2026-10-28T02:00:00Z\n")
        with patch.object(API, "run_labctl", return_value=raw) as command:
            plan = API.plan_npm("@scope/package", "1.2.3")
        self.assertEqual(plan["repository"], "npm/scope--package")
        command.assert_called_once_with("source", "npm-plan", "@scope/package", "1.2.3")
        with self.assertRaises(ValueError):
            API.plan_npm("@scope/package", "latest")

    def test_label_is_bounded_and_identity_checked(self):
        session_id = "11111111-1111-1111-1111-111111111111"
        with patch.object(API, "run_labctl", return_value=f"labeled\t{session_id}\tResearch\n") as command:
            result = API.label_session(session_id, "Research")
        self.assertEqual(result, {"session_id": session_id, "label": "Research"})
        command.assert_called_once_with("session", "label", session_id, "Research")
        for bad in ("", " leading", "x" * 121, "has\nnewline"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                API.label_session(session_id, bad)

    def test_unlabel_requires_exact_response(self):
        session_id = "11111111-1111-1111-1111-111111111111"
        with patch.object(API, "run_labctl", return_value=f"unlabeled\t{session_id}\n") as command:
            self.assertEqual(API.unlabel_session(session_id)["label"], "")
        command.assert_called_once_with("session", "unlabel", session_id)
        with patch.object(API, "run_labctl", return_value="wrong"):
            with self.assertRaises(ValueError):
                API.unlabel_session(session_id)

    def test_host_error_sanitizes_gateway_diagnostics(self):
        raw = b'{"error":"github_status_422","event":"source_controller_rejected"}\n'
        self.assertIn("ref", API.host_error(raw, 1))
        self.assertNotIn("source_controller_rejected", API.host_error(raw, 1))
        self.assertEqual(API.host_error(b"private traceback", 7), "The host operation failed with status 7.")
        lifecycle = (b'private detail\n{"schema":"secure-sandbox-host-lifecycle-v1",'
                     b'"phase":"preflight","action_failures":["parallels_gui_running"]}\n')
        self.assertIn("parallels_gui_running", API.host_error(lifecycle, 1))
        self.assertNotIn("private detail", API.host_error(lifecycle, 1))
        boundary = (b'{"schema":"secure-sandbox-host-lifecycle-v1",'
                    b'"phase":"boundary_verification",'
                    b'"action_failures":["boundary_verification_failed"]}\n')
        self.assertIn("Boundary Verification in Maintenance", API.host_error(boundary, 1))

    def test_import_reconciles_one_time_plan_to_completed_source(self):
        plan_id = "11111111-1111-4111-8111-111111111111"
        source_id = "22222222-2222-4222-8222-222222222222"
        base = {"schema": "secure-sandbox-source-plan-status-v1", "plan_id": plan_id,
                "repository": "owner/repo", "resolved_commit": "a" * 40,
                "requested_ref": "main", "expires_at": "2026-10-28T02:00:00Z"}
        import json
        initial = json.dumps({**base, "state": "planned"})
        final = json.dumps({**base, "state": "completed", "source_id": source_id})
        output = (f"Source: {source_id}\nBaseline: path\nRepository: owner/repo\n"
                  "Index: repos/INDEX.json\nEvidence: archived and verified\n")
        with patch.object(API, "run_labctl", side_effect=[initial, output, final]) as command:
            result = API.apply_source(plan_id)
        self.assertEqual(result["source_id"], source_id)
        self.assertEqual(command.call_count, 3)

    def test_import_never_replays_claimed_plan(self):
        plan_id = "11111111-1111-4111-8111-111111111111"
        import json
        state = json.dumps({"schema": "secure-sandbox-source-plan-status-v1",
                            "plan_id": plan_id, "repository": "owner/repo",
                            "resolved_commit": "a" * 40, "state": "claimed"})
        with patch.object(API, "run_labctl", return_value=state) as command:
            with self.assertRaises(ValueError):
                API.apply_source(plan_id)
        command.assert_called_once_with("source", "status", plan_id)

    def test_activity_projects_only_metadata(self):
        raw = ('{"TimeGenerated":"2026-10-28T01:00:00Z","EventType":"heartbeat",'
               '"Severity":"info","Status":0,"VmId":"gateway",'
               '"Message":"ready","private_payload":"do not expose"}\n')
        with patch.object(API, "run_labctl", return_value=raw):
            rows = API.catalog("activity")
        self.assertEqual(rows[0]["sequence"], 0)
        self.assertNotIn("private_payload", rows[0])

    def test_maintenance_reports_independent_checks(self):
        clocks = ("sandbox-gateway: skew=0s\n"
                  "sandbox-research-admin: skew=0s\n"
                  "sandbox-target-admin: skew=0s\n"
                  "SecureSandbox guest clocks are within 5s of the Mac.\n")
        with patch.object(API, "run_labctl", side_effect=[clocks, RuntimeError("policy")]):
            status = API.maintenance()
        self.assertEqual(status, {"time_sync": "verified", "snapshot_policy": "attention"})

    def test_finding_detail_requires_explicit_id_and_projects_text(self):
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        candidate = {"finding_id": finding_id, "claim": "Claim", "counterargument": "Counter",
                     "limitations": "Limit", "claim_evidence_support": "supported",
                     "proposed_severity": "low", "submitted_at": "2026-10-28T01:00:00Z",
                     "evidence": [{"class": "static_source_review"}], "private_payload": "hidden",
                     "content_sha256": "a" * 64}
        raw = json.dumps({"candidate": candidate, "amendments": [], "events": [],
                          "current_state": "candidate"})
        with patch.object(API, "run_labctl", return_value=raw) as command:
            detail = API.finding_detail(finding_id)
        self.assertEqual(detail["evidence_count"], 1)
        self.assertEqual(detail["evidence"][0]["sha256"],
                         __import__("hashlib").sha256(b'{"class":"static_source_review"}').hexdigest())
        self.assertNotIn("private_payload", detail)
        command.assert_called_once_with("finding", "show", finding_id)

    def test_finding_transition_stages_exact_request_and_verifies_journal_receipt(self):
        import json
        import tempfile
        from subprocess import CompletedProcess
        finding_id = "11111111-1111-4111-8111-111111111111"
        event_id = "22222222-2222-4222-8222-222222222222"
        evidence = "b" * 64
        request = {"schema": "secure-sandbox-control-center-finding-transition-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "candidate", "to_state": "needs_evidence",
                   "verification_method": "inspected_evidence", "consulted_evidence": [evidence],
                   "actor_id": "operator", "actor_role": "research_lead",
                   "rationale": "More measurement needed", "conflict_note": "No conflict disclosed"}
        before = {"content_sha256": "a" * 64, "current_state": "candidate",
                  "evidence": [{"sha256": evidence}], "claim_requires_execution": False}
        receipt = {"status": "recorded", "finding_id": finding_id,
                   "event_id": event_id, "entry_sha256": "c" * 64}
        after = {"current_state": "needs_evidence", "events": [{
            "event_id": event_id, "entry_sha256": "c" * 64,
            "to_state": "needs_evidence", "consulted_evidence": [evidence]}]}
        staged_paths = []
        def command(argv, *, timeout):
            staged_paths.append(Path(argv[-1]))
            payload = json.loads(staged_paths[-1].read_text())
            self.assertEqual(payload["actor"], {"id": "operator", "role": "research_lead"})
            self.assertEqual(payload["consulted_evidence"], [evidence])
            return CompletedProcess(argv, 0, json.dumps(receipt).encode(), b"")
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / ".private").mkdir()
            with (patch.object(API, "ROOT", Path(directory)),
                  patch.object(API, "finding_detail", return_value=before),
                  patch.object(API, "bounded_command", side_effect=command),
                  patch.object(API, "run_labctl", return_value=json.dumps(after))):
                self.assertEqual(API.apply_finding_transition(request)["status"], "verified")
            self.assertFalse(staged_paths[0].exists())
        with patch.object(API, "finding_detail", return_value={**before, "current_state": "disputed"}):
            with self.assertRaisesRegex(ValueError, "changed since review"):
                API.apply_finding_transition(request)
        validate = {**request, "to_state": "validated"}
        with (patch.object(API, "finding_detail", return_value={**before, "claim_requires_execution": True}),
              patch.object(API, "bounded_command") as command):
            with self.assertRaisesRegex(ValueError, "requires reviewed evidence"):
                API.apply_finding_transition(validate)
            command.assert_not_called()

    def test_finding_relation_binds_selected_target_and_journal_event(self):
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        target_id = "22222222-2222-4222-8222-222222222222"
        event_id = "33333333-3333-4333-8333-333333333333"
        request = {"schema": "secure-sandbox-control-center-finding-relation-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "candidate", "relation": "duplicate_of",
                   "target_finding_id": target_id, "actor_id": "operator",
                   "actor_role": "research_lead", "rationale": "Same cause",
                   "conflict_note": "No conflict disclosed"}
        before = {"finding_id": finding_id, "content_sha256": "a" * 64, "current_state": "candidate"}
        target = {"finding_id": target_id}
        receipt = {"status": "recorded", "finding_id": finding_id,
                   "event_id": event_id, "entry_sha256": "b" * 64}
        after = {"current_state": "candidate", "events": [{"event_id": event_id,
                 "entry_sha256": "b" * 64, "relation": "duplicate_of", "target_finding_id": target_id}]}
        with (patch.object(API, "finding_detail", side_effect=[before, target]),
              patch.object(API, "submit_finding_action", return_value=receipt) as submit,
              patch.object(API, "run_labctl", return_value=json.dumps(after))):
            self.assertEqual(API.apply_finding_relation(request)["status"], "verified")
        self.assertEqual(submit.call_args.args[0]["target_finding_id"], target_id)

    def test_reopen_options_exclude_terminal_evidence_and_bind_new_digest(self):
        import hashlib
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        old = {"class": "operator_reported", "observation": "old"}
        new = {"class": "operator_reported", "observation": "new"}
        digest = lambda item: hashlib.sha256(json.dumps(item, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        raw = {"candidate": {"evidence": [old]}, "amendments": [{"evidence": [new]}],
               "events": [{"event": "state_changed", "to_state": "rejected",
                           "terminal_evidence_sha256": [digest(old)],
                           "terminal_report_content_sha256": []}]}
        detail = {"current_state": "rejected", "content_sha256": "a" * 64,
                  "evidence": [{"sha256": digest(old)}, {"sha256": digest(new)}]}
        with (patch.object(API, "finding_detail", return_value=detail),
              patch.object(API, "run_labctl", return_value=json.dumps(raw))):
            options = API.finding_reopen_options(finding_id)
        self.assertEqual([item["sha256"] for item in options["options"]], [digest(new)])

        request = {"schema": "secure-sandbox-control-center-finding-reopen-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "rejected", "new_evidence_sha256": digest(new),
                   "actor_id": "operator", "actor_role": "research_lead",
                   "rationale": "New evidence", "conflict_note": "No conflict disclosed"}
        event_id = "22222222-2222-4222-8222-222222222222"
        receipt = {"status": "recorded", "finding_id": finding_id,
                   "event_id": event_id, "entry_sha256": "b" * 64}
        after = {"current_state": "needs_evidence", "events": [{"event": "reopened",
                 "event_id": event_id, "entry_sha256": "b" * 64,
                 "new_evidence_sha256": digest(new)}]}
        with (patch.object(API, "finding_reopen_options", return_value=options),
              patch.object(API, "submit_finding_action", return_value=receipt),
              patch.object(API, "run_labctl", return_value=json.dumps(after))):
            self.assertEqual(API.apply_finding_reopen(request)["state"], "needs_evidence")

    def test_disposition_requires_matching_archive_marker_readback(self):
        import json
        finding_id = "11111111-1111-4111-8111-111111111111"
        request = {"schema": "secure-sandbox-control-center-finding-disposition-v1",
                   "finding_id": finding_id, "expected_content_sha256": "a" * 64,
                   "expected_state": "rejected", "actor_id": "operator",
                   "actor_role": "research_lead", "rationale": "Archive terminal record",
                   "conflict_note": "No conflict disclosed"}
        before = {"content_sha256": "a" * 64, "current_state": "rejected"}
        receipt = {"status": "disposed", "finding_id": finding_id,
                   "terminal_state": "rejected", "content_sha256": "b" * 64}
        observed = {"schema": "secure-sandbox-finding-disposition-status-v1",
                    "finding_id": finding_id, "state": "rejected",
                    "content_sha256": "b" * 64, "candidate_sha256": "a" * 64}
        with (patch.object(API, "finding_detail", return_value=before),
              patch.object(API, "catalog", return_value=[{"finding_id": finding_id,
                "disposition": "active", "content_sha256": "a" * 64}]),
              patch.object(API, "submit_finding_action", return_value=receipt),
              patch.object(API, "run_labctl", return_value=json.dumps(observed))):
            self.assertEqual(API.apply_finding_disposition(request)["status"], "verified")
        observed["content_sha256"] = "c" * 64
        with (patch.object(API, "finding_detail", return_value=before),
              patch.object(API, "catalog", return_value=[{"finding_id": finding_id,
                "disposition": "active", "content_sha256": "a" * 64}]),
              patch.object(API, "submit_finding_action", return_value=receipt),
              patch.object(API, "run_labctl", return_value=json.dumps(observed))):
            with self.assertRaisesRegex(ValueError, "archive readback"):
                API.apply_finding_disposition(request)

    def test_boundary_verification_requires_final_success_marker(self):
        from subprocess import CompletedProcess
        good = "PASS  first\nPASS  second\nGATE  notice\nBOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use.\n"
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, good.encode(), b"")):
            result = API.verify_boundaries()
        self.assertEqual(result, {"status": "verified", "passed_checks": 2, "gate_notices": 1,
                                  "failed_checks": 0, "failure_labels": []})
        failed = "PASS  first\nFAIL  Gateway source mismatch\nFAIL  Research control files mismatch\nBOUNDARY VERIFICATION FAILED: 2 check(s)\n"
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, failed.encode(), b"")):
            result = API.verify_boundaries()
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["failure_labels"], ["Gateway source mismatch", "Research control files mismatch"])
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, b"PASS  first\n", b"")):
            with self.assertRaises(ValueError):
                API.verify_boundaries()
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 1,
                          failed.replace("2 check(s)", "3 check(s)").encode(), b"")):
            with self.assertRaises(RuntimeError):
                API.verify_boundaries()

    def test_lifecycle_requires_final_record_and_independent_state(self):
        import json
        before = {"status": "verified", "observed": {"gateway": "running", "research": "running", "target": "running"}}
        after = {"status": "verified", "observed": {"gateway": "stopped", "research": "stopped", "target": "stopped"}}
        completed = json.dumps({"schema": "secure-sandbox-host-lifecycle-v1", "operation": "stop",
                                "status": "verified", "phase": "complete"}) + "\n"
        from subprocess import CompletedProcess
        with (patch.object(API, "catalog", side_effect=[before, after]) as catalog,
              patch.object(API, "run_labctl", return_value=completed) as command,
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b""))):
            self.assertEqual(API.lifecycle("stop")["status"], "verified")
        self.assertEqual(catalog.call_count, 2)
        command.assert_called_once_with("stop")
        after["observed"]["target"] = "running"
        with (patch.object(API, "catalog", side_effect=[before, after]),
              patch.object(API, "run_labctl", return_value=completed),
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b""))):
            with self.assertRaisesRegex(ValueError, "independent VM state"):
                API.lifecycle("stop")

    def test_lifecycle_refuses_open_parallels_gui(self):
        from subprocess import CompletedProcess
        before = {"status": "verified", "observed": {"gateway": "running", "research": "running", "target": "running"}}
        with (patch.object(API, "catalog", return_value=before),
              patch.object(API, "run_labctl") as command,
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 0, b"", b""))):
            with self.assertRaisesRegex(ValueError, "Quit Parallels"):
                API.lifecycle("stop")
        command.assert_not_called()

    def test_start_completion_exposes_verified_clocks_boundaries_and_uplink(self):
        import json
        from subprocess import CompletedProcess
        before = {"status": "verified", "observed": {"gateway": "stopped", "research": "stopped", "target": "stopped"}}
        after = {"status": "verified",
                 "observed": {"gateway": "running", "research": "running", "target": "running",
                              "gateway_net0": "connected"},
                 "reachability": {"gateway": "reachable", "research": "reachable", "target": "reachable"}}
        completed = json.dumps({"schema": "secure-sandbox-host-lifecycle-v1", "operation": "start",
                                "status": "verified", "phase": "complete"}) + "\n"
        with (patch.object(API, "catalog", side_effect=[before, after]),
              patch.object(API, "run_labctl", return_value=completed),
              patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b""))):
            result = API.lifecycle("start")
        self.assertEqual(result["gateway_net0"], "connected")
        self.assertEqual(result["guest_reachability"], "verified")
        self.assertEqual(result["clock_sync"], "verified")
        self.assertEqual(result["boundary_verification"], "verified")

    def test_lifecycle_progress_rejects_untrusted_phase(self):
        import json
        active = {"schema": "secure-sandbox-host-lifecycle-progress-v1",
                  "state": "active", "operation": "start", "phase": "guest_readiness",
                  "target": "research", "transition_id": "11111111-1111-4111-8111-111111111111",
                  "observed_at": "2026-10-29T00:00:00Z"}
        with patch.object(API, "run_labctl", return_value=json.dumps(active)):
            self.assertEqual(API.lifecycle_progress()["phase"], "guest_readiness")
        with patch.object(API, "run_labctl", return_value=json.dumps({**active, "phase": "complete"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.lifecycle_progress()
        with patch.object(API, "run_labctl", return_value=json.dumps({"schema": active["schema"], "state": "idle"})):
            self.assertEqual(API.lifecycle_progress()["state"], "idle")

    def test_dependency_plan_parses_exact_readiness(self):
        source_id = "11111111-1111-4111-8111-111111111111"
        plan_id = "22222222-2222-4222-8222-222222222222"
        raw = (f"Plan: {plan_id}\nRoot: @scope/root@1.2.3\nSet SHA256: {'a' * 64}\n"
               "Expires: 2026-10-28T01:00:00Z\nMISSING\tleft-pad\t1.0.0\t-\n")
        with patch.object(API, "run_labctl", return_value=raw) as command:
            plan = API.dependency_plan(source_id)
        self.assertEqual(plan["dependencies"][0]["state"], "MISSING")
        command.assert_called_once_with("dependencies", "plan", source_id)
        with self.assertRaises(ValueError):
            API.dependency_rows("READY\tleft-pad\t1.0.0\t-\n")

    def test_dependency_bundle_apply_requires_ready_and_catalog_readback(self):
        plan_id = "22222222-2222-4222-8222-222222222222"
        bundle_id = "33333333-3333-4333-8333-333333333333"
        source_id = "44444444-4444-4444-8444-444444444444"
        digest = "a" * 64
        ready = {"plan_id": plan_id, "dependencies": [
            {"state": "READY", "package": "left-pad", "version": "1.0.0", "source_id": source_id}]}
        raw = (f"Bundle: {bundle_id}\nRoot: root@1.0.0\nDependencies: 1\n"
               f"Set SHA256: {digest}\nLifecycle: disabled\n")
        bundles = [{"id": bundle_id, "dependency_set_sha256": digest}]
        with (patch.object(API, "dependency_status", return_value=ready),
              patch.object(API, "run_labctl", return_value=raw) as command,
              patch.object(API, "dependency_bundles", return_value=bundles)):
            self.assertEqual(API.dependency_apply(plan_id, digest)["bundle_id"], bundle_id)
        command.assert_called_once_with("dependencies", "apply", plan_id)
        ready["dependencies"][0]["state"] = "MISSING"
        with (patch.object(API, "dependency_status", return_value=ready),
              patch.object(API, "run_labctl") as command):
            with self.assertRaisesRegex(ValueError, "Import the missing"):
                API.dependency_apply(plan_id, digest)
        command.assert_not_called()

    def test_index_source_accepts_only_matching_sealed_result(self):
        import json
        source_id = "11111111-1111-4111-8111-111111111111"
        result = {"schema": "secure-sandbox-corpus-index-v1", "source_id": source_id,
                  "status": "indexed", "index_content_sha256": "a" * 64,
                  "indexed_documents": 10}
        with patch.object(API, "run_labctl", return_value=json.dumps(result)) as command:
            self.assertEqual(API.index_source("corpus", source_id)["item_count"], 10)
        command.assert_called_once_with("corpus", "index", source_id)
        with patch.object(API, "run_labctl", return_value=json.dumps({**result, "source_id": "other"})):
            with self.assertRaises(ValueError):
                API.index_source("corpus", source_id)
        with self.assertRaises(ValueError):
            API.index_source("shell", source_id)

    def test_backup_preflight_requires_encryption_capacity_and_stopped_stack(self):
        import tempfile
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as destination:
            stopped = {"status": "verified", "observed": {
                "gateway": "stopped", "research": "stopped", "target": "stopped"}}
            with (patch.object(API, "vm_footprint", return_value={"gateway": 10, "research": 20, "target": 30}),
                  patch.object(API, "destination_volume", return_value={"volume_uuid": "a" * 36, "encrypted": True}),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=100000000, f_frsize=512))):
                self.assertTrue(API.backup_preflight(destination)["ready"])
            with (patch.object(API, "vm_footprint", return_value={"gateway": 10, "research": 20, "target": 30}),
                  patch.object(API, "destination_volume", return_value={"volume_uuid": "a" * 36, "encrypted": False}),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=100000000, f_frsize=512))):
                self.assertFalse(API.backup_preflight(destination)["ready"])

    def test_destination_requires_encryption_of_apfs_volume_itself(self):
        import plistlib
        from subprocess import CompletedProcess
        import tempfile
        with tempfile.TemporaryDirectory() as destination:
            info = {"FilesystemName": "APFS", "VolumeUUID": "11111111-1111-1111-1111-111111111111",
                    "Encryption": True, "EncryptionThisVolumeProper": False, "FileVault": False}
            with patch.object(API.subprocess, "run", side_effect=[
                CompletedProcess([], 0, b"Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk9s1 1 1 1 1% /Volumes/Test\n", b""),
                CompletedProcess([], 0, plistlib.dumps(info), b"")]):
                self.assertFalse(API.destination_volume(Path(destination))["encrypted"])

    def test_backup_inventory_and_restore_preview_verify_selected_generation(self):
        import tempfile
        from types import SimpleNamespace
        from scripts import control_center_backup as backup
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "vms"
            source.mkdir()
            config = root / "config"
            config.mkdir()
            for name in backup.HOST_CONFIG_FILES:
                (config / name).write_text(name)
            identities = {}
            for index, name in enumerate(backup.NAMES, 1):
                bundle = source / f"{name}.pvm"
                bundle.mkdir()
                (bundle / "config.pvs").write_text(name)
                identities[name] = f"{index:08x}-1111-4111-8111-111111111111"
            volume = "11111111-1111-4111-8111-111111111111"
            generation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            key = b"k" * 32
            backup.create_backup(source, config, root, identities, volume, key,
                                 copier=lambda source_path, target_path: __import__("shutil").copytree(source_path, target_path),
                                 generation=generation)
            stopped = {"status": "verified", "observed": {
                "gateway": "stopped", "research": "stopped", "target": "stopped"}}
            operations = SimpleNamespace(backup=SimpleNamespace(read_backup_key=lambda: key,
                                                                 verify_backup=backup.verify_backup,
                                                                 host_config_inventory=backup.host_config_inventory),
                                         vm_identities=lambda _: {
                                             name: {"uuid": value} for name, value in identities.items()})
            with (patch.object(API, "ROOT", root),
                  patch.object(API, "backup_operations", return_value=operations),
                  patch.object(API, "destination_volume", return_value={"volume_uuid": volume, "encrypted": True}),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=100000000, f_frsize=512))):
                entries = API.backup_inventory(str(root))["entries"]
                self.assertEqual(entries[0]["state"], "unverified")
                preview = API.restore_preview(str(root), generation)
                self.assertTrue(preview["ready"])
                self.assertEqual(preview["file_count"], 3 + len(backup.HOST_CONFIG_FILES))
                (config / backup.HOST_CONFIG_FILES[0]).write_text("changed")
                changed = API.restore_preview(str(root), generation)
                self.assertFalse(changed["ready"])
                self.assertEqual(changed["differing_host_config"], [backup.HOST_CONFIG_FILES[0]])
                (config / backup.HOST_CONFIG_FILES[0]).write_text(backup.HOST_CONFIG_FILES[0])
                stage = root / f".secure-sandbox-backup-{generation}.incomplete"
                stage.mkdir()
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    API.restore_preview(str(root), generation)
                stage.rmdir()
                (root / f"secure-sandbox-backup-{generation}/vms/{backup.NAMES[0]}.pvm/config.pvs").write_text("tampered")
                with self.assertRaises(backup.BackupError):
                    API.restore_preview(str(root), generation)

    def test_memory_proposals_expose_only_bounded_metadata(self):
        import json
        item = {"proposal_id": "11111111-1111-4111-8111-111111111111",
                "run_id": "22222222-2222-4222-8222-222222222222",
                "created_at": "2026-10-29T00:00:00Z", "category": "workflow",
                "title": "Review this", "content_sha256": "a" * 64,
                "status": "pending_operator_review", "authority": "untrusted_proposal"}
        with patch.object(API, "run_labctl", return_value=json.dumps(item) + "\n") as command:
            self.assertEqual(API.memory_proposals()[0]["title"], "Review this")
        command.assert_called_once_with("memory", "proposals")
        with patch.object(API, "run_labctl", return_value=json.dumps({**item, "content": "untrusted"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.memory_proposals()
        with patch.object(API, "run_labctl", return_value=json.dumps({**item, "run_id": "unknown"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.memory_proposals()
        with patch.object(API, "run_labctl", return_value=json.dumps({**item, "authority": "operator_adjudication"})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.memory_proposals()

    def test_restore_plan_requires_ready_preview_and_binds_current_identities(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        generation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        preview = {"ready": True, "destination": "/Volumes/Backup", "volume_uuid": "b" * 36,
                   "manifest_hmac_sha256": "c" * 64, "file_count": 12, "logical_bytes": 1000}
        identities = {"vm": {"uuid": generation}}
        created = {"restore_id": generation}
        service = SimpleNamespace(backup=SimpleNamespace(read_backup_key=lambda: b"k" * 32),
                                  base=SimpleNamespace(vm_identities=lambda _: identities),
                                  default_root=lambda: Path("/tmp/restore-plans"),
                                  create_plan=Mock(return_value=created),
                                  plan_detail=Mock(return_value={"restore_id": generation}))
        with (patch.object(API, "restore_preview", return_value=preview),
              patch.object(API, "restore_operations", return_value=service)):
            self.assertEqual(API.plan_restore("/Volumes/Backup", generation)["restore_id"], generation)
        self.assertEqual(service.create_plan.call_args.args[5], identities)
        with (patch.object(API, "restore_preview", return_value={"ready": False}),
              patch.object(API, "restore_operations") as operations):
            with self.assertRaisesRegex(ValueError, "not ready"):
                API.plan_restore("/Volumes/Backup", generation)
        operations.assert_not_called()

    def test_transcript_requires_selected_run_and_escapes_untrusted_records(self):
        run_id = "11111111-1111-4111-8111-111111111111"
        raw = '{"type":"assistant","text":"\\u001b[31mtool output"}\n'
        with patch.object(API, "run_labctl", return_value=raw) as command:
            detail = API.transcript_detail(run_id)
        command.assert_called_once_with("transcript", run_id)
        self.assertEqual(detail["record_count"], 1)
        self.assertIn("\\u001b", detail["content"])
        with patch.object(API, "run_labctl") as command:
            with self.assertRaises(ValueError):
                API.transcript_detail("invalid")
        command.assert_not_called()
        with patch.object(API, "run_labctl", return_value='["not an object"]\n'):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.transcript_detail(run_id)

    def test_transcript_archive_uses_archive_deadline(self):
        from subprocess import CompletedProcess
        with patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, b"{}\n", b"")) as command:
            API.run_labctl("transcript", "11111111-1111-4111-8111-111111111111")
        self.assertEqual(command.call_args.kwargs["timeout"], 300)

    def test_transcript_export_streams_verified_records_and_preserves_destination_on_failure(self):
        import hashlib
        import tempfile
        from pathlib import Path
        run_id = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = root / "labctl"
            destination = root / "transcript.jsonl"
            command.write_text("#!/usr/bin/env python3\nimport sys\nprint('{\"type\":\"user\",\"text\":\"\\\\u001b[31m\"}')\n")
            command.chmod(0o700)
            with patch.object(API, "LABCTL", command):
                result = API.export_transcript(run_id, str(destination))
            content = destination.read_bytes()
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["record_count"], 1)
            self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
            self.assertIn(b"\\u001b", content)
            destination.write_text("keep")
            command.write_text("#!/usr/bin/env python3\nprint('{\"type\":\"user\"}')\nraise SystemExit(1)\n")
            with patch.object(API, "LABCTL", command):
                with self.assertRaises(RuntimeError):
                    API.export_transcript(run_id, str(destination))
            self.assertEqual(destination.read_text(), "keep")
            self.assertEqual(list(root.glob(".secure-sandbox-transcript-*.tmp")), [])

    def test_transcript_export_exceeds_preview_limit_without_bridge_bulk_output(self):
        import tempfile
        from pathlib import Path
        run_id = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = root / "labctl"
            command.write_text("#!/usr/bin/env python3\nimport json\nfor _ in range(9000):\n"
                               "    print(json.dumps({'type': 'user', 'text': 'x' * 1024}))\n")
            command.chmod(0o700)
            destination = root / "large.jsonl"
            with patch.object(API, "LABCTL", command):
                result = API.export_transcript(run_id, str(destination))
            self.assertEqual(result["record_count"], 9000)
            self.assertGreater(result["byte_count"], API.MAX_OUTPUT)
            self.assertEqual(destination.stat().st_size, result["byte_count"])

    def test_tool_result_catalog_binds_exact_archived_block_digest(self):
        import hashlib
        import json
        run_id = "11111111-1111-4111-8111-111111111111"
        records = [
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": "toolu_abc", "name": "Bash", "input": {"command": "true"}}]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_abc", "content": "ok\\u001b[31m", "is_error": False}]}},
        ]
        raw = "\n".join(json.dumps(record) for record in records) + "\n"
        def stage_fixture(_run_id, destination):
            Path(destination).write_text(raw)
            return {"status": "verified"}
        with patch.object(API, "export_transcript", side_effect=stage_fixture):
            catalog = API.tool_result_catalog(run_id)
            row = catalog["results"][0]
            detail = API.tool_result_detail(run_id, "toolu_abc", row["sha256"])
            self.assertEqual(hashlib.sha256(detail["content"].encode()).hexdigest(), row["sha256"])
            with self.assertRaisesRegex(ValueError, "digest changed"):
                API.tool_result_detail(run_id, "toolu_abc", "0" * 64)

    def test_tool_result_catalog_reads_run_larger_than_preview_limit(self):
        import json
        import tempfile
        from pathlib import Path
        run_id = "11111111-1111-4111-8111-111111111111"
        with tempfile.TemporaryDirectory() as directory:
            command = Path(directory) / "labctl"
            command.write_text("#!/usr/bin/env python3\nimport json\n"
                               "for _ in range(9000):\n"
                               "    print(json.dumps({'type':'assistant','text':'x'*1024}))\n"
                               "print(json.dumps({'type':'assistant','message':{'content':[{'type':'tool_use','id':'toolu_large','name':'Bash'}]}}))\n"
                               "print(json.dumps({'type':'user','message':{'content':[{'type':'tool_result','tool_use_id':'toolu_large','content':'ok'}]}}))\n")
            command.chmod(0o700)
            with patch.object(API, "LABCTL", command):
                catalog = API.tool_result_catalog(run_id)
                self.assertEqual(catalog["results"][0]["tool_use_id"], "toolu_large")
                detail = API.tool_result_detail(run_id, "toolu_large", catalog["results"][0]["sha256"])
                self.assertIn('"content":"ok"', detail["content"])

    def test_session_run_links_accept_exact_private_catalog_projection(self):
        import json
        session_id = "11111111-1111-4111-8111-111111111111"
        run_id = "22222222-2222-4222-8222-222222222222"
        value = {"schema": "secure-sandbox-session-runs-v2", "session_id": session_id,
                 "total_runs": 3, "run_ids": [run_id]}
        with patch.object(API, "run_labctl", return_value=json.dumps(value)) as command:
            self.assertEqual(API.session_runs(session_id)["run_ids"], [run_id])
        command.assert_called_once_with("session", "runs", session_id)
        with patch.object(API, "run_labctl", return_value=json.dumps({**value, "run_ids": ["bad"]})):
            with self.assertRaisesRegex(ValueError, "invalid"):
                API.session_runs(session_id)

    def test_lease_renewal_uses_fixed_duration_and_independent_readback(self):
        import json
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        lease = {"schema": "secure-sandbox-run-lease-v1", "run_id": run_id,
                 "lease_id": lease_id, "expires_at": 1000, "maximum_expires_at": 2000,
                 "renewals": 0}
        counters = {"schema": "secure-sandbox-run-lease-counter-v1", "run_id": run_id,
                    "lease_id": lease_id, "requests": 2, "input_tokens": 3, "output_tokens": 4}
        initial = json.dumps({"lease": lease, "counters": counters, "summary": None})
        renewed_lease = {**lease, "expires_at": 1300, "renewals": 1}
        renewed = json.dumps({"lease": renewed_lease, "counters": counters, "summary": None})
        with patch.object(API, "run_labctl", side_effect=[initial, json.dumps(renewed_lease), renewed]) as command:
            result = API.renew_lease(run_id, 300)
        self.assertEqual(result["expires_at"], 1300)
        self.assertEqual(command.call_args_list[1].args, ("lease", "renew", run_id, "300"))
        with patch.object(API, "run_labctl") as command:
            with self.assertRaises(ValueError):
                API.renew_lease(run_id, 60)
        command.assert_not_called()

    def test_time_sync_apply_requires_running_vms_and_independent_check(self):
        overview = {"status": "verified", "observed": {
            "gateway": "running", "research": "running", "target": "running"}}
        clocks = ("sandbox-gateway: skew=0s\n"
                  "sandbox-research-admin: skew=0s\n"
                  "sandbox-target-admin: skew=0s\n"
                  "SecureSandbox guest clocks are within 5s of the Mac.\n")
        with (patch.object(API, "catalog", return_value=overview),
              patch.object(API, "run_labctl", side_effect=[clocks, clocks]) as command):
            self.assertEqual(API.apply_time_sync()["status"], "verified")
        self.assertEqual(command.call_count, 2)
        overview["observed"]["target"] = "stopped"
        with (patch.object(API, "catalog", return_value=overview),
              patch.object(API, "run_labctl") as command):
            with self.assertRaisesRegex(ValueError, "All three VMs"):
                API.apply_time_sync()
        command.assert_not_called()
        with self.assertRaises(ValueError):
            API.check_time_output(clocks.replace("sandbox-target-admin: skew=0s", "sandbox-gateway: skew=99s"))

    def test_safety_audit_projects_failed_posture_without_traceback(self):
        import json
        from subprocess import CompletedProcess
        report = {"schema": "secure-sandbox-external-containment-audit-v1",
                  "host_direct": {"posture_tier": 0},
                  "secure_sandbox_launch_path": {"verified": False,
                                                 "error": "Traceback private path active_release_source_mismatch"}}
        with patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, json.dumps(report).encode(), b"")):
            result = API.safety_audit()
        self.assertFalse(result["verified"])
        self.assertIn("deployment", result["detail"])
        self.assertNotIn("Traceback", result["detail"])

    def test_bounded_command_rejects_output_before_process_completion(self):
        with patch.object(API, "MAX_OUTPUT", 1024):
            with self.assertRaisesRegex(ValueError, "size limit"):
                API.bounded_command([sys.executable, "-c", "import sys; sys.stdout.write('x' * 2048)"], timeout=5)
        result = API.bounded_command([sys.executable, "-c", "import sys; sys.stderr.write('e' * 5000); print('ok')"], timeout=5)
        self.assertEqual(result.stdout, b"ok\n")
        self.assertEqual(len(result.stderr), 4096)

    def test_snapshot_policy_surfaces_missing_milestone_without_raw_diagnostic(self):
        from subprocess import CompletedProcess
        rejected = CompletedProcess([], 1, b"", b"Retention milestone missing or duplicated for SecretVM: private\n")
        with patch.object(API, "bounded_command", return_value=rejected):
            result = API.snapshot_policy()
        self.assertFalse(result["verified"])
        self.assertIn("required retained snapshot", result["detail"])

    def test_snapshot_preview_requires_exact_retained_counts_and_cold_stack(self):
        import json
        import tempfile
        from subprocess import CompletedProcess
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "config").mkdir()
            (root / "config/snapshot-retention.json").write_text(json.dumps({
                "schema": "secure-sandbox-snapshot-retention-v1",
                "minimum_free_gib_for_apply": 50, "maximum_snapshots_per_vm": 5,
                "virtual_machines": [f"SecureSandbox-{role}" for role in ("Gateway", "Research", "Target")],
                "retain_names": ["a", "b", "c", "d", "e"]}))
            raw = "\n".join(f"SecureSandbox-{role}: 6 snapshots; retain 5; remove 1"
                            for role in ("Gateway", "Research", "Target")) + "\n"
            stopped = {"status": "verified", "observed": {
                "gateway": "stopped", "research": "stopped", "target": "stopped"}}
            with (patch.object(API, "ROOT", root),
                  patch.object(API, "catalog", return_value=stopped),
                  patch.object(API.os, "statvfs", return_value=SimpleNamespace(f_bavail=60 * 1024**3, f_frsize=1)),
                  patch.object(API.subprocess, "run", return_value=CompletedProcess([], 1, b"", b"")),
                  patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, raw.encode(), b""))):
                preview = API.snapshot_preview()
                self.assertTrue(preview["ready"])
                self.assertEqual(sum(row["remove"] for row in preview["rows"]), 3)
                stopped["observed"]["target"] = "running"
                self.assertFalse(API.snapshot_preview()["ready"])

    def test_snapshot_apply_requires_preflight_and_independent_retained_readback(self):
        from subprocess import CompletedProcess
        before = {"ready": True}
        after = {"policy_verified": True, "stack_stopped": True, "gui_closed": True,
                 "rows": [{"vm": vm, "count": 5, "retain": 5, "remove": 0}
                          for vm in ("gateway", "research", "target")]}
        with (patch.object(API, "snapshot_preview", side_effect=[before, after]),
              patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, b"", b"lost response"))):
            self.assertEqual(API.apply_snapshot_retention()["status"], "verified")
        with (patch.object(API, "snapshot_preview", return_value={"ready": False}),
              patch.object(API, "bounded_command") as command):
            with self.assertRaisesRegex(ValueError, "preflight"):
                API.apply_snapshot_retention()
            command.assert_not_called()

    def test_panic_requires_independent_containment_readback(self):
        import json
        from subprocess import CompletedProcess
        record = {"schema": "secure-sandbox-host-lifecycle-v1", "operation": "panic",
                  "status": "verified", "observed": {"gateway": "running",
                  "research": "stopped", "target": "stopped", "gateway_net0": "disconnected"},
                  "action_failures": []}
        overview = {"status": "verified", "observed": {"gateway": "running",
                    "research": "stopped", "target": "stopped", "gateway_net0": "disconnected"}}
        with (patch.object(API, "bounded_command", return_value=CompletedProcess([], 0, json.dumps(record).encode(), b"")),
              patch.object(API, "catalog", return_value=overview)):
            self.assertEqual(API.panic()["status"], "verified")
            overview["observed"]["target"] = "running"
            self.assertEqual(API.panic()["status"], "incomplete")

    def test_identity_reload_checks_both_agent_sockets_without_returning_keys(self):
        from subprocess import CompletedProcess
        calls = []
        def command(argv, *, timeout, env=None):
            calls.append((argv, env))
            if argv[-1] == "key-load":
                return CompletedProcess(argv, 0, b"private diagnostic\n", b"")
            return CompletedProcess(argv, 0, b"256 SHA256:public-fingerprint key\n", b"")
        with patch.object(API, "bounded_command", side_effect=command):
            result = API.reload_control_identities()
        self.assertEqual(result, {"status": "verified", "provisioning": "loaded", "control": "loaded"})
        self.assertEqual([entry[1]["SSH_AUTH_SOCK"] for entry in calls[1:]],
                         ["/tmp/secure-sandbox-ssh-agent.sock", "/tmp/secure-sandbox-control-ssh-agent.sock"])

    def test_reconciliation_binds_gateway_summary_and_completed_research_record(self):
        import json
        from subprocess import CompletedProcess
        run_id = "11111111-1111-4111-8111-111111111111"
        lease_id = "22222222-2222-4222-8222-222222222222"
        digest = "a" * 64
        plan = {"schema": "secure-sandbox-lease-reconcile-plan-v1", "run_id": run_id,
                "lease_id": lease_id, "gateway_summary_sha256": digest}
        closed = {"state": "closed", "lease_id": lease_id}
        with (patch.object(API, "run_labctl", return_value=json.dumps(plan)),
              patch.object(API, "lease_status", return_value=closed)):
            self.assertEqual(API.reconcile_plan(run_id), plan)
            closed["state"] = "active"
            with self.assertRaisesRegex(ValueError, "not finalized"):
                API.reconcile_plan(run_id)
        completed = {"run_id": run_id, "lease_id": lease_id, "phase": "committed",
                     "gateway_summary_sha256": digest}
        with (patch.object(API, "reconcile_plan", return_value=plan),
              patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, b"", b"lost response")),
              patch.object(API, "completed_lease", return_value=completed)):
            self.assertEqual(API.reconcile_lease(run_id, digest), completed)
        with (patch.object(API, "reconcile_plan", return_value=plan),
              patch.object(API, "bounded_command", return_value=CompletedProcess([], 1, b"", b"lost response")),
              patch.object(API, "completed_lease", side_effect=RuntimeError("unavailable"))):
            with self.assertRaisesRegex(ValueError, "outcome is unclear"):
                API.reconcile_lease(run_id, digest)


if __name__ == "__main__":
    unittest.main()
