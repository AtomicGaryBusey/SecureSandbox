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
                     "evidence": [{"class": "source"}], "private_payload": "hidden"}
        raw = json.dumps({"candidate": candidate, "amendments": [], "events": [],
                          "current_state": "candidate"})
        with patch.object(API, "run_labctl", return_value=raw) as command:
            detail = API.finding_detail(finding_id)
        self.assertEqual(detail["evidence_count"], 1)
        self.assertNotIn("private_payload", detail)
        command.assert_called_once_with("finding", "show", finding_id)

    def test_boundary_verification_requires_final_success_marker(self):
        good = "PASS  first\nPASS  second\nGATE  notice\nBOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use.\n"
        with patch.object(API, "run_labctl", return_value=good):
            result = API.verify_boundaries()
        self.assertEqual(result, {"status": "verified", "passed_checks": 2, "gate_notices": 1})
        with patch.object(API, "run_labctl", return_value="PASS  first\n"):
            with self.assertRaises(ValueError):
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


if __name__ == "__main__":
    unittest.main()
