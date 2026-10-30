#!/usr/bin/env python3

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("external-containment-audit.py")
SPEC = importlib.util.spec_from_file_location("external_containment_audit", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ExternalContainmentAuditTests(unittest.TestCase):
    def test_boundary_requires_no_gate(self):
        with self.assertRaisesRegex(MODULE.AuditFailure, "boundary_evidence_incomplete"):
            MODULE.validate_boundary_output(
                "PASS  vm\nGATE  cloud unavailable\n"
                "BOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use.\n"
            )

    def test_boundary_accepts_complete_output(self):
        result = MODULE.validate_boundary_output(
            "PASS  vm\nPASS  network\n"
            "BOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use.\n"
        )
        self.assertEqual(result["passed_checks"], 2)
        self.assertRegex(result["output_sha256"], r"^[0-9a-f]{64}$")

    def test_azure_requires_every_current_control(self):
        rows = [
            {"Check": "gateway_heartbeat", "Count": 1, "Latest": "now"},
            {"Check": "research_heartbeat", "Count": 1, "Latest": "now"},
        ]
        with self.assertRaisesRegex(MODULE.AuditFailure, "research_boundary_deny"):
            MODULE.validate_azure_rows(rows)

    def test_azure_accepts_all_controls(self):
        rows = [
            {"Check": "gateway_heartbeat", "Count": 3, "Latest": "a"},
            {"Check": "research_heartbeat", "Count": 2, "Latest": "b"},
            {"Check": "research_boundary_deny", "Count": 1, "Latest": "c"},
        ]
        self.assertEqual(set(MODULE.validate_azure_rows(rows)), {
            "gateway_heartbeat", "research_heartbeat", "research_boundary_deny"
        })

    def test_invalid_policy_hash_fails_closed(self):
        with self.assertRaisesRegex(MODULE.AuditFailure, "invalid_policy_hash"):
            MODULE.validate_policy_hash("unavailable", "research")

    def test_host_findings_are_required_and_preserved(self):
        audit = {"posture_tier": {"claude-code": 0}, "findings": [{"id": "x"}]}
        self.assertIs(MODULE.validate_host_audit(audit), audit)

    def test_azure_query_binds_both_policy_hashes(self):
        gateway = "a" * 64
        research = "b" * 64
        query = MODULE.azure_query(15, gateway, research)
        self.assertIn(gateway, query)
        self.assertEqual(query.count(research), 2)
        self.assertIn('RunId == "boundary-test"', query)

    def test_controller_release_requires_verified_typed_hashes(self):
        valid = {
            "schema": "secure-sandbox-host-controller-release-v1",
            "status": "verified",
            "release_id": "a" * 64,
            "launcher_sha256": "b" * 64,
            "payloads": {
                "authorization_broker": "3" * 64,
                "authorization_service": "5" * 64,
                "authorization_ui_bundle": "6" * 64,
                "authorization_ui_sources": "7" * 64,
                "control_client": "d" * 64,
                "controller": "c" * 64,
                "gpgv": "2" * 64,
                "installer_verifier": "1" * 64,
                "pki_anchor": "f" * 64,
                "release_manager": "4" * 64,
                "seed_gateway": "8" * 64,
                "seed_research": "9" * 64,
                "seed_target": "0" * 64,
                "seed_verifier": "a" * 64,
                "ssh_config": "e" * 64,
                "vm_maintenance": "b" * 64,
            },
        }
        self.assertIs(MODULE.validate_controller_release(valid), valid)
        invalid = dict(valid, status="deployed")
        with self.assertRaisesRegex(MODULE.AuditFailure, "controller_release_unverified"):
            MODULE.validate_controller_release(invalid)
        incomplete = dict(valid, payloads={
            name: digest for name, digest in valid["payloads"].items()
            if name != "authorization_service"
        })
        with self.assertRaisesRegex(MODULE.AuditFailure, "controller_payloads_invalid"):
            MODULE.validate_controller_release(incomplete)

    def test_root_only_floor_uses_exact_reviewed_fallback(self):
        denied = subprocess.CompletedProcess([], 1, json.dumps({
            "schema": "secure-sandbox-host-controller-release-v1",
            "status": "rejected", "error": "execution_approval_floor_invalid"}), "")
        verified = {"schema": "secure-sandbox-host-controller-release-v1", "status": "verified"}
        with (patch.object(MODULE.subprocess, "run", return_value=denied),
              patch.object(MODULE, "run_checked", return_value=subprocess.CompletedProcess([], 0, json.dumps(verified), "")) as fallback,
              patch.object(MODULE, "validate_controller_release", return_value=verified)):
            self.assertEqual(MODULE.verify_controller_release(Path("/repo"), 10), verified)
        self.assertIn("verify-postactivation-host-release", fallback.call_args.args[0])
        forged = subprocess.CompletedProcess([], 1, denied.stdout, "extra diagnostic")
        with (patch.object(MODULE.subprocess, "run", return_value=forged),
              patch.object(MODULE, "run_checked") as fallback):
            with self.assertRaisesRegex(MODULE.AuditFailure, "controller_release_unverified"):
                MODULE.verify_controller_release(Path("/repo"), 10)
        fallback.assert_not_called()

    def test_live_ssh_uses_the_protected_release_configuration(self):
        self.assertEqual(
            MODULE.PROTECTED_SSH_CONFIG,
            Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config"),
        )


if __name__ == "__main__":
    unittest.main()

