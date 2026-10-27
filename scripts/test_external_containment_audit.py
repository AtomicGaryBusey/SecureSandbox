#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path

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
                "control_client": "d" * 64,
                "controller": "c" * 64,
                "gpgv": "2" * 64,
                "installer_verifier": "1" * 64,
                "pki_anchor": "f" * 64,
                "release_manager": "4" * 64,
                "ssh_config": "e" * 64,
            },
        }
        self.assertIs(MODULE.validate_controller_release(valid), valid)
        invalid = dict(valid, status="deployed")
        with self.assertRaisesRegex(MODULE.AuditFailure, "controller_release_unverified"):
            MODULE.validate_controller_release(invalid)

    def test_live_ssh_uses_the_protected_release_configuration(self):
        self.assertEqual(
            MODULE.PROTECTED_SSH_CONFIG,
            Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config"),
        )


if __name__ == "__main__":
    unittest.main()

