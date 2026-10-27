#!/usr/bin/env python3

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class LocalBrokerProtocolHardeningTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_every_http_listener_uses_an_absolute_framing_contract(self):
        shared = self.text("shared/bounded_http.py")
        self.assertIn("time.monotonic() + self.handshake_seconds", shared)
        self.assertIn("threading.Timer(timeout, self._expire_framing)", shared)
        self.assertIn("self.connection.settimeout(float(self.write_seconds))", shared)
        for relative in (
            "gateway/model_broker.py",
            "gateway/telemetry_receiver.py",
            "gateway/conversation_receiver.py",
            "research/claude_relay.py",
            "target/execution_service.py",
        ):
            source = self.text(relative)
            self.assertIn("BoundedHTTPServer", source, relative)
            self.assertIn("AbsoluteFramingHandler", source, relative)
            self.assertIn("read_exact_body", source, relative)
            self.assertIn('self.headers.get("Transfer-Encoding")', source, relative)
        execution = self.text("research/execution_broker.py")
        self.assertIn("threading.Timer(REQUEST_READ_TIMEOUT_SECONDS", execution)
        self.assertIn("self._expire_framing", execution)
        self.assertIn("len(body) != length", execution)

    def test_every_shared_runtime_is_deployed_and_policy_hashed(self):
        bounded_http_deployers = (
            "scripts/deploy-foundation.sh",
            "scripts/deploy-source-acquisition.sh",
            "scripts/deploy-run-leases.sh",
            "scripts/deploy-disposable-execution.sh",
        )
        for relative in bounded_http_deployers:
            source = self.text(relative)
            self.assertIn('shared/__init__.py', source, relative)
            self.assertIn('shared/bounded_http.py', source, relative)
        for relative in (
            "scripts/deploy-run-leases.sh",
            "scripts/deploy-agent-memory-governance.sh",
            "scripts/deploy-codegraph-adapter.sh",
        ):
            self.assertIn("bounded_unix_server.py", self.text(relative), relative)
        policy = self.text("scripts/update-policy-hash.sh")
        self.assertEqual(policy.count("shared/bounded_http.py"), 3)
        self.assertIn("bounded_unix_server.py", policy)
        verifier = self.text("scripts/verify-boundaries.sh")
        self.assertIn("approved_bounded_http_hash", verifier)
        self.assertIn("approved_bounded_server_hash", verifier)

    def test_run_lease_transactions_restore_transport_dependencies(self):
        deploy = self.text("scripts/deploy-run-leases.sh")
        self.assertEqual(deploy.count("shared/__init__.py:shared_init.py"), 2)
        pairs = (
            ("scripts/install-run-leases-gateway.sh",
             "gateway/rollback-run-leases-gateway.sh"),
            ("scripts/install-run-leases-research.sh",
             "research/rollback-run-leases-research.sh"),
        )
        for installer, rollback in pairs:
            installed = self.text(installer)
            restored = self.text(rollback)
            for path in ("shared/__init__.py", "shared/bounded_http.py"):
                self.assertIn(path, installed, installer)
                self.assertIn(path, restored, rollback)
            self.assertIn("/tmp/shared_init.py", installed, installer)
        research_install = self.text("scripts/install-run-leases-research.sh")
        research_rollback = self.text("research/rollback-run-leases-research.sh")
        self.assertIn("bounded_unix_server.py", research_install)
        self.assertIn("bounded_unix_server.py", research_rollback)

    def test_live_ddd_uses_content_free_adversarial_gate(self):
        deploy = self.text("scripts/deploy-local-broker-protocol-hardening-ddd.sh")
        self.assertIn("deploy-run-leases.sh", deploy)
        self.assertIn("deploy-disposable-execution.sh", deploy)
        self.assertIn("install-local-broker-protocol-live-verifier.sh", deploy)
        self.assertIn("verify-boundaries.sh", deploy)
        verifier = self.text("scripts/local_broker_protocol_live_verifier.py")
        self.assertNotIn("capture_output=True", verifier)
        self.assertIn("FRAMING_BOUND_SECONDS", verifier)
        self.assertIn("secure-sandbox-local-broker-protocol-live-verification-v1", verifier)

    def test_target_listener_is_root_owned_and_install_is_recoverable(self):
        installer = self.text("scripts/install-disposable-execution-target.sh")
        self.assertIn("disposable-execution-target-install.pending", installer)
        self.assertIn("restore_backup", installer)
        self.assertIn('install -o root -g root -m 755 "$service_source"', installer)
        self.assertIn('install -o root -g labadmin -m 640 "$config_tmp"', installer)
        unit = self.text("target/secure-sandbox-execution.service")
        self.assertIn("ExecStart=/usr/local/libexec/secure-sandbox/execution_service.py", unit)
        service = self.text("target/execution_service.py")
        self.assertIn('CONFIG = "/etc/secure-sandbox/execution-target.json"', service)

    def test_adversarial_transport_suite_covers_required_failures(self):
        unix_tests = self.text("research/test_bounded_unix_server.py")
        for name in (
            "test_slow_client_does_not_starve_complete_request",
            "test_absolute_deadline_is_not_extended_by_slow_drip",
            "test_excess_client_gets_fixed_overload_response",
            "test_unauthorized_peer_gets_fixed_response_without_handler_entry",
            "test_handler_failure_is_isolated_and_content_free",
            "test_untrusted_existing_path_is_not_unlinked",
        ):
            self.assertIn(name, unix_tests)
        http_tests = self.text("shared/test_bounded_http.py")
        for name in (
            "test_slow_headers_cannot_hold_serial_server",
            "test_slow_body_cannot_extend_absolute_deadline",
            "test_tls_handshake_has_absolute_deadline",
            "test_non_reading_client_cannot_hold_serial_server",
        ):
            self.assertIn(name, http_tests)


if __name__ == "__main__":
    unittest.main()
