#!/usr/bin/env python3

import json
import unittest
import uuid
from unittest import mock

import telemetry_exporter


class JournalNormalizationTests(unittest.TestCase):
    def test_pipe_buffer_drains_every_complete_line_without_waiting_for_more_input(self):
        buffer = bytearray()
        self.assertEqual(
            telemetry_exporter.complete_lines(buffer, b"first\nsecond"), [b"first"]
        )
        self.assertEqual(
            telemetry_exporter.complete_lines(buffer, b"\nthird\n"), [b"second", b"third"]
        )
        self.assertEqual(buffer, bytearray())

    @mock.patch("telemetry_exporter.ssl.create_default_context")
    @mock.patch("telemetry_exporter.http.client.HTTPSConnection")
    def test_health_probes_authenticated_gateway_endpoint(self, connection_class, context_factory):
        response = mock.Mock(status=200)
        response.read.return_value = b'{"status":"ok"}'
        connection = connection_class.return_value
        connection.getresponse.return_value = response
        telemetry_exporter.health()
        context_factory.assert_called_once_with(cafile=telemetry_exporter.CA)
        context_factory.return_value.load_cert_chain.assert_called_once_with(
            telemetry_exporter.CERT, telemetry_exporter.KEY
        )
        connection.request.assert_called_once_with(
            "GET", "/healthz", headers={"User-Agent": "SecureSandboxExporter/1"}
        )

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_pki_evidence_is_bounded_and_content_free(self, _open):
        generation = "00000000-0000-4000-8000-000000000001"
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-pki",
            "MESSAGE": json.dumps({
                "event": "pki_generation_activated", "generation_id": generation,
                "minimum_not_after": 123456, "remaining_seconds": 654321,
                "status": "ok", "private_key": "must not escape",
            }),
        })
        self.assertEqual(result["RequestId"], generation)
        self.assertEqual(result["Message"], "ok")
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_pki_expiry_canary_preserves_only_bounded_identifier(self, _open):
        generation = "00000000-0000-4000-8000-000000000001"
        evidence_id = str(uuid.uuid4())
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-pki",
            "MESSAGE": json.dumps({
                "event": "pki_expiry_status", "generation_id": generation,
                "minimum_not_after": 123456, "remaining_seconds": 654321,
                "status": "ok", "evidence_id": evidence_id,
            }),
        })
        self.assertEqual(result["EventType"], "pki_expiry_status")
        self.assertEqual(result["RequestId"], generation)
        self.assertEqual(result["Message"], f"ok:{evidence_id}")

    def test_malformed_pki_evidence_is_rejected(self):
        self.assertIsNone(telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-pki",
            "MESSAGE": '{"event":"pki_expiry_status","generation_id":"bad"}',
        }))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_active_run_execution_rejection_is_fixed_and_content_free(self, _open):
        value = {
            "event": "execution_rejected", "request_id": "", "source_id": "source-id",
            "code_sha256": "a" * 64, "status": "active_run_required", "duration_ms": 0,
            "content": "must-not-escape",
        }
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-execution", "MESSAGE": json.dumps(value),
        })
        self.assertEqual(result["EventType"], "execution_rejected")
        self.assertEqual(result["Decision"], "deny")
        self.assertIn("status=active_run_required", result["Message"])
        self.assertNotIn("must-not-escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_operator_cancellation_is_exported_as_content_free_denial(self, _open):
        value = {
            "event": "execution_rejected", "request_id": "", "source_id": "source-id",
            "code_sha256": "a" * 64, "status": "approval_cancelled", "duration_ms": 0,
            "content": "must-not-escape",
        }
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-execution", "MESSAGE": json.dumps(value),
        })
        self.assertEqual(result["Decision"], "deny")
        self.assertIn("status=approval_cancelled", result["Message"])
        self.assertNotIn("must-not-escape", json.dumps(result))

    def test_audit_correlator_flags_unapproved_destination(self):
        correlator = telemetry_exporter.AuditCorrelator()
        syscall = 'type=SYSCALL msg=audit(1.2:99): success=no comm="bash" key="agent-network"'
        address = 'type=SOCKADDR msg=audit(1.2:99): SADDR={ saddr_fam=inet laddr=8.8.8.8 lport=443 }'
        self.assertIsNone(correlator.feed(syscall))
        event = correlator.feed(address)
        self.assertEqual(event["EventType"], "network_connect_unapproved")
        self.assertEqual(event["Decision"], "deny")
        self.assertEqual(event["Destination"], "8.8.8.8")
        self.assertEqual(event["DestinationPort"], 443)

    def test_audit_correlator_allows_relay_destination(self):
        correlator = telemetry_exporter.AuditCorrelator()
        correlator.feed('type=SYSCALL msg=audit(1.2:100): success=yes comm="claude" key="agent-network"')
        event = correlator.feed('type=SOCKADDR msg=audit(1.2:100): SADDR={ laddr=127.0.0.1 lport=18080 }')
        self.assertEqual(event["EventType"], "network_connect")
        self.assertEqual(event["Decision"], "allow")

    def test_nonblocking_relay_connect_is_allowed_even_when_syscall_is_in_progress(self):
        correlator = telemetry_exporter.AuditCorrelator()
        correlator.feed('type=SYSCALL msg=audit(1.2:101): success=no exit=-115 comm="claude" key="agent-network"')
        event = correlator.feed('type=SOCKADDR msg=audit(1.2:101): SADDR={ laddr=127.0.0.1 lport=18080 }')
        self.assertEqual(event["EventType"], "network_connect")
        self.assertEqual(event["Decision"], "allow")
        self.assertEqual(event["Status"], -1)

    def test_execution_identity_to_fixed_target_is_allowed_independent_of_binary_name(self):
        correlator = telemetry_exporter.AuditCorrelator()
        correlator.feed('type=SYSCALL msg=audit(1.2:102): success=yes comm="curl" key="execution-network"')
        event = correlator.feed('type=SOCKADDR msg=audit(1.2:102): SADDR={ laddr=172.30.20.2 lport=8080 }')
        self.assertEqual(event["EventType"], "network_connect")
        self.assertEqual(event["Decision"], "allow")

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_relay_event_contains_no_content(self, _open):
        message = json.dumps(
            {
                "event": "relay_complete",
                "request_id": "abc",
                "request_bytes": 123,
                "response_bytes": 456,
                "status": 200,
                "run_id": "boundary-test",
                "prompt": "must not escape",
            }
        )
        result = telemetry_exporter.normalize_journal(
            {"_SYSTEMD_UNIT": "claude-relay.service", "MESSAGE": message}
        )
        self.assertEqual(result["RequestBytes"], 123)
        self.assertEqual(result["RunId"], "boundary-test")
        self.assertNotIn("prompt", result)
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_watchdog_event_contains_only_lease_metadata(self, _open):
        value = {
            "event": "lease_watchdog_expired",
            "run_id": "00000000-0000-4000-8000-000000000001",
            "lease_id": "00000000-0000-4000-8000-000000000002",
            "process_groups": 1,
            "content": "must not escape",
        }
        result = telemetry_exporter.normalize_journal({
            "_SYSTEMD_UNIT": "run-lease-watchdog.service", "MESSAGE": json.dumps(value),
        })
        self.assertEqual(result["RequestId"], value["lease_id"])
        self.assertEqual(result["Status"], 1)
        self.assertNotIn("must not escape", json.dumps(result))
        value["event"] = "lease_watchdog_enforcement_failed"
        failed = telemetry_exporter.normalize_journal({
            "_SYSTEMD_UNIT": "run-lease-watchdog.service", "MESSAGE": json.dumps(value),
        })
        self.assertEqual(failed["Severity"], "critical")

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_firewall_event_extracts_only_destination(self, _open):
        result = telemetry_exporter.normalize_journal(
            {
                "MESSAGE": "sandbox-r-out-deny IN= OUT=ctl0 SRC=172.30.10.2 DST=8.8.8.8 PROTO=TCP DPT=443"
            }
        )
        self.assertEqual(result["Destination"], "8.8.8.8")
        self.assertEqual(result["DestinationPort"], 443)
        self.assertEqual(result["Decision"], "deny")

    def test_unrelated_log_is_ignored(self):
        self.assertIsNone(telemetry_exporter.normalize_journal({"MESSAGE": "hello"}))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_dependency_event_retains_only_content_free_lifecycle_metadata(self, _open):
        value = {
            "event": "dependency_bundle_completed",
            "plan_id": "plan-id",
            "bundle_id": "bundle-id",
            "dependency_set_sha256": "a" * 64,
            "dependency_count": 3,
            "missing_count": 0,
            "package_name": "must-not-escape",
        }
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-dependency-orchestrator",
            "MESSAGE": json.dumps(value),
        })
        self.assertEqual(result["EventType"], "dependency_bundle_completed")
        self.assertEqual(result["RequestId"], "bundle-id")
        self.assertIn("count=3", result["Message"])
        self.assertNotIn("must-not-escape", json.dumps(result))

        plan = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-dependency-orchestrator",
            "MESSAGE": json.dumps({
                "event": "dependency_plan_created",
                "plan_id": "dependency-plan-id",
                "bundle_id": "",
                "dependency_set_sha256": "b" * 64,
                "dependency_count": 2,
                "missing_count": 1,
            }),
        })
        self.assertEqual(plan["RequestId"], "dependency-plan-id")

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_conversation_lifecycle_retains_only_cipher_metadata(self, _open):
        value = {
            "event": "conversation_chunk_captured",
            "run_id": "00000000-0000-4000-8000-000000000001",
            "cipher_sha256": "a" * 64,
            "bytes": 714,
            "prompt": "must not escape",
        }
        result = telemetry_exporter.normalize_journal({
            "_SYSTEMD_UNIT": "conversation-capture.service",
            "MESSAGE": json.dumps(value),
        })
        self.assertEqual(result["RequestId"], "a" * 64)
        self.assertEqual(result["ResponseBytes"], 714)
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_corrupt_journal_event_is_critical_without_raw_content(self, _open):
        value = {
            "event": "conversation_journal_record_wrapped",
            "run_id": "00000000-0000-4000-8000-000000000001",
            "raw_sha256": "b" * 64,
            "raw_bytes": 42,
            "raw_base64": "must-not-escape",
        }
        result = telemetry_exporter.normalize_journal({
            "_SYSTEMD_UNIT": "conversation-capture.service",
            "MESSAGE": json.dumps(value),
        })
        self.assertEqual(result["Severity"], "critical")
        self.assertEqual(result["RequestId"], "b" * 64)
        self.assertNotIn("must-not-escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_tool_audit_retains_only_fixed_metadata(self, _open):
        message = json.dumps(
            {
                "event": "claude_tool_audit",
                "event_type": "sandbox_bypass_requested",
                "severity": "critical",
                "decision": "request",
                "request_id": "toolu-1",
                "run_id": "boundary-test",
                "message": "signal=sandbox_bypass tool=Bash command_sha256=abc",
                "command": "must not escape",
            }
        )
        result = telemetry_exporter.normalize_journal(
            {"_SYSTEMD_UNIT": "claude-tool-auditor.service", "MESSAGE": message}
        )
        self.assertEqual(result["EventType"], "sandbox_bypass_requested")
        self.assertEqual(result["Severity"], "critical")
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_corpus_query_retains_hash_and_counts_not_query(self, _open):
        message = json.dumps({
            "event": "corpus_query_completed",
            "tool": "search_corpus",
            "source_id": "11111111-1111-4111-8111-111111111111",
            "query_sha256": "a" * 64,
            "files_examined": 52657,
            "total_matches": 42,
            "returned": 25,
            "status": "ok",
            "query": "must not escape",
        })
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-corpus-intelligence",
            "MESSAGE": message,
        })
        self.assertEqual(result["EventType"], "corpus_query_completed")
        self.assertEqual(result["Status"], 42)
        self.assertIn("query_sha256=" + "a" * 64, result["Message"])
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_review_bundle_telemetry_is_content_free(self, _open):
        message = json.dumps({
            "event": "review_bundle_verified",
            "bundle_id": "evidence-receipts-review",
            "manifest_sha256": "d" * 64,
            "file_count": 21,
            "status": "verified",
            "filename": "must-not-escape.py",
            "content": "must not escape",
        })
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-source-integrity",
            "MESSAGE": message,
        })
        self.assertEqual(result["EventType"], "review_bundle_verified")
        self.assertEqual(result["RequestId"], "evidence-receipts-review")
        self.assertEqual(result["Status"], 21)
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_review_bundle_telemetry_rejects_forged_identity(self, _open):
        message = json.dumps({
            "event": "review_bundle_verified",
            "bundle_id": "bad;content=must-not-escape-review",
            "manifest_sha256": "d" * 64,
            "file_count": 1,
            "status": "verified",
        })
        self.assertIsNone(telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-source-integrity",
            "MESSAGE": message,
        }))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_memory_proposal_telemetry_excludes_proposed_content(self, _open):
        message = json.dumps({
            "event": "memory_proposal_queued",
            "proposal_id": "11111111-1111-4111-8111-111111111111",
            "content_sha256": "c" * 64,
            "category": "working_principle",
            "proposal": "must not escape",
            "rationale": "also must not escape",
        })
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-memory-proposal",
            "MESSAGE": message,
        })
        self.assertEqual(result["EventType"], "memory_proposal_queued")
        self.assertEqual(result["RequestId"], "11111111-1111-4111-8111-111111111111")
        self.assertIn("content_sha256=" + "c" * 64, result["Message"])
        self.assertNotIn("must not escape", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_memory_proposal_telemetry_rejects_forged_fields(self, _open):
        base = {
            "SYSLOG_IDENTIFIER": "secure-sandbox-memory-proposal",
            "MESSAGE": json.dumps({
                "event": "memory_proposal_queued",
                "proposal_id": "not-a-uuid;content=must-not-escape",
                "content_sha256": "c" * 64,
                "category": "working_principle",
                "error": "",
            }),
        }
        self.assertIsNone(telemetry_exporter.normalize_journal(base))
        base["MESSAGE"] = json.dumps({
            "event": "memory_proposal_rejected",
            "proposal_id": "",
            "content_sha256": "",
            "category": "invalid",
            "error": "must-not-escape",
        })
        self.assertIsNone(telemetry_exporter.normalize_journal(base))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_findings_telemetry_excludes_claim_and_evidence_content(self, _open):
        message = json.dumps({
            "event": "finding_submitted", "operation": "submit",
            "finding_id": "11111111-1111-4111-8111-111111111111",
            "content_sha256": "d" * 64, "claim_evidence_support": "supported",
            "claim": "must not escape", "evidence": [{"content": "also secret"}],
        })
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-findings", "MESSAGE": message,
        })
        self.assertEqual(result["EventType"], "finding_submitted")
        self.assertEqual(result["RequestId"], "11111111-1111-4111-8111-111111111111")
        self.assertNotIn("must not escape", json.dumps(result))
        self.assertNotIn("also secret", json.dumps(result))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_findings_telemetry_rejects_forged_metadata(self, _open):
        forged = {
            "event": "finding_rejected", "operation": "submit", "finding_id": "",
            "content_sha256": "", "claim_evidence_support": "", "error": "claim=must-not-escape",
        }
        self.assertIsNone(telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-findings", "MESSAGE": json.dumps(forged),
        }))

        transport = {
            "event": "finding_rejected", "operation": "invalid", "finding_id": "",
            "content_sha256": "", "claim_evidence_support": "", "error": "request_too_large",
            "payload": "must not escape",
        }
        result = telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER": "secure-sandbox-findings", "MESSAGE": json.dumps(transport),
        })
        self.assertEqual(result["EventType"], "finding_rejected")
        self.assertIn("error=request_too_large", result["Message"])
        self.assertNotIn("must not escape", json.dumps(result))

        mismatch = {
            "event":"finding_rejected", "operation":"submit", "finding_id":"",
            "content_sha256":"", "claim_evidence_support":"",
            "error":"receipt_projection_mismatch_receipt_sha256",
        }
        mismatch_result=telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER":"secure-sandbox-findings","MESSAGE":json.dumps(mismatch),
        })
        self.assertIn("error=receipt_projection_mismatch_receipt_sha256",mismatch_result["Message"])
        mismatch["error"]="receipt_projection_mismatch_private_claim"
        self.assertIsNone(telemetry_exporter.normalize_journal({
            "SYSLOG_IDENTIFIER":"secure-sandbox-findings","MESSAGE":json.dumps(mismatch),
        }))

    @mock.patch("telemetry_exporter.open", side_effect=OSError)
    def test_evidence_receipt_event_is_content_free(self, _open):
        receipt_id="12345678-1234-4234-8234-123456789abc"
        value={"event":"receipt_published","instrument":"search_corpus","receipt_id":receipt_id,
               "status":"ok","query":"secret needle","stdout":"secret output"}
        result=telemetry_exporter.normalize_journal({"SYSLOG_IDENTIFIER":"secure-sandbox-evidence-receipts",
            "MESSAGE":json.dumps(value)})
        self.assertEqual(result["RequestId"],receipt_id)
        self.assertEqual(result["Message"],"instrument=search_corpus;status=ok")
        self.assertNotIn("secret",json.dumps(result))

        value["event"]="receipt_reused"
        reused=telemetry_exporter.normalize_journal({"SYSLOG_IDENTIFIER":"secure-sandbox-evidence-receipts",
            "MESSAGE":json.dumps(value)})
        self.assertEqual(reused["EventType"],"receipt_reused")
        self.assertNotIn("secret",json.dumps(reused))


if __name__ == "__main__":
    unittest.main()
