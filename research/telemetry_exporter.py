#!/usr/bin/env python3
"""Export normalized Research metadata to the Gateway mTLS receiver."""

from __future__ import annotations

import collections
import argparse
import http.client
import json
import re
import select
import ssl
import subprocess
import time
import uuid

CA = "/etc/secure-sandbox/telemetry/ca.crt"
CERT = "/etc/secure-sandbox/telemetry/client.crt"
KEY = "/etc/secure-sandbox/telemetry/client.key"
POLICY_HASH_FILE = "/etc/secure-sandbox/policy.sha256"
RUN_ID_FILE = "/run/secure-sandbox/run-id"
DESTINATION = ("172.30.10.1", 9443)
MAX_QUEUE = 500
HEARTBEAT_SECONDS = 60


def current_run_id() -> str:
    try:
        with open(RUN_ID_FILE, encoding="ascii") as handle:
            value = handle.read(64).strip()
    except OSError:
        return "preflight"
    if value == "boundary-test":
        return value
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return "preflight"
    return str(parsed) if parsed.version == 4 and str(parsed) == value.lower() else "preflight"


class AuditCorrelator:
    """Correlate audit SYSCALL and SOCKADDR records without retaining commands."""

    def __init__(self) -> None:
        self.pending: dict[str, tuple[bool, str, bool]] = {}

    def feed(self, line: str) -> dict | None:
        serial_match = re.search(r"msg=audit\([^:]+:(\d+)\)", line)
        if not serial_match:
            return None
        serial = serial_match.group(1)
        if line.startswith("type=SYSCALL") and ('key="agent-network"' in line or 'key="execution-network"' in line):
            success = " success=yes " in line
            command = re.search(r'\bcomm="([^"]{0,64})"', line)
            self.pending[serial] = (success, command.group(1) if command else "", 'key="execution-network"' in line)
            if len(self.pending) > 256:
                self.pending.pop(next(iter(self.pending)))
            return None
        if not line.startswith("type=SOCKADDR") or serial not in self.pending:
            return None
        success, command, execution_identity = self.pending.pop(serial)
        address = re.search(r"\bladdr=([^ ]+)", line)
        port = re.search(r"\blport=(\d+)", line)
        if not address:
            return None
        destination = address.group(1)
        destination_port = int(port.group(1)) if port else 0
        approved = (
            (destination == "127.0.0.1" and destination_port in {18080, 18081})
            or (execution_identity and destination == "172.30.20.2" and destination_port == 8080)
        )
        event = base_event(
            "network_connect" if approved else "network_connect_unapproved",
            "info" if approved else "high",
            "allow" if approved else "deny",
        )
        event.update({
            "Destination": destination,
            "DestinationPort": destination_port,
            "Status": 0 if success else -1,
            "Message": f"connect syscall by {command}"[:128],
        })
        return event


def base_event(event_type: str, severity: str = "info", decision: str = "") -> dict:
    try:
        with open(POLICY_HASH_FILE, encoding="ascii") as handle:
            policy_hash = handle.read(128).strip()
    except OSError:
        policy_hash = "unavailable"
    return {
        "RunId": current_run_id(),
        "VmId": "research",
        "AgentId": "claude-code",
        "EventType": event_type,
        "Severity": severity,
        "Decision": decision,
        "PolicyHash": policy_hash,
    }


def normalize_journal(record: dict) -> dict | None:
    message = record.get("MESSAGE", "")
    unit = record.get("_SYSTEMD_UNIT", "")
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-pki":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        generation = str(value.get("generation_id", ""))
        status = str(value.get("status", ""))
        minimum = value.get("minimum_not_after", 0)
        remaining = value.get("remaining_seconds", 0)
        if (
            kind not in {"pki_expiry_status", "pki_generation_activated"}
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", generation)
            or status not in {"ok", "warning", "critical"}
            or not isinstance(minimum, int) or isinstance(minimum, bool)
            or not isinstance(remaining, int) or isinstance(remaining, bool)
        ):
            return None
        event = base_event(kind, "critical" if status == "critical" else "warning" if status == "warning" else "info", "allow")
        event["RequestId"] = generation
        event["Status"] = remaining
        event["ResponseBytes"] = minimum
        event["Message"] = status
        return event
    if unit == "run-lease-watchdog.service":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"lease_watchdog_expired", "lease_watchdog_failed", "lease_watchdog_enforcement_failed"}:
            return None
        failed = kind != "lease_watchdog_expired"
        event = base_event(kind, "critical" if failed else "warning", "deny")
        event["RunId"] = str(value.get("run_id", event["RunId"]))
        event["RequestId"] = str(value.get("lease_id", ""))
        event["Status"] = int(value.get("process_groups", 0))
        event["Message"] = str(value.get("error", "run lease expired"))
        return event
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-execution":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"execution_accepted", "execution_completed", "execution_rejected", "execution_timed_out", "execution_failed"}:
            return None
        status = str(value.get("status", ""))
        fixed_status = {
            "execution_accepted": {"accepted"}, "execution_completed": {"completed"},
            "execution_timed_out": {"timeout"}, "execution_failed": {"internal_error"},
            "execution_rejected": {
                "active_run_required","active_run_untrusted",
                "control_file_changed","control_file_too_large","file_too_large","filesystem_changed_during_verification",
                "filesystem_race","fixture_changed","fixture_integrity_mismatch","fixture_not_registered_file",
                "fixtures_too_large","integrity_manifest_hash_mismatch","invalid_code_or_source","invalid_control_json",
                "invalid_fixture_path","invalid_fixture_paths","invalid_integrity_manifest","invalid_request","invalid_scope",
                "invalid_source_id","invalid_source_index","invalid_timeout","registered_tree_missing","source_manifest_unavailable",
                "source_not_registered","too_many_entries","tree_too_large","tree_unreadable","unsafe_fixture",
                "unsafe_fixture_path","unsafe_path_collision","unsafe_registered_path","untrusted_control_file",
            },
        }
        if status not in fixed_status[kind]: return None
        denied = kind in {"execution_rejected", "execution_failed"}
        event = base_event(kind, "warning" if denied else "info", "deny" if denied else "allow")
        event.update({
            "RequestId": str(value.get("request_id", ""))[:64],
            "Status": int(value.get("duration_ms", 0)),
            "Message": (
                f"source={str(value.get('source_id', ''))[:64]};"
                f"code_sha256={str(value.get('code_sha256', ''))[:64]};"
                f"status={status}"
            ),
        })
        return event
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-corpus-intelligence":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"corpus_query_completed", "corpus_query_rejected"}:
            return None
        rejected = kind == "corpus_query_rejected"
        event = base_event(kind, "warning" if rejected else "info", "deny" if rejected else "allow")
        event.update({
            "RequestId": str(value.get("scan_id", value.get("source_id", "")))[:64],
            "Status": int(value.get("total_matches", 0)),
            "Message": (
                f"tool={str(value.get('tool', ''))[:32]};"
                f"source={str(value.get('source_id', ''))[:64]};"
                f"query_sha256={str(value.get('query_sha256', ''))[:64]};"
                f"profile={str(value.get('profile', ''))[:32]};"
                f"files={int(value.get('files_examined', 0))};"
                f"bytes={int(value.get('bytes_examined', 0))};"
                f"elapsed_ms={int(value.get('elapsed_ms', 0))};"
                f"budget_s={int(value.get('query_budget_seconds', 0))};"
                f"returned={int(value.get('returned', 0))};"
                f"status={str(value.get('status', ''))[:32]}"
            ),
        })
        return event
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-dependency-orchestrator":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"dependency_plan_created", "dependency_bundle_completed", "dependency_bundle_rejected"}:
            return None
        rejected = kind == "dependency_bundle_rejected"
        event = base_event(kind, "warning" if rejected else "info", "deny" if rejected else "allow")
        event.update({
            "RequestId": str(value.get("bundle_id") or value.get("plan_id", ""))[:64],
            "Status": int(value.get("missing_count", 0)),
            "Message": (
                f"set_sha256={str(value.get('dependency_set_sha256', ''))[:64]};"
                f"count={int(value.get('dependency_count', 0))};"
                f"missing={int(value.get('missing_count', 0))};"
                f"error={str(value.get('error', ''))[:64]}"
            ),
        })
        return event
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-source-integrity":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind in {"review_bundle_verified", "review_bundle_rejected"}:
            bundle_id = str(value.get("bundle_id", ""))
            manifest_sha256 = str(value.get("manifest_sha256", ""))
            status = str(value.get("status", ""))
            file_count = value.get("file_count", 0)
            expected_status = "verified" if kind == "review_bundle_verified" else {"rejected", "internal_error"}
            if (not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,55}[a-z0-9])?-review", bundle_id)
                    or (manifest_sha256 and not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256))
                    or not isinstance(file_count, int) or isinstance(file_count, bool)
                    or not 0 <= file_count <= 127
                    or (status != expected_status if isinstance(expected_status, str) else status not in expected_status)
                    or (status == "verified" and not manifest_sha256)
                    or (status != "verified" and (manifest_sha256 or file_count))):
                return None
            rejected = kind == "review_bundle_rejected"
            event = base_event(kind, "warning" if rejected else "info", "deny" if rejected else "allow")
            event.update({
                "RequestId": bundle_id,
                "Status": file_count,
                "Message": f"status={status};manifest_sha256={manifest_sha256}",
            })
            return event
        if kind not in {"source_integrity_verified", "source_integrity_rejected", "source_integrity_baseline_mismatch"}:
            return None
        status = str(value.get("status", ""))
        rejected = kind == "source_integrity_rejected"
        baseline_mismatch = kind == "source_integrity_baseline_mismatch"
        changed = status == "changed_or_unverified"
        event = base_event(
            kind,
            "critical" if baseline_mismatch else ("warning" if rejected or changed else "info"),
            "deny" if rejected or baseline_mismatch else "allow",
        )
        event.update({
            "RequestId": str(value.get("source_id", ""))[:64],
            "Status": int(value.get("change_count", 0)),
            "Message": f"scope={str(value.get('scope', ''))[:16]};status={status[:32]};anchor={str(value.get('anchor_status', ''))[:32]};baseline={str(value.get('baseline_status', ''))[:32]};worktree={str(value.get('worktree_status', ''))[:32]}",
        })
        return event
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-memory-proposal":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"memory_proposal_queued", "memory_proposal_rejected"}:
            return None
        rejected = kind == "memory_proposal_rejected"
        proposal_id = str(value.get("proposal_id", ""))
        content_sha256 = str(value.get("content_sha256", ""))
        category = str(value.get("category", ""))
        error = str(value.get("error", ""))
        allowed_categories = {
            "identity", "working_principle", "project_context", "operator_preference"
        }
        allowed_errors = {
            "active_run_required", "proposal_schema_invalid", "category_invalid",
            "evidence_refs_invalid", "evidence_ref_invalid", "title_invalid",
            "proposal_invalid", "rationale_invalid", "proposal_state_unavailable",
            "proposal_state_untrusted", "proposal_state_limit_exceeded", "internal_error",
        }
        uuid4 = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        sha256 = re.compile(r"^[0-9a-f]{64}$")
        if rejected:
            if proposal_id or content_sha256 or category != "invalid" or error not in allowed_errors:
                return None
        elif (
            not uuid4.fullmatch(proposal_id)
            or not sha256.fullmatch(content_sha256)
            or category not in allowed_categories
            or error
        ):
            return None
        event = base_event(kind, "warning" if rejected else "info", "deny" if rejected else "allow")
        event.update({
            "RequestId": proposal_id,
            "Status": 0,
            "Message": (
                f"category={category};"
                f"content_sha256={content_sha256};"
                f"error={error}"
            ),
        })
        return event
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-evidence-receipts":
        try: value=json.loads(message)
        except (TypeError,ValueError): return None
        kind=str(value.get("event","")); instrument=str(value.get("instrument",""))
        receipt_id=str(value.get("receipt_id","")); status=str(value.get("status",""))
        uuid4=re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        if (kind not in {"receipt_published","receipt_reused"} or instrument not in {"search_corpus","scan_corpus","run_python_fixture"}
                or not uuid4.fullmatch(receipt_id) or status!="ok"):
            return None
        event=base_event(kind,"info","allow")
        event.update({"RequestId":receipt_id,"Status":0,"Message":f"instrument={instrument};status=ok"})
        return event
    if record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-findings":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        allowed_events = {
            "finding_submitted", "finding_amended", "finding_already_submitted",
            "finding_rejected",
        }
        allowed_errors = {
            "active_run_required", "policy_generation_unavailable",
            "source_registry_unavailable", "source_registry_ambiguous",
            "source_not_registered", "source_anchor_unsupported", "source_path_invalid",
            "baseline_path_invalid",
            "candidate_schema_invalid", "amendment_schema_invalid",
            "affected_invalid", "affected_path_invalid", "affected_symbol_invalid",
            "affected_line_invalid", "evidence_invalid", "evidence_schema_invalid",
            "evidence_duplicate", "evidence_report_invalid", "evidence_path_invalid",
            "evidence_line_invalid", "operator_reference_invalid",
            "codegraph_anchor_unavailable", "codegraph_anchor_mismatch",
            "image_digest_invalid", "claim_invalid", "reproduction_conditions_invalid",
            "limitations_invalid", "counterargument_invalid", "proposed_severity_invalid",
            "severity_rationale_invalid", "finding_state_untrusted",
            "finding_state_limit_exceeded", "finding_run_limit_exceeded",
            "amendment_finding_limit_exceeded", "finding_not_available",
            "finding_id_invalid", "note_invalid", "request_schema_invalid",
            "operation_invalid", "finding_invalid", "request_too_large",
            "request_incomplete", "receipt_invalid", "receipt_unavailable",
            "receipt_untrusted", "receipt_state_untrusted", "receipt_projection_mismatch",
            "internal_error",
        }
        uuid4 = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        sha256 = re.compile(r"^[0-9a-f]{64}$")
        if kind not in allowed_events:
            return None
        finding_id = str(value.get("finding_id", ""))
        content_sha256 = str(value.get("content_sha256", ""))
        operation = str(value.get("operation", ""))
        support = str(value.get("claim_evidence_support", ""))
        error = str(value.get("error", ""))
        rejected = kind == "finding_rejected"
        if operation not in ({"submit", "amend", "invalid"} if rejected else {"submit", "amend"}):
            return None
        if rejected:
            if finding_id or content_sha256 or support or error not in allowed_errors:
                return None
        elif (
            not uuid4.fullmatch(finding_id)
            or not sha256.fullmatch(content_sha256)
            or error
            or support not in {"", "supported", "mismatch"}
        ):
            return None
        event = base_event(kind, "warning" if rejected or support == "mismatch" else "info",
                           "deny" if rejected else "allow")
        event.update({
            "RequestId": finding_id,
            "Status": 0,
            "Message": (
                f"operation={operation};content_sha256={content_sha256};"
                f"support={support};error={error}"
            ),
        })
        return event
    if unit in {
        "artifact-collector.service",
        "artifact-capture-failure.service",
        "conversation-capture.service",
        "conversation-capture-failure.service",
        "conversation-shipper.service",
    }:
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        allowed = {
            "conversation_chunk_captured",
            "conversation_journal_record_wrapped",
            "conversation_capture_failed",
            "conversation_chunk_forwarded",
            "conversation_forward_failed",
            "artifact_captured",
            "artifact_rejected",
            "artifact_capture_failed",
            "artifact_forwarded",
            "artifact_forward_failed",
            "source_manifest_forwarded",
            "source_manifest_forward_failed",
        }
        if kind not in allowed:
            return None
        failed = kind.endswith("failed")
        corruption = kind == "conversation_journal_record_wrapped"
        rejected = kind == "artifact_rejected"
        event = base_event(
            kind,
            "critical" if failed or corruption else ("warning" if rejected else "info"),
            "deny" if failed else ("drop" if rejected else "allow"),
        )
        event.update({
            "RunId": str(value.get("run_id", event["RunId"])),
            "ResponseBytes": int(value.get("bytes", 0)),
            "RequestId": str(value.get("cipher_sha256", value.get("artifact_id", value.get("raw_sha256", "")))),
            "Message": str(value.get("error", value.get("reason", "encrypted evidence lifecycle"))),
        })
        return event
    if (unit.startswith("source-import-") and unit.endswith(".service")) or record.get("SYSLOG_IDENTIFIER") == "secure-sandbox-source-importer":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"source_import_staged", "source_import_completed", "source_import_rejected"}:
            return None
        failed = kind == "source_import_rejected"
        event = base_event(kind, "warning" if failed else "info", "deny" if failed else "allow")
        event.update({
            "RunId": str(value.get("run_id", "preflight")),
            "RequestId": str(value.get("source_id", value.get("plan_id", ""))),
            "Message": str(value.get("error", "source acquisition lifecycle")),
        })
        return event
    if unit == "claude-relay.service":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        event_type = str(value.get("event", ""))
        if event_type not in {"relay_complete", "relay_denied", "relay_failed"}:
            return None
        event = base_event(event_type, "warning" if event_type != "relay_complete" else "info")
        event["RunId"] = str(value.get("run_id", event["RunId"]))
        event.update(
            {
                "Decision": "deny" if event_type == "relay_denied" else "allow",
                "Status": int(value.get("status", 0)),
                "RequestBytes": int(value.get("request_bytes", 0)),
                "ResponseBytes": int(value.get("response_bytes", 0)),
                "RequestId": str(value.get("request_id", "")),
                "Message": str(value.get("code", value.get("error", ""))),
            }
        )
        return event
    if unit == "claude-tool-auditor.service":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        if value.get("event") != "claude_tool_audit":
            return None
        allowed = {
            "sandbox_bypass_requested",
            "privilege_escalation_requested",
            "security_policy_change_requested",
            "network_tunnel_requested",
            "risky_tool_approval",
        }
        event_type = str(value.get("event_type", ""))
        severity = str(value.get("severity", ""))
        decision = str(value.get("decision", ""))
        if (
            event_type not in allowed
            or severity not in {"warning", "high", "critical"}
            or decision not in {"request", "accept", "deny"}
        ):
            return None
        event = base_event(event_type, severity, decision)
        event.update(
            {
                "RunId": str(value.get("run_id", event["RunId"])),
                "RequestId": str(value.get("request_id", "")),
                "Message": str(value.get("message", "")),
            }
        )
        return event
    if isinstance(message, str) and "sandbox-r-" in message and "-deny " in message:
        if "sandbox-r-fwd-deny " in message:
            event = base_event("firewall_forward_deny", "critical", "deny")
        elif "sandbox-r-out-deny " in message:
            event = base_event("firewall_egress_deny", "high", "deny")
        else:
            event = base_event("firewall_inbound_drop", "info", "drop")
        destination = re.search(r"\bDST=([^ ]+)", message)
        port = re.search(r"\bDPT=(\d+)", message)
        event["Destination"] = destination.group(1) if destination else ""
        event["DestinationPort"] = int(port.group(1)) if port else 0
        event["Message"] = "research nftables default policy"
        return event
    return None


def send(events: list[dict]) -> None:
    context = ssl.create_default_context(cafile=CA)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(CERT, KEY)
    body = json.dumps(events, separators=(",", ":")).encode()
    connection = http.client.HTTPSConnection(*DESTINATION, timeout=15, context=context)
    try:
        connection.request(
            "POST",
            "/v1/events",
            body=body,
            headers={"Content-Type": "application/json", "User-Agent": "SecureSandboxExporter/1"},
        )
        response = connection.getresponse()
        response.read(4096)
        if response.status != 202:
            raise RuntimeError("telemetry rejected")
    finally:
        connection.close()


def health() -> None:
    context = ssl.create_default_context(cafile=CA)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(CERT, KEY)
    connection = http.client.HTTPSConnection(*DESTINATION, timeout=5, context=context)
    try:
        connection.request("GET", "/healthz", headers={"User-Agent": "SecureSandboxExporter/1"})
        response = connection.getresponse()
        body = response.read(4096)
        if response.status != 200 or json.loads(body) != {"status": "ok"}:
            raise RuntimeError("telemetry health rejected")
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", action="store_true")
    args = parser.parse_args()
    if args.health:
        health()
        return
    journal = subprocess.Popen(
        [
            "/usr/bin/journalctl",
            "--follow",
            "--since=now",
            "--output=json",
            "--output-fields=_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,MESSAGE,PRIORITY,_BOOT_ID,__REALTIME_TIMESTAMP",
        ],
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        bufsize=1,
    )
    audit = subprocess.Popen(
        ["/usr/bin/tail", "--follow=name", "--retry", "--lines=0", "/var/log/audit/audit.log"],
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        bufsize=1,
    )
    assert journal.stdout is not None
    assert audit.stdout is not None
    correlator = AuditCorrelator()
    queue: collections.deque[dict] = collections.deque(maxlen=MAX_QUEUE)
    next_heartbeat = 0.0
    while True:
        now = time.monotonic()
        if now >= next_heartbeat:
            queue.append(base_event("heartbeat"))
            next_heartbeat = now + HEARTBEAT_SECONDS
        ready, _, _ = select.select([journal.stdout, audit.stdout], [], [], 2.0)
        for source in ready:
            line = source.readline()
            if not line:
                raise RuntimeError("telemetry source reader stopped")
            try:
                event = normalize_journal(json.loads(line)) if source is journal.stdout else correlator.feed(line)
            except (ValueError, TypeError):
                event = None
            if event is not None:
                queue.append(event)
        if queue:
            batch = list(queue)[:100]
            try:
                send(batch)
            except (OSError, RuntimeError, ssl.SSLError) as error:
                print(
                    json.dumps(
                        {
                            "event": "telemetry_send_failed",
                            "error": type(error).__name__,
                            "queued": len(queue),
                        },
                        separators=(",", ":"),
                    ),
                    flush=True,
                )
                time.sleep(2)
            else:
                for _ in batch:
                    queue.popleft()


if __name__ == "__main__":
    main()
