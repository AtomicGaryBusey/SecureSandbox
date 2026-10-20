#!/usr/bin/env python3
"""Normalize Gateway journal metadata into the bounded telemetry spool."""

from __future__ import annotations

import json
import re
import select
import subprocess
import time

from telemetry_receiver import append_events, normalize

POLICY_HASH_FILE = "/etc/secure-sandbox/policy.sha256"
HEARTBEAT_SECONDS = 60
INBOUND_DROP_THROTTLE_SECONDS = 300


class InboundDropThrottle:
    """Emit the first identical inbound drop, then at most one per interval."""

    def __init__(self, interval: float = INBOUND_DROP_THROTTLE_SECONDS) -> None:
        self.interval = interval
        self.last_emitted: dict[tuple[str, int], float] = {}

    def allow(self, event: dict, now: float) -> bool:
        if event.get("EventType") != "firewall_inbound_drop":
            return True
        key = (str(event.get("Destination", "")), int(event.get("DestinationPort", 0)))
        previous = self.last_emitted.get(key)
        if previous is not None and now - previous < self.interval:
            return False
        self.last_emitted[key] = now
        return True


def event_base(event_type: str, severity: str = "info", decision: str = "") -> dict:
    try:
        with open(POLICY_HASH_FILE, encoding="ascii") as handle:
            policy_hash = handle.read(128).strip()
    except OSError:
        policy_hash = "unavailable"
    return {
        "RunId": "preflight",
        "VmId": "gateway",
        "AgentId": "model-broker",
        "EventType": event_type,
        "Severity": severity,
        "Decision": decision,
        "PolicyHash": policy_hash,
    }


def from_journal(record: dict) -> dict | None:
    message = record.get("MESSAGE", "")
    unit = record.get("_SYSTEMD_UNIT", "")
    identifier = record.get("SYSLOG_IDENTIFIER", "")
    if identifier == "secure-sandbox-pki":
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
        event = event_base(kind, "critical" if status == "critical" else "warning" if status == "warning" else "info", "allow")
        event["RequestId"] = generation
        event["Status"] = remaining
        event["ResponseBytes"] = minimum
        event["Message"] = status
        return event
    if identifier == "secure-sandbox-lease":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"lease_issued", "lease_renewed", "lease_finalized"}:
            return None
        event = event_base(kind, "info", "allow")
        event["RunId"] = str(value.get("run_id", "preflight"))
        event["RequestId"] = str(value.get("lease_id", ""))
        event["Status"] = int(value.get("expires_at", 0))
        event["Message"] = str(value.get("reason", ""))
        return event
    if identifier == "secure-sandbox-source":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {"source_plan_created", "source_fetch_started", "source_fetch_completed", "source_fetch_failed", "source_acquisition_completed"}:
            return None
        failed = kind == "source_fetch_failed"
        event = event_base(kind, "critical" if failed else "info", "deny" if failed else "allow")
        event["RequestId"] = str(value.get("plan_id", ""))
        event["ResponseBytes"] = int(value.get("archive_bytes", 0))
        event["Message"] = str(value.get("error", "source acquisition lifecycle"))
        return event
    if unit in {"conversation-receiver.service", "conversation-azure-shipper.service"}:
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        allowed = {
            "conversation_chunk_received",
            "conversation_blob_uploaded",
            "conversation_blob_upload_failed",
            "artifact_received",
            "artifact_blob_uploaded",
            "artifact_blob_upload_failed",
            "source_manifest_received",
            "source_manifest_blob_uploaded",
            "source_manifest_blob_upload_failed",
        }
        if kind not in allowed:
            return None
        failed = kind.endswith("failed")
        event = event_base(kind, "critical" if failed else "info", "deny" if failed else "allow")
        name = str(value.get("name", ""))
        event["RunId"] = "preflight" if name.startswith(("artifact-", "source-")) else (name[:36] if len(name) >= 36 else "preflight")
        event["ResponseBytes"] = int(value.get("bytes", 0))
        event["RequestId"] = name[-68:-4] if name.endswith(".age") else ""
        event["Message"] = str(value.get("detail", value.get("error", "encrypted evidence lifecycle")))
        return event
    if unit == "model-broker.service":
        try:
            value = json.loads(message)
        except (TypeError, ValueError):
            return None
        kind = str(value.get("event", ""))
        if kind not in {
            "request_complete",
            "request_denied",
            "upstream_failed",
            "health",
            "lease_reserved",
        }:
            return None
        denied = kind in {"request_denied", "upstream_failed"}
        event = event_base(kind, "warning" if denied else "info", "deny" if denied else "allow")
        event["RunId"] = str(value.get("run_id", event["RunId"]))
        event.update(
            {
                "Status": int(value.get("status", 0)),
                "RequestBytes": int(value.get("request_bytes", 0)),
                "ResponseBytes": int(value.get("response_bytes", 0)),
                "RequestId": str(value.get("request_id", "")),
                "Message": str(value.get("code", value.get("error", ""))),
            }
        )
        if kind == "lease_reserved":
            event["RequestId"] = str(value.get("lease_id", ""))
            event["Status"] = int(value.get("cumulative_requests", 0))
            event["RequestBytes"] = int(value.get("cumulative_input_tokens", 0))
            event["ResponseBytes"] = int(value.get("cumulative_output_tokens", 0))
            event["Message"] = "lease reservation committed"
        return event
    if isinstance(message, str) and "sandbox-gw-" in message and "-deny " in message:
        if "sandbox-gw-fwd-deny " in message:
            event = event_base("firewall_forward_deny", "critical", "deny")
        elif "sandbox-gw-out-deny " in message:
            event = event_base("firewall_egress_deny", "high", "deny")
        else:
            # Unsolicited broadcasts and scans on the Parallels shared segment
            # are expected background noise, not attempted sandbox egress.
            event = event_base("firewall_inbound_drop", "info", "drop")
        destination = re.search(r"\bDST=([^ ]+)", message)
        port = re.search(r"\bDPT=(\d+)", message)
        event["Destination"] = destination.group(1) if destination else ""
        event["DestinationPort"] = int(port.group(1)) if port else 0
        event["Message"] = "gateway nftables default policy"
        return event
    return None


def main() -> None:
    process = subprocess.Popen(
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
    assert process.stdout is not None
    next_heartbeat = 0.0
    throttle = InboundDropThrottle()
    while True:
        now = time.monotonic()
        if now >= next_heartbeat:
            append_events([normalize(event_base("heartbeat"))])
            next_heartbeat = now + HEARTBEAT_SECONDS
        ready, _, _ = select.select([process.stdout], [], [], 2.0)
        if ready:
            line = process.stdout.readline()
            if not line:
                raise RuntimeError("journal reader stopped")
            try:
                event = from_journal(json.loads(line))
            except (TypeError, ValueError):
                event = None
            if event is not None and throttle.allow(event, time.monotonic()):
                append_events([normalize(event)])


if __name__ == "__main__":
    main()
