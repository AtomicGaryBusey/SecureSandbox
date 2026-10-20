#!/usr/bin/env python3
"""Combine an unchanged host agent audit with live SecureSandbox evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA = "secure-sandbox-external-containment-audit-v1"
CONFIG_SCHEMA = "secure-sandbox-external-containment-config-v1"
MAX_DIAGNOSTIC = 16 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AuditFailure(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_config(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema") != CONFIG_SCHEMA:
        raise AuditFailure("invalid_config_schema")
    if not re.fullmatch(r"[0-9a-f-]{36}", str(value.get("subscription_id", ""))):
        raise AuditFailure("invalid_subscription_id")
    if not re.fullmatch(r"[0-9a-f-]{36}", str(value.get("workspace_customer_id", ""))):
        raise AuditFailure("invalid_workspace_customer_id")
    launcher_path = value.get("launcher_path")
    if not isinstance(launcher_path, str) or not Path(launcher_path).is_absolute():
        raise AuditFailure("invalid_launcher_path")
    age = value.get("maximum_evidence_age_minutes")
    if not isinstance(age, int) or not 1 <= age <= 30:
        raise AuditFailure("invalid_evidence_age")
    timeouts = value.get("timeouts_seconds")
    if not isinstance(timeouts, dict):
        raise AuditFailure("invalid_timeouts")
    for name in ("agent_safety", "boundary", "azure", "ssh"):
        timeout = timeouts.get(name)
        if not isinstance(timeout, int) or not 1 <= timeout <= 300:
            raise AuditFailure(f"invalid_timeout:{name}")
    return value


def discover_agent_safety_tool() -> Path:
    override = os.environ.get("AGENT_SAFETY_TOOL")
    candidates = [Path(override)] if override else []
    candidates.extend(
        [
            Path.home() / ".agents/skills/agent-safety-check/scripts/agentsafe.py",
            Path.home() / ".codex/skills/agent-safety-check/scripts/agentsafe.py",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise AuditFailure("agent_safety_tool_unavailable")


def run_checked(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuditFailure(f"command_unavailable_or_timed_out:{command[0]}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout)[-MAX_DIAGNOSTIC:].strip()
        raise AuditFailure(f"command_failed:{command[0]}:{result.returncode}:{detail}")
    return result


def validate_host_audit(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuditFailure("invalid_host_audit")
    tiers = value.get("posture_tier")
    findings = value.get("findings")
    if not isinstance(tiers, dict) or not isinstance(tiers.get("claude-code"), int):
        raise AuditFailure("host_tier_missing")
    if not isinstance(findings, list):
        raise AuditFailure("host_findings_missing")
    return value


def validate_boundary_output(output: str) -> dict[str, Any]:
    lines = output.splitlines()
    failures = [line for line in lines if line.startswith("FAIL  ")]
    gates = [line for line in lines if line.startswith("GATE  ")]
    sentinel = "BOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use."
    if failures or gates or sentinel not in lines:
        raise AuditFailure("boundary_evidence_incomplete")
    passes = [line for line in lines if line.startswith("PASS  ")]
    if not passes:
        raise AuditFailure("boundary_evidence_empty")
    return {
        "passed_checks": len(passes),
        "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
    }


def validate_policy_hash(value: str, role: str) -> str:
    normalized = value.strip()
    if not SHA256.fullmatch(normalized):
        raise AuditFailure(f"invalid_policy_hash:{role}")
    return normalized


def validate_controller_release(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("status") != "verified":
        raise AuditFailure("controller_release_unverified")
    if value.get("schema") != "secure-sandbox-host-controller-release-v1":
        raise AuditFailure("controller_release_schema_invalid")
    if not SHA256.fullmatch(str(value.get("release_id", ""))):
        raise AuditFailure("controller_release_id_invalid")
    if not SHA256.fullmatch(str(value.get("launcher_sha256", ""))):
        raise AuditFailure("controller_launcher_hash_invalid")
    payloads = value.get("payloads")
    if not isinstance(payloads, dict) or set(payloads) != {
        "controller", "op_agents", "pki_anchor", "ssh_config"
    }:
        raise AuditFailure("controller_payloads_invalid")
    if any(not SHA256.fullmatch(str(item)) for item in payloads.values()):
        raise AuditFailure("controller_payload_hash_invalid")
    return value


def azure_query(age: int, gateway_hash: str, research_hash: str) -> str:
    return f'''let Recent = SecureSandbox_CL
| extend ObservedAt=coalesce(ingestion_time(), TimeGenerated)
| where ObservedAt > ago({age}m);
union
(Recent | where VmId == "gateway" and EventType == "heartbeat" and PolicyHash == "{gateway_hash}" | summarize Count=count(), Latest=max(ObservedAt) | extend Check="gateway_heartbeat"),
(Recent | where VmId == "research" and EventType == "heartbeat" and PolicyHash == "{research_hash}" | summarize Count=count(), Latest=max(ObservedAt) | extend Check="research_heartbeat"),
(Recent | where VmId == "research" and Decision == "deny" and RunId == "boundary-test" and PolicyHash == "{research_hash}" | summarize Count=count(), Latest=max(ObservedAt) | extend Check="research_boundary_deny")
| project Check, Count, Latest
// external-containment-audit {dt.datetime.now(dt.timezone.utc).timestamp()}'''


def validate_azure_rows(value: Any) -> dict[str, Any]:
    if not isinstance(value, list):
        raise AuditFailure("invalid_azure_result")
    required = {"gateway_heartbeat", "research_heartbeat", "research_boundary_deny"}
    accepted: dict[str, dict[str, Any]] = {}
    for row in value:
        if not isinstance(row, dict) or row.get("Check") not in required:
            continue
        try:
            count = int(row.get("Count", 0))
        except (TypeError, ValueError):
            raise AuditFailure("invalid_azure_count")
        if count > 0 and row.get("Latest"):
            accepted[str(row["Check"])] = {"count": count, "latest": row["Latest"]}
    missing = sorted(required - accepted.keys())
    if missing:
        raise AuditFailure("azure_evidence_missing:" + ",".join(missing))
    return accepted


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    launcher = Path("/usr/local/bin/secure-sandbox-claude")
    boundary = (root / "scripts/verify-boundaries.sh").resolve()
    config = load_config(root / "config/external-containment.json")
    if (
        str(launcher) != config["launcher_path"]
        or not launcher.is_file()
    ):
        raise AuditFailure("unrecognized_launcher")
    tool = discover_agent_safety_tool()
    timeouts = config["timeouts_seconds"]

    host_result = run_checked(
        [
            sys.executable,
            str(tool),
            "audit",
            "--cli",
            "claude-code",
            "--project",
            str(root),
            "--workload",
            "offensive",
            "--format",
            "json",
        ],
        timeouts["agent_safety"],
    )
    host_audit = validate_host_audit(json.loads(host_result.stdout))
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "required_tier": 4,
        "host_direct": {
            "posture_tier": host_audit["posture_tier"]["claude-code"],
            "auditor": str(tool),
            "auditor_sha256": sha256_file(tool),
            "audit": host_audit,
        },
    }
    try:
        controller_result = run_checked(
            [sys.executable, str(root / "scripts/host-controller-release.py"), "verify", "--json"],
            timeouts["ssh"],
        )
        controller_evidence = validate_controller_release(json.loads(controller_result.stdout))
        boundary_result = run_checked([str(boundary)], timeouts["boundary"])
        boundary_evidence = validate_boundary_output(boundary_result.stdout)

        ssh_config = root / "config/ssh_config"
        gateway_hash = validate_policy_hash(
            run_checked(
                ["ssh", "-F", str(ssh_config), "sandbox-gateway", "cat /etc/secure-sandbox/policy.sha256"],
                timeouts["ssh"],
            ).stdout,
            "gateway",
        )
        research_hash = validate_policy_hash(
            run_checked(
                ["ssh", "-F", str(ssh_config), "sandbox-research", "cat /etc/secure-sandbox/policy.sha256"],
                timeouts["ssh"],
            ).stdout,
            "research",
        )
        query = azure_query(config["maximum_evidence_age_minutes"], gateway_hash, research_hash)
        azure_result = run_checked(
            [
                "az",
                "monitor",
                "log-analytics",
                "query",
                "--subscription",
                config["subscription_id"],
                "--workspace",
                config["workspace_customer_id"],
                "--analytics-query",
                query,
                "--output",
                "json",
            ],
            timeouts["azure"],
        )
        azure_evidence = validate_azure_rows(json.loads(azure_result.stdout))
        report["secure_sandbox_launch_path"] = {
            "posture_tier": 4,
            "verified": True,
            "launcher": str(launcher),
            "subcommand": "claude",
            "launcher_sha256": sha256_file(launcher),
            "controller_release": controller_evidence,
            "boundary": boundary_evidence,
            "policy_hashes": {"gateway": gateway_hash, "research": research_hash},
            "off_host_evidence": azure_evidence,
            "maximum_evidence_age_minutes": config["maximum_evidence_age_minutes"],
            "scope": "new invocations through this exact launcher path at verification time",
        }
    except (AuditFailure, json.JSONDecodeError) as error:
        report["secure_sandbox_launch_path"] = {
            "posture_tier": None,
            "verified": False,
            "error": str(error),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AuditFailure, json.JSONDecodeError) as error:
        report = {
            "schema": SCHEMA,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "required_tier": 4,
            "secure_sandbox_launch_path": {
                "posture_tier": None,
                "verified": False,
                "error": str(error),
            },
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        raise SystemExit(1)

