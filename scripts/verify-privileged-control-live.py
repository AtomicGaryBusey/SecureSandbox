#!/usr/bin/env python3
"""First-person acceptance tests for Privileged Control Plane v1."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
DEFAULT_SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
HOSTS = {
    "gateway": "sandbox-gateway-control",
    "research": "sandbox-research-control",
    "target": "sandbox-target-control",
}
SCHEMA = "secure-sandbox-privileged-control-request-v1"


class AcceptanceFailure(RuntimeError):
    pass


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_client(
    ssh_config: Path,
    host: str,
    operation: str,
    *arguments: str,
    request_id: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable, str(CLIENT), "client", "--ssh-config", str(ssh_config),
    ]
    if request_id is not None:
        command.extend(["--request-id", request_id])
    command.extend([host, "run", operation, *arguments])
    return subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=45, text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def ssh_request(ssh_config: Path, host: str, command: str, payload: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "/usr/bin/ssh", "-F", str(ssh_config), "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15", host, command,
        ],
        input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=45,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceFailure(message)


def one_json(output: str, label: str) -> dict[str, object]:
    lines = [line for line in output.splitlines() if line.strip()]
    require(len(lines) == 1, f"{label}_output_invalid")
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise AcceptanceFailure(f"{label}_json_invalid") from error
    require(isinstance(value, dict), f"{label}_json_invalid")
    return value


def expected_hashes(role: str) -> dict[str, str]:
    return {
        "dispatcher": digest(ROOT / "scripts/privileged_control.py"),
        "entrypoint": digest(ROOT / "scripts/privileged_control_entry.py"),
        "sudoers": digest(ROOT / "config/privileged-control.sudoers"),
        "sshd_policy": digest(ROOT / "config/sshd-control.conf"),
        "authorized_key": digest(ROOT / "runs/control_key.pub"),
        "role": hashlib.sha256(f"{role}\n".encode("ascii")).hexdigest(),
    }


def verify_self_check(ssh_config: Path, role: str, host: str) -> None:
    result = run_client(ssh_config, host, "control-self-check")
    require(result.returncode == 0, f"{role}_self_check_failed:{result.stderr.strip()}")
    evidence = one_json(result.stdout, f"{role}_self_check")
    require(evidence.get("schema") == "secure-sandbox-privileged-control-self-check-v1", f"{role}_self_check_schema")
    require(evidence.get("role") == role and evidence.get("status") == "verified", f"{role}_self_check_identity")
    require(evidence.get("labadmin_passwordless_sudo") is False, f"{role}_labadmin_sudo")
    files = evidence.get("files")
    require(isinstance(files, dict), f"{role}_self_check_files")
    for name, expected in expected_hashes(role).items():
        item = files.get(name)
        require(isinstance(item, dict) and item.get("sha256") == expected, f"{role}_{name}_hash")
        require(item.get("uid") == 0 and item.get("gid") == 0 and item.get("nlink") == 1, f"{role}_{name}_metadata")


def malformed_request_check(ssh_config: Path, host: str) -> None:
    result = ssh_request(ssh_config, host, "request", struct.pack(">I", 0))
    require(result.returncode == 64, "malformed_request_not_rejected")
    require(b"header_size_invalid" in result.stderr, "malformed_request_error_missing")


def forced_command_check(ssh_config: Path, host: str) -> None:
    result = ssh_request(ssh_config, host, "sh", b"")
    require(result.returncode == 64, "forced_command_not_enforced")
    require(b"control_request_required" in result.stderr, "forced_command_error_missing")


def integrity_rejection_request(request_id: str) -> bytes:
    data = b"#!/bin/bash\nexit 0\n"
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("files/install-integrity-probe.sh")
        info.size = len(data)
        info.mode = 0o755
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = 0
        archive.addfile(info, io.BytesIO(data))
    payload = output.getvalue()
    request = {
        "args": [],
        "files": [{
            "mode": 0o755,
            "path": "install-integrity-probe.sh",
            "sha256": "0" * 64,
            "size": len(data),
        }],
        "installer": "install-integrity-probe.sh",
        "kind": "deploy",
        "payload_length": len(payload),
        "request_id": request_id,
        "schema": SCHEMA,
    }
    header = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return struct.pack(">I", len(header)) + header + payload


def parse_audit(output: str, label: str) -> list[dict[str, object]]:
    records = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise AcceptanceFailure(f"{label}_audit_invalid") from error
        require(isinstance(value, dict), f"{label}_audit_invalid")
        records.append(value)
    return records


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    ssh_config = DEFAULT_SSH_CONFIG.resolve(strict=True)
    try:
        require(not ssh_config.is_symlink() and ssh_config.is_file(), "ssh_config_untrusted")
        for role, host in HOSTS.items():
            status = run_client(ssh_config, host, "control-status")
            require(status.returncode == 0, f"{role}_control_unavailable:{status.stderr.strip()}")
            status_value = one_json(status.stdout, f"{role}_status")
            require(status_value.get("role") == role, f"{role}_status_mismatch")
            verify_self_check(ssh_config, role, host)

        gateway = HOSTS["gateway"]
        target = HOSTS["target"]
        forced_command_check(ssh_config, gateway)
        malformed_request_check(ssh_config, gateway)

        denial = run_client(ssh_config, target, "pki-verify")
        require(denial.returncode == 64, "target_role_denial_failed")
        require("operation_not_allowed_for_role" in denial.stderr, "target_role_denial_error_missing")

        replay_id = str(uuid.uuid4())
        first = run_client(ssh_config, gateway, "control-status", request_id=replay_id)
        second = run_client(ssh_config, gateway, "control-status", request_id=replay_id)
        require(first.returncode == 0 and second.returncode == 64, "request_replay_not_denied")
        require("request_replayed" in second.stderr, "request_replay_error_missing")

        integrity_id = str(uuid.uuid4())
        integrity = ssh_request(
            ssh_config, gateway, "request", integrity_rejection_request(integrity_id)
        )
        require(integrity.returncode == 64, "deployment_integrity_not_rejected")
        require(b"bundle_digest_mismatch" in integrity.stderr, "deployment_integrity_error_missing")

        gateway_audit = run_client(ssh_config, gateway, "control-audit-tail")
        target_audit = run_client(ssh_config, target, "control-audit-tail")
        require(gateway_audit.returncode == 0 and target_audit.returncode == 0, "control_audit_unavailable")
        gateway_records = parse_audit(gateway_audit.stdout, "gateway")
        target_records = parse_audit(target_audit.stdout, "target")
        require(any(record.get("request_id") == replay_id and record.get("outcome") == "rejected" for record in gateway_records), "replay_audit_missing")
        require(any(record.get("request_id") == integrity_id and record.get("outcome") == "rejected" for record in gateway_records), "integrity_audit_missing")
        require(any(record.get("operation") == "pki-verify" and record.get("outcome") == "rejected" for record in target_records), "role_denial_audit_missing")
    except (AcceptanceFailure, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error), "schema": "secure-sandbox-privileged-control-live-verification-v1", "status": "rejected"}, sort_keys=True))
        return 1
    print(json.dumps({
        "roles": sorted(HOSTS),
        "schema": "secure-sandbox-privileged-control-live-verification-v1",
        "status": "verified",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
