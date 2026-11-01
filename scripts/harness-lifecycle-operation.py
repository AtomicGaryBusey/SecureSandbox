#!/usr/bin/env python3
"""Unprivileged exact-plan producer and Touch ID requestor for harness lifecycle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import uuid
from pathlib import Path


SCHEMA = "secure-sandbox-harness-consumer-stage-v1"
WRAPPER_SCHEMA = "secure-sandbox-harness-consumer-plan-v1"
RECOVERY_SCHEMA = "secure-sandbox-harness-consumer-recovery-v1"
SAFE_FILES = ("artifact", "manifest.json", "verification.json", "qualification.json", "adapter.json")
SHA256 = re.compile(r"[0-9a-f]{64}")
SESSION_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MAX_JSON = 1024 * 1024
MAX_ARTIFACT = 254 * 1024 * 1024
CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
BROKER = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
RESOURCE = "Protected Research harness generation selector"
RECOVERY_RESOURCE = "Protected Research harness generation recovery journal"


class OperationError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True).encode("ascii")


def trusted_read(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.geteuid() or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < before.st_size <= maximum):
        raise OperationError(f"candidate_file_untrusted:{path.name}")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor); data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
            if not chunk: break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > maximum):
        raise OperationError(f"candidate_file_changed:{path.name}")
    return bytes(data)


def control(kind: str, operation: str, args: list[str] | None = None,
            payload: bytes | None = None, timeout: int = 180) -> dict:
    command = [str(CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
               "--timeout-seconds", str(timeout), "sandbox-research-control",
               kind, operation, *(args or [])]
    result = subprocess.run(command, input=payload,
                            stdin=subprocess.DEVNULL if payload is None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                            timeout=timeout + 10,
                            env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin", "LANG":"C.UTF-8"})
    if result.returncode != 0 or len(result.stdout) > MAX_JSON:
        raise OperationError("research_plan_operation_failed")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OperationError("research_plan_response_invalid") from error
    if not isinstance(value, dict):
        raise OperationError("research_plan_response_invalid")
    return value


def plan_activate(directory: Path) -> dict:
    files = {name:trusted_read(directory / name,
                               MAX_ARTIFACT if name == "artifact" else MAX_JSON)
             for name in SAFE_FILES}
    try:
        manifest = json.loads(files["manifest.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OperationError("candidate_manifest_invalid") from error
    generation_id = manifest.get("generation_id") if isinstance(manifest, dict) else None
    if not isinstance(generation_id, str) or SHA256.fullmatch(generation_id) is None:
        raise OperationError("candidate_generation_invalid")
    header = {"schema":SCHEMA, "stage_id":str(uuid.uuid4()), "generation_id":generation_id,
              "files":[{"name":name, "sha256":hashlib.sha256(files[name]).hexdigest(),
                        "size":len(files[name])} for name in SAFE_FILES]}
    encoded = canonical(header)
    payload = struct.pack(">I", len(encoded)) + encoded + b"".join(files[name] for name in SAFE_FILES)
    return control("pipe", "harness-lifecycle-stage-activate", payload=payload, timeout=300)


def session_count(generation_id: str) -> int:
    path = Path.home() / "Library/Application Support/SecureSandbox/controller-state/session-runs.json"
    try:
        data = trusted_read(path, MAX_JSON)
    except FileNotFoundError:
        return 0
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OperationError("session_catalog_invalid") from error
    sessions = value.get("sessions") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get("schema") != "secure-sandbox-session-runs-v4"
            or not isinstance(sessions, dict)):
        raise OperationError("session_catalog_invalid")
    required = {"last_started_at", "runs", "run_ids", "adapter", "model", "model_profile_id",
                "model_profile_sha256", "vendor_id", "harness_id", "harness_generation_id",
                "harness_manifest_sha256", "harness_executable_sha256",
                "harness_inventory_sha256", "harness_adapter_id", "harness_adapter_sha256",
                "harness_binding_sha256"}
    count = 0
    for session_id, record in sessions.items():
        if (not isinstance(session_id, str) or SESSION_UUID.fullmatch(session_id) is None
                or not isinstance(record, dict) or set(record) != required
                or any(SHA256.fullmatch(str(record.get(name, ""))) is None for name in (
                    "model_profile_sha256", "harness_generation_id", "harness_manifest_sha256",
                    "harness_executable_sha256", "harness_inventory_sha256",
                    "harness_adapter_sha256", "harness_binding_sha256"))):
            raise OperationError("session_catalog_invalid")
        if record["harness_generation_id"] == generation_id: count += 1
    return count


def plan_management(operation: str, generation_id: str, reason: str) -> dict:
    if SHA256.fullmatch(generation_id) is None or not 1 <= len(reason.encode("utf-8")) <= 240:
        raise OperationError("management_parameters_invalid")
    reason_sha = hashlib.sha256(reason.encode("utf-8")).hexdigest()
    return control("run", "harness-lifecycle-plan-management",
                   [operation, generation_id, reason_sha, str(session_count(generation_id))])


def submit(operation: str, value: dict, agent: str, session: str) -> dict:
    if operation == "recover":
        parameters = {"recovery":value}; resource = RECOVERY_RESOURCE
    else:
        parameters = {"plan":value}; resource = RESOURCE
    command = [str(BROKER), "request", "--agent", agent, "--session", session,
               "--purpose", f"Apply exact reviewed harness generation {operation} plan",
               "--resource", resource, "--operation", f"harness-generation-{operation}",
               "--parameters-json", canonical(parameters).decode("ascii")]
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False, timeout=240)
    if completed.returncode != 0 or len(completed.stdout) > MAX_JSON:
        raise OperationError("harness_authorization_rejected")
    try:
        result = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OperationError("harness_authorization_response_invalid") from error
    if not isinstance(result, dict) or result.get("schema") != "secure-sandbox-harness-lifecycle-host-result-v1":
        raise OperationError("harness_authorization_response_invalid")
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    commands = value.add_subparsers(dest="command", required=True)
    activate = commands.add_parser("plan-activate"); activate.add_argument("directory", type=Path)
    rollback = commands.add_parser("plan-rollback"); rollback.add_argument("generation_id")
    for name in ("retire", "revoke"):
        item = commands.add_parser(f"plan-{name}"); item.add_argument("generation_id"); item.add_argument("reason")
    commands.add_parser("recovery-status")
    authorize = commands.add_parser("authorize")
    authorize.add_argument("operation", choices=("activate", "rollback", "retire", "revoke", "recover"))
    authorize.add_argument("plan", type=Path); authorize.add_argument("--agent", required=True)
    authorize.add_argument("--session", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if args.command == "plan-activate": result = plan_activate(args.directory)
    elif args.command == "plan-rollback":
        if SHA256.fullmatch(args.generation_id) is None: raise OperationError("generation_id_invalid")
        result = control("run", "harness-lifecycle-prepare-rollback", [args.generation_id])
    elif args.command in {"plan-retire", "plan-revoke"}:
        result = plan_management(args.command.removeprefix("plan-"), args.generation_id, args.reason)
    elif args.command == "recovery-status":
        result = control("run", "harness-lifecycle-recovery-status")
    else:
        raw = trusted_read(args.plan, MAX_JSON)
        try: result = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise OperationError("plan_file_invalid") from error
        result = submit(args.operation, result, args.agent, args.session)
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (OperationError, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, OperationError) else "harness_lifecycle_operation_failed"
        print(json.dumps({"schema":"secure-sandbox-harness-lifecycle-operation-error-v1",
                          "status":"rejected", "error":code}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
