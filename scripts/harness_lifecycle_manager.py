#!/usr/bin/env python3
"""Protected Host consumer for exact Touch ID-authorized harness plans."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Callable


PLAN_WRAPPER_SCHEMA = "secure-sandbox-harness-consumer-plan-v1"
ACTIVATION_PLAN_SCHEMA = "secure-sandbox-harness-activation-plan-v1"
MANAGEMENT_PLAN_SCHEMA = "secure-sandbox-harness-management-plan-v1"
AUTHORIZATION_SCHEMA = "secure-sandbox-harness-touchid-authorization-v1"
APPLY_SCHEMA = "secure-sandbox-harness-consumer-apply-v1"
RECOVERY_SCHEMA = "secure-sandbox-harness-consumer-recovery-v1"
RESULT_SCHEMA = "secure-sandbox-harness-lifecycle-host-result-v1"
CATALOG_SCHEMA = "secure-sandbox-session-runs-v4"
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
SESSION_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
MAX_JSON = 1024 * 1024


class ManagerError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")


def self_digest(value: dict, field: str, label: str) -> None:
    supplied = value.get(field)
    unsigned = {name: item for name, item in value.items() if name != field}
    if (not isinstance(supplied, str) or SHA256.fullmatch(supplied) is None
            or hashlib.sha256(canonical(unsigned)).hexdigest() != supplied):
        raise ManagerError(f"{label}_digest_invalid")


def parse_exact(raw: str, maximum: int = MAX_JSON) -> dict:
    if not 0 < len(raw.encode("utf-8")) <= maximum:
        raise ManagerError("input_size_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManagerError("input_json_invalid") from error
    if not isinstance(value, dict):
        raise ManagerError("input_json_invalid")
    return value


def validate_wrapper(value: dict, expected_operation: str) -> dict:
    if set(value) != {"schema", "stage_id", "plan", "reference", "wrapper_sha256"}:
        raise ManagerError("plan_wrapper_fields_invalid")
    if (value["schema"] != PLAN_WRAPPER_SCHEMA
            or not isinstance(value["stage_id"], str)
            or UUID4.fullmatch(value["stage_id"]) is None
            or not isinstance(value["plan"], dict)):
        raise ManagerError("plan_wrapper_invalid")
    self_digest(value, "wrapper_sha256", "plan_wrapper")
    plan = value["plan"]
    if plan.get("operation") != expected_operation:
        raise ManagerError("plan_operation_mismatch")
    if expected_operation in {"activate", "rollback"}:
        if plan.get("schema") != ACTIVATION_PLAN_SCHEMA or value["reference"] is not None:
            raise ManagerError("activation_plan_invalid")
    else:
        if (plan.get("schema") != MANAGEMENT_PLAN_SCHEMA
                or not isinstance(value["reference"], dict)):
            raise ManagerError("management_plan_invalid")
    self_digest(plan, "plan_sha256", "plan")
    return plan


def validate_authorization(value: dict, plan: dict) -> None:
    fields = {"schema", "authorization_id", "plan_id", "plan_sha256", "transaction_id",
              "operation", "method", "password_fallback", "authorized_at", "expires_at",
              "requesting_agent_sha256", "requesting_session_sha256", "authorization_sha256"}
    if set(value) != fields or value.get("schema") != AUTHORIZATION_SCHEMA:
        raise ManagerError("authorization_fields_invalid")
    self_digest(value, "authorization_sha256", "authorization")
    if (value.get("method") != "touch-id" or value.get("password_fallback") is not False
            or value.get("plan_id") != plan.get("plan_id")
            or value.get("plan_sha256") != plan.get("plan_sha256")
            or value.get("transaction_id") != plan.get("transaction_id")
            or value.get("operation") != plan.get("operation")):
        raise ManagerError("authorization_binding_invalid")


def session_catalog(operator_uid: int) -> Path:
    home = Path(pwd.getpwuid(operator_uid).pw_dir)
    return home / "Library/Application Support/SecureSandbox/controller-state/session-runs.json"


def resumable_count(generation_id: str, operator_uid: int,
                    catalog_path: Path | None = None) -> int:
    if SHA256.fullmatch(generation_id) is None:
        raise ManagerError("generation_id_invalid")
    path = catalog_path or session_catalog(operator_uid)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return 0
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != operator_uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= MAX_JSON):
        raise ManagerError("session_catalog_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= MAX_JSON:
            chunk = os.read(descriptor, min(65536, MAX_JSON + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > MAX_JSON):
        raise ManagerError("session_catalog_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManagerError("session_catalog_invalid") from error
    sessions = value.get("sessions") if isinstance(value, dict) else None
    if value.get("schema") != CATALOG_SCHEMA or not isinstance(sessions, dict) or len(sessions) > 10_000:
        raise ManagerError("session_catalog_invalid")
    count = 0
    required = {"last_started_at", "runs", "run_ids", "adapter", "model",
                "model_profile_id", "model_profile_sha256", "vendor_id", "harness_id",
                "harness_generation_id", "harness_manifest_sha256",
                "harness_executable_sha256", "harness_inventory_sha256",
                "harness_adapter_id", "harness_adapter_sha256", "harness_binding_sha256"}
    for session_id, record in sessions.items():
        if (not isinstance(session_id, str) or SESSION_UUID.fullmatch(session_id) is None
                or not isinstance(record, dict) or set(record) != required
                or not isinstance(record.get("runs"), int) or isinstance(record["runs"], bool)
                or not 1 <= record["runs"] <= 1_000_000
                or not isinstance(record.get("run_ids"), list)
                or len(record["run_ids"]) > min(record["runs"], 1000)
                or any(SHA256.fullmatch(str(record.get(name, ""))) is None for name in (
                    "model_profile_sha256", "harness_generation_id", "harness_manifest_sha256",
                    "harness_executable_sha256", "harness_inventory_sha256",
                    "harness_adapter_sha256", "harness_binding_sha256"))):
            raise ManagerError("session_catalog_invalid")
        if record["harness_generation_id"] == generation_id:
            count += 1
    return count


class HarnessLifecycleManager:
    def __init__(self, release: Path | None = None,
                 runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run) -> None:
        self.release = release or Path(__file__).resolve().parent
        self.client = self.release / "control_client"
        self.ssh_config = self.release / "ssh_config"
        self.runner = runner

    def control(self, kind: str, operation: str, arguments: list[str] | None = None,
                payload: bytes | None = None, timeout: int = 180) -> dict:
        command = [str(self.client), "client", "--ssh-config", str(self.ssh_config),
                   "--timeout-seconds", str(timeout), "sandbox-research-control", kind,
                   operation, *(arguments or [])]
        result = self.runner(
            command, input=payload, stdin=subprocess.DEVNULL if payload is None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=timeout + 10,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        if result.returncode != 0 or len(result.stdout) > MAX_JSON or len(result.stderr) > MAX_JSON:
            raise ManagerError("research_lifecycle_operation_failed")
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ManagerError("research_lifecycle_response_invalid") from error
        if not isinstance(value, dict):
            raise ManagerError("research_lifecycle_response_invalid")
        return value

    def apply(self, operation: str, wrapper: dict, authorization: dict,
              operator_uid: int) -> dict:
        plan = validate_wrapper(wrapper, operation)
        validate_authorization(authorization, plan)
        count = 0
        if operation in {"retire", "revoke"}:
            count = resumable_count(plan["generation_id"], operator_uid)
        request = {"schema": APPLY_SCHEMA, "stage_id": wrapper["stage_id"], "plan": plan,
                   "authorization": authorization, "resumable_session_count": count}
        result = self.control("pipe", "harness-lifecycle-apply", payload=canonical(request))
        status = self.control("run", "harness-generation-status")
        boundary = self.control("run", "harness-generation-verify-boundary")
        if (status.get("schema") != "secure-sandbox-harness-generation-status-v1"
                or status.get("status") != "verified"
                or boundary.get("schema") != "secure-sandbox-harness-generation-boundary-v1"
                or boundary.get("status") != "verified"):
            raise ManagerError("research_lifecycle_postcondition_invalid")
        return {"schema": RESULT_SCHEMA, "operation": operation, "result": result,
                "status": status, "boundary": boundary}

    def recover(self, recovery: dict) -> dict:
        if set(recovery) != {"schema", "pending", "journal_sha256"}:
            raise ManagerError("recovery_fields_invalid")
        digest = recovery.get("journal_sha256")
        if recovery.get("schema") != RECOVERY_SCHEMA or recovery.get("pending") is not True \
                or not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise ManagerError("recovery_state_invalid")
        current = self.control("run", "harness-lifecycle-recovery-status")
        if current != recovery:
            raise ManagerError("recovery_state_changed")
        result = self.control("run", "harness-lifecycle-recover", [digest])
        status = self.control("run", "harness-generation-status")
        boundary = self.control("run", "harness-generation-verify-boundary")
        if (status.get("schema") != "secure-sandbox-harness-generation-status-v1"
                or status.get("status") != "verified"
                or boundary.get("schema") != "secure-sandbox-harness-generation-boundary-v1"
                or boundary.get("status") != "verified"):
            raise ManagerError("research_lifecycle_postcondition_invalid")
        return {"schema": RESULT_SCHEMA, "operation": "recover", "result": result,
                "status": status, "boundary": boundary}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    commands = value.add_subparsers(dest="command", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("operation", choices=("activate", "rollback", "retire", "revoke"))
    apply.add_argument("--wrapper-json", required=True)
    apply.add_argument("--authorization-json", required=True)
    apply.add_argument("--operator-uid", required=True, type=int)
    recover = commands.add_parser("recover")
    recover.add_argument("--recovery-json", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    manager = HarnessLifecycleManager()
    if args.command == "apply":
        if args.operator_uid <= 0:
            raise ManagerError("operator_uid_invalid")
        result = manager.apply(args.operation, parse_exact(args.wrapper_json),
                               parse_exact(args.authorization_json), args.operator_uid)
    else:
        result = manager.recover(parse_exact(args.recovery_json))
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ManagerError, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, ManagerError) else "harness_lifecycle_manager_failed"
        print(json.dumps({"schema": "secure-sandbox-harness-lifecycle-host-error-v1",
                          "status": "rejected", "error": code}, separators=(",", ":"),
                         sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
