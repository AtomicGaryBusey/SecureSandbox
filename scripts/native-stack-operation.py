#!/usr/bin/env python3
"""Unprivileged content-free native-stack plan and authorization client."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / "shared/native_stack_operations.py").is_file():
    sys.path.insert(0, str(ROOT))

from shared import native_stack_operations as operations
from shared import native_vendor_stack


MAX_JSON = 1024 * 1024
BROKER = Path("/usr/local/libexec/secure-sandbox-host/current/authorization_broker")
RESOURCE = "Native vendor harness and model stack authority"


class NativeStackOperationClientError(RuntimeError):
    pass


def trusted_read(path: Path, maximum: int = MAX_JSON) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not 2 <= before.st_size <= maximum
    ):
        raise NativeStackOperationClientError("native_stack_input_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
        or len(data) != opened.st_size
        or len(data) > maximum
    ):
        raise NativeStackOperationClientError("native_stack_input_changed")
    return bytes(data)


def read_json(path: Path) -> object:
    try:
        return json.loads(trusted_read(path))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackOperationClientError("native_stack_input_invalid") from error


def load_stack(path: Path, stack_id: str) -> dict:
    catalog = native_vendor_stack.validate_catalog(read_json(path))
    for stack in catalog["stacks"]:
        if stack["stack_id"] == stack_id:
            return stack
    raise NativeStackOperationClientError("native_stack_not_found")


def create_plan(
    *,
    catalog: Path,
    status: Path,
    stack_id: str,
    action: str,
    observed_account_subject_sha256: str | None = None,
    observed_workspace_sha256: str | None = None,
    created_at: int | None = None,
) -> dict:
    return operations.make_plan(
        stack=load_stack(catalog, stack_id),
        status=operations.validate_status(read_json(status)),
        action=action,
        observed_account_subject_sha256=observed_account_subject_sha256,
        observed_workspace_sha256=observed_workspace_sha256,
        created_at=created_at,
    )


def authorize(
    plan: object,
    *,
    expected_plan_sha256: str,
    agent: str,
    session: str,
    broker: Path = BROKER,
    runner=subprocess.run,
) -> dict:
    validated = operations.validate_plan(plan)
    if validated["plan_sha256"] != expected_plan_sha256:
        raise NativeStackOperationClientError("native_stack_plan_changed")
    command = [
        str(broker), "request",
        "--agent", agent,
        "--session", session,
        "--purpose", f"Apply exact native stack {validated['action']} plan",
        "--resource", RESOURCE,
        "--operation", f"native-stack-{validated['action']}",
        "--parameters-json",
        operations.canonical_bytes({"plan": validated}).decode("ascii").rstrip("\n"),
    ]
    result = runner(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=(1260 if validated["action"] == "signin-begin" else
                 660 if validated["action"] in {"entitlement-verify", "logout"}
                 else 420),
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
    )
    if result.returncode != 0 or not 2 <= len(result.stdout) <= MAX_JSON:
        raise NativeStackOperationClientError("native_stack_authorization_rejected")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackOperationClientError("native_stack_authorization_response_invalid") from error
    return operations.validate_receipt(value)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser()
    commands = value.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("action", choices=sorted(operations.ACTIONS))
    plan.add_argument("--catalog", type=Path, required=True)
    plan.add_argument("--status", type=Path, required=True)
    plan.add_argument("--stack-id", required=True)
    plan.add_argument("--observed-account-subject-sha256")
    plan.add_argument("--observed-workspace-sha256")
    auth = commands.add_parser("authorize")
    auth.add_argument("plan", type=Path)
    auth.add_argument("--expected-plan-sha256", required=True)
    auth.add_argument("--agent", required=True)
    auth.add_argument("--session", required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    try:
        if args.command == "plan":
            result = create_plan(
                catalog=args.catalog,
                status=args.status,
                stack_id=args.stack_id,
                action=args.action,
                observed_account_subject_sha256=args.observed_account_subject_sha256,
                observed_workspace_sha256=args.observed_workspace_sha256,
            )
        else:
            result = authorize(
                read_json(args.plan), expected_plan_sha256=args.expected_plan_sha256,
                agent=args.agent, session=args.session
            )
        sys.stdout.buffer.write(operations.canonical_bytes(result))
        return 0
    except (
        NativeStackOperationClientError,
        operations.NativeStackOperationError,
        native_vendor_stack.NativeVendorStackError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        code = str(error)
        if not code.startswith("native_stack_"):
            code = "native_stack_operation_failed"
        output = {
            "schema": "secure-sandbox-native-stack-operation-error-v1",
            "status": "rejected",
            "error": code,
        }
        sys.stderr.write(json.dumps(output, separators=(",", ":"), sort_keys=True) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
