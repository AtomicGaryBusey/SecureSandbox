#!/usr/bin/env python3
"""Root-owned one-time plan controller for brokered source acquisition."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import time
import uuid

ROOT = "/var/lib/secure-sandbox/source-acquisition"
PLANS = f"{ROOT}/plans"
SPOOL = f"{ROOT}/spool"
LOCK = f"{ROOT}/controller.lock"
CONFIG = "/etc/secure-sandbox/source-acquisition.json"
FETCHER = "/usr/local/libexec/secure-sandbox/source_fetcher.py"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def log_event(event: str, value: dict, error: str = "") -> None:
    record = {
        "event": event,
        "plan_id": str(value.get("plan_id", "")),
        "repository_sha256": hashlib.sha256(str(value.get("repository", "")).encode()).hexdigest(),
        "resolved_commit": str(value.get("resolved_commit", "")),
        "archive_bytes": int(value.get("archive_bytes", 0)),
        "error": error,
    }
    subprocess.run(["/usr/bin/logger", "--tag", "secure-sandbox-source", canonical(record).decode()], check=False)


def atomic_json(path: str, value: object, mode: int = 0o640) -> None:
    temporary = path + ".new"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        os.write(descriptor, canonical(value) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_fetcher(arguments: list[str]) -> dict:
    command = [
        "/usr/bin/systemd-run", "--pipe", "--wait", "--collect", "--quiet",
        "--uid=source-fetcher", "--gid=source-fetcher",
        "--property=NoNewPrivileges=yes", "--property=PrivateDevices=yes",
        "--property=PrivateTmp=yes", "--property=ProtectHome=yes",
        "--property=ProtectSystem=strict", "--property=RestrictNamespaces=yes",
        "--property=RestrictRealtime=yes", "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes", "--property=MemoryDenyWriteExecute=yes",
        "--property=RestrictAddressFamilies=AF_INET AF_UNIX",
        "--property=RestrictNetworkInterfaces=uplink0 lo",
        "--property=ReadOnlyPaths=/etc/secure-sandbox/source-acquisition.json",
        f"--property=ReadWritePaths={SPOOL}",
        "--property=MemoryMax=384M", "--property=TasksMax=16",
        FETCHER, "--config", CONFIG, *arguments,
    ]
    result = subprocess.run(command, capture_output=True, check=False, timeout=330, env={"PATH": "/usr/sbin:/usr/bin"})
    if result.returncode != 0:
        # The isolated fetcher may include paths or endpoint details in a
        # traceback. Forward only its final stable error token.
        tail = result.stderr.decode("utf-8", "replace").splitlines()[-1:]
        match = re.fullmatch(r"(?:RuntimeError|ValueError): ([a-z0-9_]{1,80})", tail[0]) if tail else None
        raise RuntimeError(match.group(1) if match else "fetcher_failed")
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid_fetcher_output") from error
    if not isinstance(value, dict):
        raise RuntimeError("invalid_fetcher_output")
    return value


def plan_path(plan_id: str) -> str:
    if not UUID_RE.fullmatch(plan_id):
        raise ValueError("invalid_plan_id")
    return f"{PLANS}/{plan_id}.json"


def load_plan(plan_id: str) -> dict:
    with open(plan_path(plan_id), encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict) or value.get("plan_id") != plan_id:
        raise ValueError("invalid_plan")
    return value


def create_plan(repository: str, requested_ref: str, npm: bool = False) -> dict:
    resolved = run_fetcher(["resolve-npm" if npm else "resolve", repository, requested_ref])
    plan_id = str(uuid.uuid4())
    now = int(time.time())
    value = {
        "schema": "secure-sandbox-source-plan-v1",
        "plan_id": plan_id,
        "repository": resolved["repository"],
        "requested_ref": resolved["requested_ref"],
        "resolved_commit": resolved["resolved_commit"],
        "visibility": resolved["visibility"],
        "archive_endpoint_class": resolved["archive_endpoint_class"],
        "created_unix": now,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "expires_unix": now + 900,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + 900)),
        "policy_version": "source-acquisition-v1",
        "state": "planned",
    }
    for key in ("source_kind", "package_name", "package_version", "npm_integrity", "npm_tarball_path"):
        if key in resolved:
            value[key] = resolved[key]
    atomic_json(plan_path(plan_id), value)
    log_event("source_plan_created", value)
    print(json.dumps({key: value[key] for key in ("plan_id", "repository", "requested_ref", "resolved_commit", "expires_at")}, separators=(",", ":"), sort_keys=True))
    return value


def apply_plan(plan_id: str) -> dict:
    with open(LOCK, "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = load_plan(plan_id)
        if value.get("state") != "planned":
            raise ValueError("plan_not_available")
        if int(value.get("expires_unix", 0)) < int(time.time()):
            value["state"] = "expired"
            atomic_json(plan_path(plan_id), value)
            raise ValueError("plan_expired")
        value["state"] = "claimed"
        value["claimed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        atomic_json(plan_path(plan_id), value)
        log_event("source_fetch_started", value)
        archive = f"{SPOOL}/{plan_id}.tar.gz"
        try:
            fetched = run_fetcher(["fetch", plan_path(plan_id), archive])
            value.update(fetched)
            value["state"] = "fetched"
            value["fetched_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            atomic_json(plan_path(plan_id), value)
            log_event("source_fetch_completed", value)
        except Exception:
            value["state"] = "failed"
            value["error_class"] = "fetch_failed"
            atomic_json(plan_path(plan_id), value)
            log_event("source_fetch_failed", value, "fetch_failed")
            raise
    output = {key: value[key] for key in ("plan_id", "repository", "resolved_commit", "archive_sha256", "archive_bytes", "state")}
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return value


def export_plan(plan_id: str) -> None:
    with open(LOCK, "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = load_plan(plan_id)
        if value.get("state") != "fetched":
            raise ValueError("plan_not_exportable")
        archive = f"{SPOOL}/{plan_id}.tar.gz"
        info = os.lstat(archive)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != int(value["archive_bytes"]):
            raise ValueError("invalid_archive_spool")
        with open(archive, "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        if digest != value["archive_sha256"]:
            raise ValueError("archive_hash_mismatch")
        value["state"] = "exported"
        value["exported_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        atomic_json(plan_path(plan_id), value)
    manifest = canonical(value)
    sys.stdout.buffer.write(struct.pack(">Q", len(manifest)))
    sys.stdout.buffer.write(manifest)
    with open(archive, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            sys.stdout.buffer.write(chunk)
    sys.stdout.buffer.flush()


def complete(plan_id: str, source_id: str) -> None:
    if not UUID_RE.fullmatch(source_id):
        raise ValueError("invalid_source_id")
    value = load_plan(plan_id)
    if value.get("state") != "exported":
        raise ValueError("plan_not_exported")
    value["state"] = "completed"
    value["source_id"] = source_id
    value["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    atomic_json(plan_path(plan_id), value)
    log_event("source_acquisition_completed", value)
    try:
        os.unlink(f"{SPOOL}/{plan_id}.tar.gz")
    except FileNotFoundError:
        pass
    print(json.dumps({"plan_id": plan_id, "source_id": source_id, "state": "completed"}, separators=(",", ":"), sort_keys=True))


def status_plan(plan_id: str) -> None:
    value = load_plan(plan_id)
    if value.get("schema") != "secure-sandbox-source-plan-v1":
        raise ValueError("invalid_plan")
    fields = {key: value[key] for key in
              ("plan_id", "repository", "requested_ref", "resolved_commit", "expires_at", "state")}
    if fields["state"] == "planned" and int(value.get("expires_unix", 0)) < int(time.time()):
        fields["state"] = "expired"
    if value.get("state") == "completed":
        fields["source_id"] = value["source_id"]
    fields["schema"] = "secure-sandbox-source-plan-status-v1"
    print(json.dumps(fields, separators=(",", ":"), sort_keys=True))


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("root required")
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    creator = subparsers.add_parser("plan")
    creator.add_argument("repository")
    creator.add_argument("requested_ref")
    npm_creator = subparsers.add_parser("plan-npm")
    npm_creator.add_argument("package")
    npm_creator.add_argument("version")
    applier = subparsers.add_parser("apply")
    applier.add_argument("plan_id")
    exporter = subparsers.add_parser("export")
    exporter.add_argument("plan_id")
    completer = subparsers.add_parser("complete")
    completer.add_argument("plan_id")
    completer.add_argument("source_id")
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("plan_id")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            create_plan(args.repository, args.requested_ref)
        elif args.command == "plan-npm":
            create_plan(args.package, args.version, npm=True)
        elif args.command == "apply":
            apply_plan(args.plan_id)
        elif args.command == "export":
            export_plan(args.plan_id)
        elif args.command == "status":
            status_plan(args.plan_id)
        else:
            complete(args.plan_id, args.source_id)
    except Exception as error:
        detail = str(error)
        error_class = detail if re.fullmatch(r"[a-z0-9_]{1,80}", detail) else type(error).__name__
        print(json.dumps({"event": "source_controller_rejected", "error": error_class}, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
