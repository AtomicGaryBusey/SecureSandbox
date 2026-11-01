#!/usr/bin/env python3
"""Operator CLI for disposable-Mac harness lifecycle acceptance evidence."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    assemble_export,
    CAMPAIGN_SCHEMA,
    CASES,
    MAX_CAMPAIGN_SECONDS,
    canonical,
    case_record,
    digest,
    suite_sha256,
    validate_campaign,
    validate_enrollment,
    verdict,
    SUITE_ID,
)


MAX_JSON = 4 * 1024 * 1024


def trusted_json(path: Path, maximum: int = MAX_JSON) -> dict:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != os.geteuid() or before.st_nlink != 1
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 0 < before.st_size <= maximum):
        raise AcceptanceError("input_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > maximum):
        raise AcceptanceError("input_file_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("input_json_invalid") from error
    if not isinstance(value, dict) or canonical(value) != bytes(data):
        raise AcceptanceError("input_json_noncanonical")
    return value


def write_new(path: Path, value: dict) -> None:
    payload = canonical(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AcceptanceError("output_write_failed")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def trusted_observations(path: Path) -> list[dict]:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise AcceptanceError("observation_directory_untrusted")
    expected = {
        f"{case.case_id}.{kind}.json"
        for case in CASES for kind in case.evidence_kinds
    }
    entries = {item.name: item for item in path.iterdir()}
    if set(entries) != expected:
        raise AcceptanceError("observation_file_inventory_invalid")
    return [
        trusted_json(entries[f"{case.case_id}.{kind}.json"], 64 * 1024)
        for case in CASES for kind in case.evidence_kinds
    ]


def initialize(enrollment_path: Path, source_commit: str, output: Path,
               now: int, lifetime: int) -> dict:
    enrollment = validate_enrollment(trusted_json(enrollment_path, 64 * 1024), now)
    if len(source_commit) != 40 or any(character not in "0123456789abcdef" for character in source_commit):
        raise AcceptanceError("source_commit_invalid")
    if not 3600 <= lifetime <= MAX_CAMPAIGN_SECONDS:
        raise AcceptanceError("campaign_lifetime_invalid")
    value = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": str(uuid.uuid4()),
        "suite_id": SUITE_ID,
        "suite_sha256": suite_sha256(),
        "machine_identity_sha256": enrollment["machine_identity_sha256"],
        "source_commit": source_commit,
        "created_at": now,
        "expires_at": now + lifetime,
        "environment": "disposable-mac",
        "production_data_present": False,
        "production_credentials_present": False,
        "synthetic_credentials_only": True,
        "authority": "acceptance-evidence-only",
    }
    value["campaign_sha256"] = digest(value)
    validate_campaign(value, now)
    write_new(output, value)
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Verify disposable-Mac harness lifecycle acceptance")
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("catalog")
    initialize_command = commands.add_parser("initialize")
    initialize_command.add_argument("--enrollment", type=Path, required=True)
    initialize_command.add_argument("--source-commit", required=True)
    initialize_command.add_argument("--output", type=Path, required=True)
    initialize_command.add_argument("--lifetime-seconds", type=int, default=7 * 86400)
    campaign = commands.add_parser("verify-campaign")
    campaign.add_argument("path", type=Path)
    export = commands.add_parser("verify-export")
    export.add_argument("path", type=Path)
    assemble = commands.add_parser("assemble")
    assemble.add_argument("--campaign", type=Path, required=True)
    assemble.add_argument("--observations", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    now = int(time.time())
    if args.command == "catalog":
        result = {
            "schema": "secure-sandbox-harness-lifecycle-acceptance-catalog-v1",
            "suite_id": SUITE_ID,
            "suite_sha256": suite_sha256(),
            "case_count": len(CASES),
            "cases": [case_record(case) for case in CASES],
            "authority": "none",
        }
    elif args.command == "initialize":
        result = initialize(args.enrollment, args.source_commit, args.output, now,
                            args.lifetime_seconds)
    elif args.command == "verify-campaign":
        result = validate_campaign(trusted_json(args.path), now)
    elif args.command == "verify-export":
        result = verdict(trusted_json(args.path), now)
    else:
        campaign = validate_campaign(trusted_json(args.campaign), now)
        result = assemble_export(campaign, trusted_observations(args.observations), now)
        write_new(args.output, result)
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, AcceptanceError) else "acceptance_io_failed"
        print(json.dumps({
            "schema": "secure-sandbox-harness-lifecycle-acceptance-error-v1",
            "status": "rejected",
            "error": reason,
        }, ensure_ascii=True, separators=(",", ":"), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
