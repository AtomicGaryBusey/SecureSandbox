#!/usr/bin/env python3
"""Validate all retained snapshots before cold-stack consolidation."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRLCTL = Path("/Applications/Parallels Desktop.app/Contents/MacOS/prlctl")
POLICY = ROOT / "config/snapshot-retention.json"
NAMES = ("SecureSandbox-Gateway", "SecureSandbox-Research", "SecureSandbox-Target")


class SnapshotError(RuntimeError):
    pass


def load_policy() -> dict:
    if not POLICY.is_file() or POLICY.is_symlink() or POLICY.stat().st_size > 16384:
        raise SnapshotError("snapshot_policy_unavailable")
    value = json.loads(POLICY.read_text(encoding="utf-8"))
    if (not isinstance(value, dict)
            or set(value) != {"schema", "maximum_snapshots_per_vm", "minimum_free_gib_for_apply",
                              "virtual_machines", "retain_names"}
            or value["schema"] != "secure-sandbox-snapshot-retention-v1"
            or type(value["maximum_snapshots_per_vm"]) is not int
            or not 1 <= value["maximum_snapshots_per_vm"] <= 40
            or type(value["minimum_free_gib_for_apply"]) is not int
            or not 1 <= value["minimum_free_gib_for_apply"] <= 1000
            or value["virtual_machines"] != list(NAMES)
            or not isinstance(value["retain_names"], list)
            or len(value["retain_names"]) != value["maximum_snapshots_per_vm"]
            or any(not isinstance(name, str) or not name or len(name) > 100
                   for name in value["retain_names"])
            or len(set(value["retain_names"])) != len(value["retain_names"])):
        raise SnapshotError("snapshot_policy_invalid")
    return value


def prlctl(*arguments: str) -> str:
    completed = subprocess.run([str(PRLCTL), *arguments], capture_output=True,
                               check=False, timeout=60)
    if completed.returncode != 0 or len(completed.stdout) > 2 * 1024 * 1024:
        raise SnapshotError("parallels_snapshot_command_failed")
    return completed.stdout.decode("utf-8", "strict")


def vm_states() -> dict[str, str]:
    lines = prlctl("list", "-a", "--no-header", "--output", "status,name").splitlines()
    result: dict[str, str] = {}
    for line in lines:
        fields = line.split(maxsplit=1)
        if len(fields) == 2 and fields[1] in NAMES:
            if fields[1] in result or fields[0] not in {"running", "stopped", "suspended", "paused"}:
                raise SnapshotError("vm_state_ambiguous")
            result[fields[1]] = fields[0]
    if set(result) != set(NAMES):
        raise SnapshotError("vm_state_ambiguous")
    return result


def inventory(vm: str) -> dict:
    if vm not in NAMES:
        raise SnapshotError("vm_name_invalid")
    raw = prlctl("snapshot-list", vm, "-j").strip()
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict) or len(value) > 40:
        raise SnapshotError("snapshot_inventory_invalid")
    for identifier, item in value.items():
        if (not isinstance(identifier, str) or re.fullmatch(r"[A-Za-z0-9{}-]{1,100}", identifier) is None
                or not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or not isinstance(item.get("date"), str) or not isinstance(item.get("current"), bool)):
            raise SnapshotError("snapshot_inventory_invalid")
    return value


def plan(policy: dict, states: dict[str, str], *, apply: bool) -> list[dict]:
    if apply and any(states[name] != "stopped" for name in NAMES):
        raise SnapshotError("all_vms_must_be_stopped")
    retained = set(policy["retain_names"])
    rows = []
    for vm in NAMES:
        snapshots = inventory(vm)
        if any(sum(item["name"] == name for item in snapshots.values()) != 1 for name in retained):
            raise SnapshotError("Retention milestone missing or duplicated")
        current = [item for item in snapshots.values() if item["current"]]
        if len(current) != 1 or current[0]["name"] not in retained:
            raise SnapshotError("Current snapshot is not retained")
        remove = sorted(((identifier, item["date"]) for identifier, item in snapshots.items()
                         if item["name"] not in retained), key=lambda entry: entry[1])
        if len(snapshots) - len(remove) != policy["maximum_snapshots_per_vm"]:
            raise SnapshotError("snapshot_retained_count_invalid")
        rows.append({"vm": vm, "count": len(snapshots), "retain": len(retained),
                     "remove": [identifier for identifier, _ in remove],
                     "retained_ids": {identifier for identifier, item in snapshots.items()
                                      if item["name"] in retained}})
    return rows


def free_bytes() -> int:
    value = os.statvfs("/System/Volumes/Data")
    return value.f_bavail * value.f_frsize


def lifecycle_module():
    spec = importlib.util.spec_from_file_location("snapshot_lifecycle", ROOT / "scripts/parallels-lifecycle.py")
    if spec is None or spec.loader is None:
        raise SnapshotError("lifecycle_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def execute(*, apply: bool) -> list[dict]:
    if not PRLCTL.is_file():
        raise SnapshotError("parallels_cli_unavailable")
    policy = load_policy()
    lock = -1
    try:
        if apply:
            lock = lifecycle_module().ensure_mutation_preconditions("snapshots")
            if free_bytes() < policy["minimum_free_gib_for_apply"] * 1024**3:
                raise SnapshotError("snapshot_free_space_below_policy")
        rows = plan(policy, vm_states(), apply=apply)
        if apply:
            for row in rows:
                for identifier in row["remove"]:
                    prlctl("snapshot-delete", row["vm"], "--id", identifier)
                after = inventory(row["vm"])
                if set(after) != row["retained_ids"] or len(after) != row["retain"]:
                    raise SnapshotError("snapshot_retained_readback_failed")
        return rows
    finally:
        if lock >= 0:
            os.close(lock)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        rows = execute(apply=args.apply)
        for row in rows:
            print(f"{row['vm']}: {row['count']} snapshots; retain {row['retain']}; remove {len(row['remove'])}")
        return 0
    except (SnapshotError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(str(error) if isinstance(error, SnapshotError) else "snapshot_operation_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
