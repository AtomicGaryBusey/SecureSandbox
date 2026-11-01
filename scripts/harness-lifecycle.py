#!/usr/bin/env python3
"""Host CLI for non-executing harness metadata and quarantine lifecycle."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle import HarnessLifecycleError, HarnessStore  # noqa: E402


DEFAULT_POLICY = ROOT / "config/harness-release-policy.json"
DEFAULT_STATE = ROOT / ".private/harness-lifecycle"


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Verify harness release metadata and quarantine exact inert artifacts",
    )
    value.add_argument("--policy", type=Path, default=DEFAULT_POLICY, help=argparse.SUPPRESS)
    value.add_argument("--state-root", type=Path, default=DEFAULT_STATE, help=argparse.SUPPRESS)
    commands = value.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("check")
    commands.add_parser("releases")
    acquire = commands.add_parser("acquire")
    acquire.add_argument("generation_id")
    verify = commands.add_parser("verify")
    verify.add_argument("generation_id")
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    store = HarnessStore(args.state_root, args.policy)
    if args.command == "status":
        result = store.status()
    elif args.command == "check":
        result = store.check()
    elif args.command == "releases":
        result = store.releases()
    elif args.command == "acquire":
        result = store.acquire(args.generation_id)
    elif args.command == "verify":
        result = store.verify(args.generation_id)
    else:  # pragma: no cover - argparse owns the command set
        raise HarnessLifecycleError("command_invalid")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (HarnessLifecycleError, OSError) as error:
        reason = str(error) if isinstance(error, HarnessLifecycleError) else "host_io_failed"
        print(json.dumps({
            "error": reason, "schema": "secure-sandbox-harness-lifecycle-error-v1",
            "status": "rejected",
        }, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
