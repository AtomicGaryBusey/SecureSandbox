#!/usr/bin/env python3
"""Read-only operator inspection for the protected harness generation store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_generation_store import GenerationStore, GenerationStoreError  # noqa: E402


DEFAULT_RELEASE_ROOT = Path("/usr/local/libexec/secure-sandbox-harnesses")
DEFAULT_STATE_ROOT = Path("/var/lib/secure-sandbox/harnesses")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Inspect the protected harness generation catalog and boundary",
    )
    value.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT,
                       help=argparse.SUPPRESS)
    value.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT,
                       help=argparse.SUPPRESS)
    value.add_argument("command", choices=("status", "verify-boundary"))
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    store = GenerationStore(args.release_root, args.state_root)
    if args.command == "status":
        result = store.inspect_status()
    else:
        with store.inspection_locked():
            result = store.verify_boundary()
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (GenerationStoreError, OSError) as error:
        reason = str(error) if isinstance(error, GenerationStoreError) else "protected_store_io_failed"
        print(json.dumps({"schema": "secure-sandbox-harness-generation-error-v1",
                          "status": "rejected", "error": reason},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
