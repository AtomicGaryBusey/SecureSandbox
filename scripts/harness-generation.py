#!/usr/bin/env python3
"""Read-only operator inspection for the protected harness generation store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve()
REQUIRED_SHARED_MODULES = (
    "harness_generation_store.py",
    "harness_runtime_binding.py",
    "privileged_workflow.py",
)


def complete_shared_directory(path: Path) -> bool:
    return all(
        (path / name).is_file() and not (path / name).is_symlink()
        for name in REQUIRED_SHARED_MODULES
    )


SOURCE_SHARED = SCRIPT.parent.parent / "shared"
INSTALLED_SHARED = SCRIPT.parent / "shared"
if SCRIPT.parent.name == "scripts" and complete_shared_directory(SOURCE_SHARED):
    SHARED = SOURCE_SHARED
elif complete_shared_directory(INSTALLED_SHARED):
    SHARED = INSTALLED_SHARED
else:
    raise SystemExit("harness_generation_dependencies_unavailable")
sys.path.insert(0, str(SHARED))

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
    value.add_argument("command", choices=(
        "status", "verify-boundary", "active-runtime", "generation-runtime",
    ))
    value.add_argument("generation_id", nargs="?")
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    store = GenerationStore(args.release_root, args.state_root)
    if args.command != "generation-runtime" and args.generation_id is not None:
        raise GenerationStoreError("generation_id_not_allowed")
    if args.command == "generation-runtime" and args.generation_id is None:
        raise GenerationStoreError("generation_id_required")
    if args.command == "status":
        result = store.inspect_status()
    else:
        with store.inspection_locked():
            if args.command == "verify-boundary":
                result = store.verify_boundary()
            elif args.command == "active-runtime":
                result = store.runtime_binding()
            else:
                result = store.runtime_binding(args.generation_id)
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
