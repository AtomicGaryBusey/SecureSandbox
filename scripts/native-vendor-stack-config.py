#!/usr/bin/env python3
"""Bounded native-vendor stack settings reader and inert stager."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared import native_vendor_stack as stacks  # noqa: E402


CATALOG = ROOT / "config/native-vendor-stacks.json"
EXAMPLE = ROOT / "config/native-vendor-stacks.example.json"
STATUS_SCHEMA = "secure-sandbox-native-vendor-stack-catalog-status-v1"


def status(
    catalog_path: Path = CATALOG,
    example_path: Path = EXAMPLE,
) -> dict[str, object]:
    if catalog_path.exists() or catalog_path.is_symlink():
        catalog = stacks.load_catalog(catalog_path)
        source = "staged"
    else:
        catalog = stacks.load_catalog(example_path, private=False)
        source = "example"
    payload = stacks.canonical_bytes(catalog)
    return {
        "catalog": catalog,
        "catalog_sha256": hashlib.sha256(payload).hexdigest(),
        "schema": STATUS_SCHEMA,
        "source": source,
        "stacks": [
            {
                "readiness": stacks.activation_readiness(item),
                "revision_sha256": stacks.stack_revision(item),
                "stack": item,
            }
            for item in catalog["stacks"]
        ],
        "status": "verified",
    }


def stage(
    raw: bytes,
    catalog_path: Path = CATALOG,
    example_path: Path = EXAMPLE,
) -> dict[str, object]:
    if len(raw) > stacks.MAX_CATALOG_BYTES:
        raise stacks.NativeVendorStackError("native_stack_catalog_oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise stacks.NativeVendorStackError("native_stack_catalog_json_invalid") from error
    stacks.write_catalog(catalog_path, value)
    return status(catalog_path, example_path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("status", "stage"))
    arguments = parser.parse_args()
    try:
        result = status() if arguments.operation == "status" else stage(
            sys.stdin.buffer.read(stacks.MAX_CATALOG_BYTES + 1)
        )
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        code = str(error)
        if not code.startswith("native_stack_"):
            code = "native_stack_settings_unavailable"
        print(
            json.dumps(
                {"error": code, "schema": STATUS_SCHEMA, "status": "rejected"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
