#!/usr/bin/env python3
"""Bounded local model-profile settings reader and inert stager."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))
import model_profiles  # noqa: E402


CATALOG = ROOT / "config/model-profiles.json"
EXAMPLE = ROOT / "config/model-profiles.example.json"
STATUS_SCHEMA = "secure-sandbox-model-profile-catalog-status-v1"


def status() -> dict:
    if CATALOG.exists() or CATALOG.is_symlink():
        value = model_profiles.load_catalog(CATALOG)
        source = "staged"
    else:
        value = model_profiles.load_catalog(EXAMPLE, private=False)
        source = "example"
    payload = model_profiles.canonical_json(value)
    return {
        "catalog": value,
        "catalog_sha256": hashlib.sha256(payload).hexdigest(),
        "profiles": [
            {
                "profile": profile,
                "revision_sha256": model_profiles.profile_revision(profile),
            }
            for profile in value["profiles"]
        ],
        "schema": STATUS_SCHEMA,
        "source": source,
        "status": "verified",
    }


def stage(raw: bytes) -> dict:
    if len(raw) > model_profiles.MAX_CATALOG_BYTES:
        raise model_profiles.ProfileError("model_profile_catalog_oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise model_profiles.ProfileError("model_profile_catalog_json_invalid") from error
    model_profiles.write_catalog(CATALOG, value)
    return status()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("status", "stage"))
    args = parser.parse_args()
    try:
        result = status() if args.operation == "status" else stage(
            sys.stdin.buffer.read(model_profiles.MAX_CATALOG_BYTES + 1)
        )
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as error:
        code = str(error)
        if not code.startswith("model_profile_"):
            code = "model_profile_settings_unavailable"
        print(json.dumps({"error": code, "schema": STATUS_SCHEMA, "status": "rejected"},
                         separators=(",", ":"), sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
