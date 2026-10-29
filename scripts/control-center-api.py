#!/usr/bin/env python3
"""Bounded, read-only, versioned host catalog for the Control Center app."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
LABCTL = ROOT / "scripts" / "labctl"
SCHEMA = "secure-sandbox-control-center-v1"
MAX_OUTPUT = 8 * 1024 * 1024
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def run_labctl(*args: str) -> str:
    # No shell. Callers validate every variable argument before this boundary.
    completed = subprocess.run(
        [str(LABCTL), *args],
        cwd=ROOT,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if len(completed.stdout) > MAX_OUTPUT or len(completed.stderr) > 4096:
        raise ValueError("catalog response exceeds its size limit")
    if completed.returncode:
        raise RuntimeError(
            completed.stderr.decode("utf-8", "replace").strip()[:500]
            or f"host operation failed with status {completed.returncode}"
        )
    return completed.stdout.decode("utf-8", "strict")


def table(raw: str, width: int, header: str | None = None) -> list[list[str]]:
    lines = raw.splitlines()
    if header is not None:
        if not lines or lines.pop(0) != header:
            raise ValueError("catalog header is invalid")
    rows = [line.split("\t") for line in lines]
    if any(len(row) != width for row in rows) or len(rows) > 10_000:
        raise ValueError("catalog row is invalid")
    return rows


def catalog(name: str) -> list[dict] | dict:
    raw = run_labctl({"overview": "status", "sessions": "sessions", "sources": "sources", "findings": "findings"}[name])
    if name == "overview":
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-host-lifecycle-v1":
            raise ValueError("host status schema is invalid")
        observed = value.get("observed")
        if not isinstance(observed, dict) or any(observed.get(vm) not in ("running", "stopped", "paused", "suspended") for vm in ("gateway", "research", "target")):
            raise ValueError("VM status is invalid")
        if value.get("status") not in ("verified", "degraded", "failed"):
            raise ValueError("host status is invalid")
        return value
    if name == "sessions":
        rows = table(raw, 7, "SESSION\tCREATED_UTC\tLAST_UTC\tTURNS\tCOMPACTS\tRUNS\tLABEL")
        if any(UUID.fullmatch(row[0]) is None for row in rows):
            raise ValueError("session ID is invalid")
        return [dict(zip(("id", "created_at", "last_at", "turns", "compacts", "runs", "label"), row)) for row in rows]
    if name == "sources":
        rows = table(raw, 5)
        if any(UUID.fullmatch(row[1]) is None or SHA.fullmatch(row[3]) is None for row in rows):
            raise ValueError("source identity is invalid")
        return [dict(zip(("imported_at", "id", "repository", "commit", "worktree"), row)) for row in rows]
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) > 10_000 or any(not isinstance(row, dict) or UUID.fullmatch(str(row.get("finding_id", ""))) is None for row in value):
        raise ValueError("findings catalog is invalid")
    return value


def normalize_github_url(raw: str) -> str:
    if len(raw) > 500 or raw != raw.strip():
        raise ValueError("Paste a plain GitHub repository URL")
    parsed = urlsplit(raw)
    if (parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query
            or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("Only plain https://github.com/owner/repository URLs are supported")
    segments = parsed.path.split("/")
    if len(segments) != 3 or not all(segments[1:]):
        raise ValueError("The URL must name one GitHub repository")
    slug = "/".join(segments[1:])
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9][A-Za-z0-9._-]{0,98}", slug) is None or slug.endswith(".git"):
        raise ValueError("The GitHub repository name is unsupported")
    return slug


def plan_source(url: str, ref: str) -> dict[str, str]:
    slug = normalize_github_url(url)
    if (re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", ref) is None
            or ref.startswith(".") or ref.endswith(("/", ".")) or ".." in ref
            or "//" in ref or "@{" in ref):
        raise ValueError("The Git ref is unsupported")
    raw = run_labctl("source", "plan", slug, ref)
    lines = [line.split(":", 1) for line in raw.splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("Source plan response is invalid")
    fields = {key.strip(): value.strip() for key, value in lines}
    if (set(fields) != {"Plan", "Repository", "Requested", "Commit", "Expires"}
            or UUID.fullmatch(fields["Plan"]) is None
            or fields["Repository"] != slug or fields["Requested"] != ref
            or SHA.fullmatch(fields["Commit"]) is None):
        raise ValueError("Source plan identity is invalid")
    return {"plan_id": fields["Plan"], "repository": slug, "requested_ref": ref,
            "resolved_commit": fields["Commit"], "expires_at": fields["Expires"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    catalog_parser = subparsers.add_parser("catalog")
    catalog_parser.add_argument("name", choices=("overview", "sessions", "sources", "findings"))
    plan_parser = subparsers.add_parser("plan-source")
    plan_parser.add_argument("url")
    plan_parser.add_argument("ref")
    args = parser.parse_args()
    name = args.name if args.action == "catalog" else "source-plan"
    try:
        data = catalog(name) if args.action == "catalog" else plan_source(args.url, args.ref)
        payload = {"schema": SCHEMA, "catalog": name, "data": data}
        print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"schema": SCHEMA, "catalog": name, "error": str(error)[:500]}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
