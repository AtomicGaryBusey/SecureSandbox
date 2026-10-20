#!/usr/bin/env python3
"""Reject sensitive publication material in the exact Git history being released."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parent.parent
ZERO_UUID = "00000000-0000-0000-0000-000000000000"
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
MAC_HOME = re.compile(r"/Users/[^/\s]+/")
TILDE_HOME = re.compile(r"(?:^|[\s=:'\"])~/SecureSandbox(?:/|\b)")
AGE_RECIPIENT = re.compile(r"\bage1[023456789acdefghjklmnpqrstuvwxyz]{50,}\b")
MAC_ADDRESS = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
UUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b")
LONG_HEX_ID = re.compile(r"(?i)\b(?:[0-9a-f]{40}|[0-9a-f]{64})\b")
DEPLOYMENT_GENERATION = re.compile(r"\b[a-z][a-z0-9-]+-20\d{6}(?:T\d{6}Z(?:-\d+)?)?\b")
OPAQUE_OP_ITEM = re.compile(r"op://[^/]+/[a-z0-9]{20,}/")
LIVE_BLOB_HOST = re.compile(r"(?i)\b(?!REPLACE_)[a-z0-9]{8,}\.blob\.core\.windows\.net\b")
SENSITIVE_JSON_KEY_FORMS = {"subscriptionid", "workspacecustomerid", "tenantid", "clientid"}
ALLOWED_EMAIL_DOMAINS = {"example.com", "example.invalid", "example.test", "users.noreply.github.com"}
ALLOWED_UUIDS = {
    # Public Azure built-in role-definition identifiers.
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1",
    "3913510d-42f4-4e42-8a64-420c390055eb",
    # Conspicuously synthetic test and boundary fixtures.
    "00000000-0000-4000-8000-000000000000",
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "12345678-1234-4123-8123-123456789abc",
    "12345678-1234-4234-8234-123456789abc",
    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
}
FORBIDDEN_ROOTS = {".private", "references", "runs"}
DENYLIST = ROOT / ".private" / "public-deny-patterns.txt"


def git(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, input=input_bytes)


def tracked_files() -> list[Path]:
    return [Path(v.decode()) for v in git("ls-files", "-z").split(b"\0") if v]


def local_deny_patterns() -> list[str]:
    if not DENYLIST.exists():
        return []
    return [line.strip() for line in DENYLIST.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def walk_json(value: object, path: tuple[str, ...] = ()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk_json(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_json(child, path + (str(index),))
    else:
        yield path, value


def inspect_text(path: str, text: str, deny_patterns: list[str]) -> list[str]:
    findings: list[str] = []
    pure = PurePosixPath(path)
    if pure.parts and pure.parts[0] in FORBIDDEN_ROOTS:
        findings.append(f"{path}: private runtime directory must not be tracked")
    if pure.parts[:1] == ("vulnerability-reports",) and path != "vulnerability-reports/README.md":
        findings.append(f"{path}: vulnerability report content must not be tracked")
    example = ".example." in path or path.endswith(".example")
    markdown = pure.suffix.lower() in {".md", ".markdown"}
    for line_number, line in enumerate(text.splitlines(), 1):
        prefix = f"{path}:{line_number}"
        checker_source = path == "scripts/check-public-identifiers.py"
        if not checker_source and MAC_HOME.search(line): findings.append(f"{prefix}: absolute macOS user path")
        if not checker_source and TILDE_HOME.search(line): findings.append(f"{prefix}: user-relative home path")
        if AGE_RECIPIENT.search(line): findings.append(f"{prefix}: live age recipient")
        if OPAQUE_OP_ITEM.search(line): findings.append(f"{prefix}: opaque 1Password item identifier")
        if LIVE_BLOB_HOST.search(line): findings.append(f"{prefix}: live Azure Blob hostname")
        for match in UUID.finditer(line):
            if match.group(0).lower() not in ALLOWED_UUIDS:
                findings.append(f"{prefix}: concrete operational UUID")
        if not checker_source and LONG_HEX_ID.search(line) and markdown:
            findings.append(f"{prefix}: concrete revision or digest in documentation")
        if not checker_source and DEPLOYMENT_GENERATION.search(line) and markdown:
            findings.append(f"{prefix}: concrete deployment generation in documentation")
        for match in MAC_ADDRESS.finditer(line):
            if not (example and match.group(0).lower().startswith("02:00:00:")):
                findings.append(f"{prefix}: literal MAC address")
        for match in EMAIL.finditer(line):
            if match.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
                findings.append(f"{prefix}: non-placeholder email address")
        for pattern in deny_patterns:
            if pattern.casefold() in line.casefold():
                findings.append(f"{prefix}: matches private local deny pattern")
    if pure.suffix.lower() == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            findings.append(f"{path}: invalid JSON is not safe for publication")
            value = None
        for keys, child in walk_json(value):
            key_form = re.sub(r"[^a-z0-9]", "", keys[-1].casefold()) if keys else ""
            if key_form in SENSITIVE_JSON_KEY_FORMS and child not in (ZERO_UUID, "REPLACE", "REPLACE_ME", ""):
                findings.append(f"{path}: deployment-specific value in {'.'.join(keys)}")
    return findings


def inspect_raw(path: str, raw: bytes, deny_patterns: list[str]) -> list[str]:
    if len(raw) > 8 * 1024 * 1024:
        return [f"{path}: blob exceeds the public inspection limit"]
    if b"\0" in raw:
        return [f"{path}: binary or NUL-containing blob requires explicit review"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{path}: non-UTF-8 blob requires explicit review"]
    return inspect_text(path, text, deny_patterns)


def inspect_worktree(deny_patterns: list[str]) -> list[str]:
    findings: list[str] = []
    for relative in tracked_files():
        try:
            raw = (ROOT / relative).read_bytes()
        except OSError as error:
            findings.append(f"{relative.as_posix()}: tracked file is unreadable ({type(error).__name__})")
            continue
        findings.extend(inspect_raw(relative.as_posix(), raw, deny_patterns))
    return findings


def reachable_entries(ref: str):
    for commit in git("rev-list", ref).splitlines():
        for record in git("ls-tree", "-r", "-z", commit.decode("ascii")).split(b"\0"):
            if not record:
                continue
            metadata, path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ")
            yield mode.decode("ascii"), kind.decode("ascii"), object_id.decode("ascii"), path.decode("utf-8", "surrogateescape")


def inspect_history(ref: str, deny_patterns: list[str]) -> list[str]:
    findings: list[str] = []
    for mode, kind, object_id, path in reachable_entries(ref):
        if mode not in {"100644", "100755"} or kind != "blob":
            findings.append(f"{object_id[:12]} {path}: unsupported Git entry mode {mode} type {kind}")
            continue
        size = int(git("cat-file", "-s", object_id))
        if size > 8 * 1024 * 1024:
            findings.append(f"{object_id[:12]} {path}: blob exceeds the public inspection limit")
            continue
        raw = git("cat-file", "blob", object_id)
        findings.extend(f"{object_id[:12]} {item}" for item in inspect_raw(path, raw, deny_patterns))
    records = git("log", ref, "--format=%H%x00%ae%x00%ce").splitlines()
    for record in records:
        commit, author, committer = record.decode().split("\0")
        for role, address in (("author", author), ("committer", committer)):
            match = EMAIL.fullmatch(address)
            if not match or match.group(1).lower() != "users.noreply.github.com":
                findings.append(f"{commit[:12]}: non-noreply {role} email")
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="HEAD", help="exact Git ref whose reachable objects will be published")
    parser.add_argument("--worktree-only", action="store_true")
    args = parser.parse_args()
    deny_patterns = local_deny_patterns()
    findings = inspect_worktree(deny_patterns)
    if not args.worktree_only:
        findings.extend(inspect_history(args.ref, deny_patterns))
    if findings:
        raise SystemExit("\n".join(dict.fromkeys(findings)))
    scope = "tracked worktree" if args.worktree_only else f"tracked worktree and objects reachable from {args.ref}"
    print(f"Public-material check passed for {scope}.")


if __name__ == "__main__":
    main()
