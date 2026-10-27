#!/usr/bin/env python3
"""Reject sensitive publication material in the exact Git history being released."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
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
APPLE_TEAM_ASSIGNMENT = re.compile(
    r"(?i)(?:DEVELOPMENT_TEAM|DevelopmentTeam|TeamIdentifier|team-identifier|subject\.OU)"
    r"[^A-Za-z0-9\n]{0,40}[\"']?([A-Z0-9]{10})(?:[\"';,\]\s]|$)"
)
APPLE_ACCESS_GROUP = re.compile(
    r"\b[A-Z0-9]{10}\.[a-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+){1,}\b"
)
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
    "abcdefab-cdef-4abc-8def-abcdefabcdef",
    "fedcbafe-dcba-4fed-8cba-fedcbafedcba",
}
FORBIDDEN_ROOTS = {".private", "references", "reports", "runs"}
FORBIDDEN_GENERATED_PATHS = {
    "artifacts/host/SecureSandboxAuthorizationUI",
    "artifacts/host/SecureSandboxAuthorizationUI.bundle.json",
    "artifacts/host/SecureSandboxAuthorizationUI.sources.json",
    "macos/TouchIDAuthorization/Signing.local.xcconfig",
}
FORBIDDEN_GENERATED_PREFIXES = (
    "artifacts/host/SecureSandboxAuthorizationUI.app/",
)
DENYLIST = ROOT / ".private" / "public-deny-patterns.txt"


def git(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, input=input_bytes)


def worktree_files() -> list[Path]:
    return [
        Path(value.decode())
        for value in git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")
        if value
    ]


def synthetic_uuid(value: str) -> bool:
    compact = value.lower().replace("-", "")
    ordinary = compact[:12] + compact[13:16] + compact[17:]
    if re.fullmatch(r"0{29}[0-9a-f]", ordinary):
        return True
    return len(ordinary) == 30 and len(set(ordinary)) == 1


def inspect_path(path: str) -> list[str]:
    pure = PurePosixPath(path)
    findings: list[str] = []
    if pure.parts and pure.parts[0] in FORBIDDEN_ROOTS:
        findings.append(f"{path}: private runtime directory must not be tracked")
    if pure.parts[:1] == ("vulnerability-reports",) and path != "vulnerability-reports/README.md":
        findings.append(f"{path}: vulnerability report content must not be tracked")
    if (path in FORBIDDEN_GENERATED_PATHS
            or path.endswith("/embedded.provisionprofile")
            or any(path.startswith(prefix) for prefix in FORBIDDEN_GENERATED_PREFIXES)):
        findings.append(f"{path}: generated signed authorization artifact must not be tracked")
    return findings


def inspect_identifier_value(label: str, value: str,
                             deny_patterns: list[str]) -> list[str]:
    findings: list[str] = []
    if MAC_HOME.search(value): findings.append(f"{label}: absolute macOS user path")
    if TILDE_HOME.search(value): findings.append(f"{label}: user-relative home path")
    if AGE_RECIPIENT.search(value): findings.append(f"{label}: live age recipient")
    if OPAQUE_OP_ITEM.search(value): findings.append(f"{label}: opaque 1Password item identifier")
    if LIVE_BLOB_HOST.search(value): findings.append(f"{label}: live Azure Blob hostname")
    for match in UUID.finditer(value):
        identifier = match.group(0).lower()
        if identifier not in ALLOWED_UUIDS and not synthetic_uuid(identifier):
            findings.append(f"{label}: concrete operational UUID")
    if LONG_HEX_ID.search(value): findings.append(f"{label}: concrete revision or digest")
    if DEPLOYMENT_GENERATION.search(value): findings.append(f"{label}: concrete deployment generation")
    if MAC_ADDRESS.search(value): findings.append(f"{label}: literal MAC address")
    for match in EMAIL.finditer(value):
        if match.group(1).lower() not in ALLOWED_EMAIL_DOMAINS:
            findings.append(f"{label}: non-placeholder email address")
    if APPLE_TEAM_ASSIGNMENT.search(value) or APPLE_ACCESS_GROUP.search(value):
        findings.append(f"{label}: concrete Apple signing identity")
    for pattern in deny_patterns:
        if pattern.casefold() in value.casefold():
            findings.append(f"{label}: matches private local deny pattern")
    return findings


def read_worktree_regular(relative: Path) -> bytes:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise OSError("invalid worktree path")
    directory_fds: list[int] = []
    file_fd: int | None = None
    try:
        current = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
        directory_fds.append(current)
        for component in relative.parts[:-1]:
            current = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=current,
            )
            directory_fds.append(current)
        file_fd = os.open(
            relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=current,
        )
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError("worktree entry is not a regular file")
        chunks: list[bytes] = []
        remaining = 8 * 1024 * 1024 + 1
        while remaining:
            chunk = os.read(file_fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)


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
    findings = inspect_path(path)
    pure = PurePosixPath(path)
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
            value = match.group(0).lower()
            if value not in ALLOWED_UUIDS and not synthetic_uuid(value):
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
        if (not checker_source
                and (APPLE_TEAM_ASSIGNMENT.search(line) or APPLE_ACCESS_GROUP.search(line))):
            findings.append(f"{prefix}: concrete Apple signing identity")
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
    path_findings = inspect_path(path)
    if len(raw) > 8 * 1024 * 1024:
        return [*path_findings, f"{path}: blob exceeds the public inspection limit"]
    if b"\0" in raw:
        return [*path_findings, f"{path}: binary or NUL-containing blob requires explicit review"]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [*path_findings, f"{path}: non-UTF-8 blob requires explicit review"]
    return inspect_text(path, text, deny_patterns)


def inspect_index(deny_patterns: list[str]) -> list[str]:
    findings: list[str] = []
    for record in git("ls-files", "--stage", "-z").split(b"\0"):
        if not record:
            continue
        metadata, path_raw = record.split(b"\t", 1)
        mode_raw, object_id_raw, stage_raw = metadata.split(b" ")
        path = path_raw.decode("utf-8", "surrogateescape")
        findings.extend(inspect_identifier_value(f"Git path {path}", path, deny_patterns))
        mode = mode_raw.decode("ascii")
        stage = stage_raw.decode("ascii")
        object_id = object_id_raw.decode("ascii")
        if stage != "0" or mode not in {"100644", "100755"}:
            findings.append(f"{path}: unsupported staged Git entry mode {mode} stage {stage}")
            continue
        size = int(git("cat-file", "-s", object_id))
        if size > 8 * 1024 * 1024:
            findings.append(f"{path}: blob exceeds the public inspection limit")
            continue
        findings.extend(inspect_raw(path, git("cat-file", "blob", object_id), deny_patterns))
    return findings


def inspect_worktree(deny_patterns: list[str]) -> list[str]:
    findings: list[str] = []
    for relative in worktree_files():
        findings.extend(inspect_identifier_value(
            f"Git path {relative.as_posix()}", relative.as_posix(), deny_patterns
        ))
        try:
            raw = read_worktree_regular(relative)
        except OSError as error:
            findings.append(
                f"{relative.as_posix()}: worktree entry is not a readable no-follow regular file "
                f"({type(error).__name__})"
            )
            continue
        findings.extend(inspect_raw(relative.as_posix(), raw, deny_patterns))
    return findings


def inspect_tag_object(
    object_id: str,
    deny_patterns: list[str],
    seen: set[str] | None = None,
    depth: int = 0,
) -> list[str]:
    findings: list[str] = []
    seen = set() if seen is None else seen
    if object_id in seen:
        return [f"{object_id[:12]}: annotated-tag cycle"]
    if depth >= 64:
        return [f"{object_id[:12]}: annotated-tag nesting exceeds inspection limit"]
    seen.add(object_id)
    raw = git("cat-file", "tag", object_id)
    findings.extend(
        f"{object_id[:12]} {item}"
        for item in inspect_raw(f"tag-object/{object_id}.txt", raw, deny_patterns)
    )
    headers, separator, _message = raw.partition(b"\n\n")
    if not separator:
        findings.append(f"{object_id[:12]}: malformed annotated-tag object")
        return findings
    object_fields = [line[7:] for line in headers.splitlines() if line.startswith(b"object ")]
    type_fields = [line[5:] for line in headers.splitlines() if line.startswith(b"type ")]
    if len(object_fields) != 1 or len(type_fields) != 1:
        findings.append(f"{object_id[:12]}: malformed annotated-tag headers")
        return findings
    target = object_fields[0]
    declared_type = type_fields[0]
    if not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", target):
        findings.append(f"{object_id[:12]}: malformed annotated-tag target")
        return findings
    target_id = target.decode("ascii")
    actual_type = git("cat-file", "-t", target_id).strip()
    if actual_type not in {b"blob", b"commit", b"tag", b"tree"}:
        findings.append(f"{object_id[:12]}: unsupported annotated-tag target type")
        return findings
    if declared_type != actual_type:
        findings.append(f"{object_id[:12]}: annotated-tag declared/actual type mismatch")
    if actual_type == b"tag":
        findings.extend(
            inspect_tag_object(target_id, deny_patterns, seen, depth + 1)
        )
    return findings


def reachable_entries(ref: str):
    for commit in git("rev-list", ref).splitlines():
        for record in git("ls-tree", "-r", "-z", commit.decode("ascii")).split(b"\0"):
            if not record:
                continue
            metadata, path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ")
            yield mode.decode("ascii"), kind.decode("ascii"), object_id.decode("ascii"), path.decode("utf-8", "surrogateescape")


def inspect_history(ref: str, deny_patterns: list[str], include_tags: bool = True) -> list[str]:
    findings: list[str] = []
    for mode, kind, object_id, path in reachable_entries(ref):
        findings.extend(inspect_identifier_value(f"Git path {path}", path, deny_patterns))
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
    for commit_raw in git("rev-list", ref).splitlines():
        commit = commit_raw.decode("ascii")
        raw = git("cat-file", "commit", commit)
        _headers, separator, _message = raw.partition(b"\n\n")
        if not separator:
            findings.append(f"{commit[:12]}: malformed commit object")
            continue
        findings.extend(
            f"{commit[:12]} {item}"
            for item in inspect_raw(f"commit-object/{commit}.txt", raw, deny_patterns)
        )
    tag_records = (git(
        "for-each-ref", "--format=%(objectname)%00%(objecttype)%00%(refname)", "refs/tags"
    ).splitlines() if include_tags else [])
    for record in tag_records:
        object_id_raw, kind_raw, ref_raw = record.split(b"\0", 2)
        object_id = object_id_raw.decode("ascii")
        kind = kind_raw.decode("ascii")
        ref_name = ref_raw.decode("utf-8", "surrogateescape")
        findings.extend(
            f"{object_id[:12]} {item}"
            for item in inspect_text(f"tag-ref/{object_id}.txt", ref_name, deny_patterns)
        )
        if kind == "tag":
            findings.extend(inspect_tag_object(object_id, deny_patterns))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", default="HEAD", help="exact Git ref whose reachable objects will be published")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--worktree-only", action="store_true")
    modes.add_argument("--staged-only", action="store_true")
    modes.add_argument("--history-only", action="store_true")
    args = parser.parse_args()
    deny_patterns = local_deny_patterns()
    if args.staged_only:
        findings = inspect_index(deny_patterns)
    elif args.history_only:
        findings = inspect_history(args.ref, deny_patterns, include_tags=False)
    else:
        findings = inspect_worktree(deny_patterns)
    if not (args.worktree_only or args.staged_only or args.history_only):
        findings.extend(inspect_history(args.ref, deny_patterns))
    if findings:
        raise SystemExit("\n".join(dict.fromkeys(findings)))
    if args.worktree_only:
        scope = "non-ignored worktree"
    elif args.staged_only:
        scope = "exact staged index"
    elif args.history_only:
        scope = f"objects reachable from {args.ref}"
    else:
        scope = f"non-ignored worktree and objects reachable from {args.ref}"
    print(f"Public-material check passed for {scope}.")


if __name__ == "__main__":
    main()
