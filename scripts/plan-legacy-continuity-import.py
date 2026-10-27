#!/usr/bin/env python3
"""Plan a conflict-safe Research continuity import without extracting data."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tarfile


ROOT = Path(__file__).resolve().parent
VERIFY_PATH = ROOT / "verify-legacy-archive.py"
MANAGED_WORKSPACE_ROOTS = {
    "baselines", "codegraph-indexes", "corpus-indexes", "dependency-bundles",
    "repos", "review-bundles", "source-manifests",
}
AGENT_INSTRUCTION_FILES = {
    "AGENTS.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".mcp.json",
}
AGENT_CONTROL_DIRECTORIES = {".claude", ".git", ".cursor"}
CLAUDE_PROJECTS = Path("/home/agent/.claude/projects")
WORKSPACE = Path("/home/agent/research-workspace")
RESUMABLE_CLAUDE_PROJECTS = {
    "-home-agent",
    "-home-agent-research-workspace",
}
SESSION_JOURNAL = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.jsonl$"
)


class PlanError(RuntimeError):
    pass


def load_verifier():
    spec = importlib.util.spec_from_file_location("legacy_archive_verifier", VERIFY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def manifest_from_archive(path: Path) -> dict[str, object]:
    manifest = None
    with gzip.open(path, "rb") as compressed:
        with tarfile.open(fileobj=compressed, mode="r|") as archive:
            for item in archive:
                if item.name != "MANIFEST.json":
                    continue
                stream = archive.extractfile(item)
                if stream is None:
                    raise PlanError("manifest_unreadable")
                manifest = json.loads(stream.read())
    if not isinstance(manifest, dict):
        raise PlanError("manifest_missing")
    return manifest


def decoded_source(record: dict[str, object]) -> Path:
    value = record.get("source_path_hex")
    if not isinstance(value, str):
        raise PlanError("source_path_invalid")
    try:
        path = Path(os.fsdecode(bytes.fromhex(value)))
    except (TypeError, ValueError) as error:
        raise PlanError("source_path_invalid") from error
    if not path.is_absolute():
        raise PlanError("source_path_invalid")
    return path


def relative_to(path: Path, root: Path) -> Path | None:
    try:
        return path.relative_to(root)
    except ValueError:
        return None


def import_class(path: Path, record: dict[str, object]) -> str:
    kind = record.get("kind")
    if record.get("omitted") is True:
        return "archive_only_special"
    project_relative = relative_to(path, CLAUDE_PROJECTS)
    if project_relative is not None:
        if "memory" in project_relative.parts:
            return "archive_only_governed_memory"
        project_name = project_relative.parts[0] if project_relative.parts else ""
        if project_name not in RESUMABLE_CLAUDE_PROJECTS:
            return "archive_only_claude_state"
        if kind == "directory" and len(project_relative.parts) == 1:
            return "claude_journal_directory"
        if (kind == "regular" and len(project_relative.parts) == 2
                and SESSION_JOURNAL.fullmatch(project_relative.name)):
            return "claude_journal"
        return "archive_only_claude_state"
    workspace_relative = relative_to(path, WORKSPACE)
    if workspace_relative is not None:
        if (any(part in AGENT_CONTROL_DIRECTORIES for part in workspace_relative.parts)
                or any(part in AGENT_INSTRUCTION_FILES for part in workspace_relative.parts)):
            return "archive_only_agent_control"
        first = workspace_relative.parts[0] if workspace_relative.parts else ""
        if first in MANAGED_WORKSPACE_ROOTS:
            return "archive_only_managed_workspace"
        if kind == "directory":
            return "workspace_directory"
        if kind == "regular":
            return "workspace_file"
        return "archive_only_workspace_link"
    return "archive_only_root_state"


def destination(path: Path, prefix: Path) -> Path:
    return prefix / path.relative_to("/")


def regular_sha256(path: Path) -> str | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode):
        raise PlanError("destination_type_conflict")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise PlanError("destination_changed")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise PlanError("destination_changed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def plan(archive: Path, prefix: Path) -> dict[str, object]:
    verifier = load_verifier()
    verification = verifier.verify(archive, include_manifest=True)
    if verification.get("role") != "research":
        raise PlanError("research_archive_required")
    manifest = verification.pop("_manifest")
    dispositions: list[dict[str, object]] = []
    counts: dict[str, int] = {}
    blocking = 0
    for record in manifest["records"]:
        path = decoded_source(record)
        category = import_class(path, record)
        action = "archive_only"
        target = None
        if category in {"claude_journal", "workspace_file"}:
            target_path = destination(path, prefix)
            target = str(target_path)
            try:
                existing = regular_sha256(target_path)
            except PlanError:
                action = "conflict"
                blocking += 1
            else:
                if existing is None:
                    action = "create"
                elif existing == record.get("sha256"):
                    action = "identical"
                else:
                    action = "conflict"
                    blocking += 1
        elif category in {"claude_journal_directory", "workspace_directory"}:
            target_path = destination(path, prefix)
            target = str(target_path)
            if target_path.exists() and not target_path.is_dir():
                action = "conflict"
                blocking += 1
            else:
                action = "directory"
        counts[action] = counts.get(action, 0) + 1
        dispositions.append({
            "action": action,
            "category": category,
            "destination": target,
            "sha256": record.get("sha256"),
            "source_path_hex": record["source_path_hex"],
        })
    return {
        "archive_sha256": verification["archive_sha256"],
        "blocking_conflicts": blocking,
        "counts": counts,
        "dispositions": dispositions,
        "manifest_sha256": verification["manifest_sha256"],
        "schema": "secure-sandbox-legacy-continuity-plan-v1",
        "status": "blocked" if blocking else "ready",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument("--destination-prefix", default="/")
    args = parser.parse_args()
    result = plan(Path(args.archive), Path(args.destination_prefix))
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 2 if result["blocking_conflicts"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PlanError, OSError, tarfile.TarError, json.JSONDecodeError) as error:
        print(f"legacy_import_plan_rejected:{type(error).__name__}:{error}", file=os.sys.stderr)
        raise SystemExit(1)

