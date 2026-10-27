#!/usr/bin/env python3
"""Report legacy migration/deletion gates. This tool never deletes data."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


GENERATION = re.compile(r"^[0-9]{8}T[0-9]{6}Z$")
ROLES = ("gateway", "research", "target")
SCOPE_CATEGORIES = {
    "claude_conversations", "conversation_capture", "evidence_receipts", "findings",
    "memory_proposals", "native_memory", "related_agent_state", "reports",
    "review_materials", "scripts", "workspace_materials",
}
VM_NAMES = {
    "gateway": "SecureSandbox-Gateway.pvm",
    "research": "SecureSandbox-Research.pvm",
    "target": "SecureSandbox-Target.pvm",
}


class StatusError(RuntimeError):
    pass


def load_json(path: Path) -> dict[str, object] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise StatusError(f"record_untrusted:{path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StatusError(f"record_invalid:{path.name}") from error
    if not isinstance(value, dict):
        raise StatusError(f"record_invalid:{path.name}")
    return value


def sha256_regular(path: Path) -> str | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
            raise StatusError(f"archive_untrusted:{path.name}")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise StatusError(f"archive_changed:{path.name}")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def secondary_copy_current(repo: Path, redundancy: dict[str, object],
                           archive_hashes: dict[str, str]) -> bool:
    """Re-verify that the attested second copy still exists on another filesystem."""
    root_value = redundancy.get("secondary_root")
    if not isinstance(root_value, str) or not root_value or not Path(root_value).is_absolute():
        return False
    root = Path(root_value)
    try:
        info = root.lstat()
        primary_info = (repo / ".private/legacy-migration"
                        / str(redundancy.get("generation")) / "archives").lstat()
    except FileNotFoundError:
        return False
    if (not stat.S_ISDIR(info.st_mode) or root.is_symlink() or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022 or info.st_dev == primary_info.st_dev):
        return False
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        return False
    if resolved != root:
        return False
    for role in ROLES:
        archive = root / f"{role}.tar.gz"
        try:
            archive_info = archive.lstat()
        except FileNotFoundError:
            return False
        if archive_info.st_uid != os.geteuid() or archive_info.st_dev != info.st_dev:
            return False
        try:
            digest = sha256_regular(archive)
        except (OSError, StatusError):
            return False
        if digest != archive_hashes.get(role):
            return False
    return True


def evaluate(repo: Path, generation: str) -> dict[str, object]:
    if not GENERATION.fullmatch(generation):
        raise StatusError("generation_invalid")
    quarantine_root = (repo / ".private/vm-quarantine").resolve()
    source = (quarantine_root / generation).resolve()
    if source.parent != quarantine_root or not source.is_dir() or source.is_symlink():
        raise StatusError("quarantine_generation_invalid")

    gates: dict[str, dict[str, object]] = {}
    bundles = []
    for role in ROLES:
        bundle = source / VM_NAMES[role]
        try:
            info = bundle.lstat()
        except FileNotFoundError:
            valid = False
        else:
            valid = stat.S_ISDIR(info.st_mode) and not bundle.is_symlink()
        bundles.append(valid)
        gates[f"source_{role}_preserved"] = {"passed": valid, "path": str(bundle)}

    restoration = load_json(repo / ".private/restoration/current.json")
    restoration_complete = bool(
        restoration
        and restoration.get("schema") == "secure-sandbox-fresh-vm-restoration-v1"
        and restoration.get("status") == "complete"
    )
    gates["fresh_vm_restoration_complete"] = {"passed": restoration_complete}

    receipt_root = repo / ".private/legacy-migration" / generation / "receipts"
    archive_root = repo / ".private/legacy-migration" / generation / "archives"
    archive_hashes: dict[str, str] = {}
    creating_plan_hashes: dict[str, str] = {}
    source_tree_hashes: dict[str, str] = {}
    for role in ROLES:
        receipt = load_json(receipt_root / f"preservation-{role}.json")
        archive_digest = sha256_regular(archive_root / f"{role}.tar.gz")
        valid = bool(
            receipt
            and receipt.get("schema") == "secure-sandbox-legacy-preservation-receipt-v1"
            and receipt.get("verification_schema") == "secure-sandbox-legacy-preservation-verification-v1"
            and receipt.get("status") == "verified"
            and receipt.get("role") == role
            and receipt.get("generation") == generation
            and isinstance(receipt.get("plan_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", receipt["plan_sha256"])
            and isinstance(receipt.get("source_tree_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", receipt["source_tree_sha256"])
            and isinstance(receipt.get("legacy_vm_uuid"), str)
            and re.fullmatch(r"\{[0-9a-f-]{36}\}", receipt["legacy_vm_uuid"])
            and isinstance(receipt.get("archive_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", receipt["archive_sha256"])
            and archive_digest == receipt.get("archive_sha256")
        )
        if valid:
            archive_hashes[role] = str(receipt["archive_sha256"])
            creating_plan_hashes[role] = str(receipt["plan_sha256"])
            source_tree_hashes[role] = str(receipt["source_tree_sha256"])
        gates[f"preservation_{role}_verified"] = {"passed": valid}
    preservation_set = load_json(receipt_root / "preservation-set.json")
    set_valid = bool(
        preservation_set
        and preservation_set.get("schema")
        == "secure-sandbox-legacy-preservation-set-v1"
        and preservation_set.get("status") == "verified"
        and preservation_set.get("generation") == generation
        and isinstance(preservation_set.get("plan_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", preservation_set["plan_sha256"])
        and preservation_set.get("archive_sha256") == archive_hashes
        and preservation_set.get("creating_plan_sha256") == creating_plan_hashes
        and preservation_set.get("source_tree_sha256") == source_tree_hashes
        and isinstance(preservation_set.get("transport_research_uuid"), str)
        and re.fullmatch(
            r"\{[0-9a-f-]{36}\}", preservation_set["transport_research_uuid"]
        )
    )
    gates["preservation_set_one_plan"] = {
        "passed": len(archive_hashes) == len(ROLES) and set_valid
    }

    imported = load_json(receipt_root / "continuity-import.json")
    imported_sessions = imported.get("imported_session_ids", []) if imported else []
    preserved_scope = imported.get("preserved_scope") if imported else None
    scope_valid = bool(
        isinstance(preserved_scope, dict) and set(preserved_scope) == SCOPE_CATEGORIES
        and all(
            isinstance(value, dict) and set(value) == {"records", "regular_bytes", "sha256"}
            and isinstance(value["records"], int) and not isinstance(value["records"], bool)
            and value["records"] >= 0
            and isinstance(value["regular_bytes"], int)
            and not isinstance(value["regular_bytes"], bool) and value["regular_bytes"] >= 0
            and isinstance(value["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
            for value in preserved_scope.values()
        )
        and isinstance(imported.get("preserved_scope_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", imported["preserved_scope_sha256"])
        and hashlib.sha256((json.dumps(
            preserved_scope, separators=(",", ":"), sort_keys=True
        ) + "\n").encode()).hexdigest() == imported["preserved_scope_sha256"]
    )
    import_valid = bool(
        imported
        and imported.get("schema") == "secure-sandbox-legacy-continuity-receipt-v1"
        and imported.get("status") == "imported"
        and imported.get("blocking_conflicts") == 0
        and imported.get("rejected") == 0
        and scope_valid
        and imported.get("archive_sha256") == archive_hashes.get("research")
        and isinstance(imported.get("dispositions"), int)
        and not isinstance(imported.get("dispositions"), bool)
        and imported.get("dispositions", 0) > 0
        and isinstance(imported.get("dispositions_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", imported["dispositions_sha256"])
        and isinstance(imported_sessions, list) and bool(imported_sessions)
        and len(imported_sessions) == len(set(imported_sessions))
        and all(isinstance(value, str) and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", value
        ) for value in imported_sessions)
        and isinstance(imported.get("report_evidence_count"), int)
        and not isinstance(imported.get("report_evidence_count"), bool)
        and imported.get("report_evidence_count", 0) > 0
        and isinstance(imported.get("report_evidence_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", imported["report_evidence_sha256"])
    )
    gates["research_continuity_imported"] = {"passed": import_valid}

    continuity = load_json(receipt_root / "glm-continuity.json")
    continuity_valid = bool(
        continuity
        and continuity.get("schema") == "secure-sandbox-glm-continuity-acceptance-v1"
        and continuity.get("status") == "continuous"
        and continuity.get("session_resume_verified") is True
        and continuity.get("reports_verified") is True
        and continuity.get("context_verified") is True
        and continuity.get("evidence_class") == "operator-observed-first-person-glm"
        and continuity.get("generation") == generation
        and isinstance(continuity.get("observed_at"), int)
        and not isinstance(continuity.get("observed_at"), bool)
        and continuity.get("observed_at", 0) > 0
        and continuity.get("archive_sha256") == archive_hashes.get("research")
        and continuity.get("session_id") in imported_sessions
        and continuity.get("report_evidence_sha256") == (
            imported.get("report_evidence_sha256") if imported else None
        )
        and continuity.get("preserved_scope_sha256") == (
            imported.get("preserved_scope_sha256") if imported else None
        )
    )
    gates["glm_continuity_accepted"] = {"passed": continuity_valid}

    redundancy = load_json(receipt_root / "redundancy.json")
    redundancy_valid = bool(
        redundancy
        and redundancy.get("schema") == "secure-sandbox-legacy-redundancy-v1"
        and redundancy.get("status") == "verified"
        and redundancy.get("generation") == generation
        and redundancy.get("archive_sha256") == archive_hashes
        and isinstance(redundancy.get("independent_copies"), int)
        and not isinstance(redundancy.get("independent_copies"), bool)
        and redundancy.get("independent_copies", 0) >= 2
        and redundancy.get("failure_domain_evidence")
        == "operator-attested-separate-failure-domain-and-distinct-filesystem"
        and isinstance(redundancy.get("primary_device"), int)
        and isinstance(redundancy.get("secondary_device"), int)
        and redundancy.get("primary_device") != redundancy.get("secondary_device")
        and isinstance(redundancy.get("verified_at"), int)
        and not isinstance(redundancy.get("verified_at"), bool)
        and redundancy.get("verified_at", 0) > 0
        and secondary_copy_current(repo, redundancy, archive_hashes)
    )
    gates["two_copy_preservation_verified"] = {"passed": redundancy_valid}

    approval = load_json(receipt_root / "operator-retirement-approval.json")
    approval_valid = bool(
        approval
        and approval.get("schema") == "secure-sandbox-legacy-retirement-approval-v1"
        and approval.get("status") == "approved"
        and approval.get("generation") == generation
        and approval.get("archive_sha256") == archive_hashes
        and approval.get("evidence_class")
        == "operator-explicit-after-all-technical-gates"
        and approval.get("glm_continuity_confirmed") is True
        and approval.get("independent_backup_confirmed") is True
        and approval.get("retirement_understood") is True
        and isinstance(approval.get("approved_at"), int)
        and not isinstance(approval.get("approved_at"), bool)
        and approval.get("approved_at", 0) > 0
    )
    gates["operator_retirement_approved"] = {"passed": approval_valid}

    failed = [name for name, value in gates.items() if not value["passed"]]
    return {
        "deletion_eligible": not failed,
        "failed_gates": failed,
        "gates": gates,
        "generation": generation,
        "schema": "secure-sandbox-legacy-migration-status-v1",
        "status": "eligible" if not failed else "preserve",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--generation", required=True)
    args = parser.parse_args()
    result = evaluate(Path(args.repo).resolve(), args.generation)
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (StatusError, OSError) as error:
        print(f"legacy_migration_status_rejected:{type(error).__name__}:{error}", file=__import__("sys").stderr)
        raise SystemExit(1)

