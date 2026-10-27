#!/usr/bin/env python3
"""Archive predecessor acceptance evidence without changing the pinned verifier."""
from __future__ import annotations
import json, os, re, stat, sys, uuid
from pathlib import Path
from typing import Callable

STATE_ROOT = Path("/var/lib/secure-sandbox/execution-approval-transition")
MAX_ARCHIVED = 64
MAXIMUM_SIZE = 16 * 1024
EVIDENCE_SCHEMA = "secure-sandbox-execution-approval-acceptance-evidence-v1"
JOURNAL_SCHEMA = "secure-sandbox-execution-approval-transition-journal-v2"
PHASE_RECEIPT_SCHEMA = "secure-sandbox-execution-approval-transition-receipt-v2"
RESULT_SCHEMA = "secure-sandbox-execution-approval-evidence-archive-v1"
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
COMMITTED_FIELDS = ("transaction_id", "generation_id", "generation_epoch",
                    "host_release_id", "research_release_id")

class ArchiveError(RuntimeError): pass

def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"

def checked_uuid4(value: object, label: str) -> str:
    try: parsed = uuid.UUID(value)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError) as error: raise ArchiveError(f"{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value: raise ArchiveError(f"{label}_invalid")
    return str(value)

def lexists(path: Path) -> bool: return os.path.lexists(path)

def trusted_directory(path: Path, uid: int, gid: int, *, create: bool = False) -> None:
    if create and not lexists(path): path.mkdir(mode=0o700)
    try: info = path.lstat()
    except OSError as error: raise ArchiveError("acceptance_evidence_directory_untrusted") from error
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ArchiveError("acceptance_evidence_directory_untrusted")

def read_json(path: Path, schema: str, uid: int, gid: int) -> tuple[dict, bytes]:
    try:
        info, raw = path.lstat(), path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ArchiveError("acceptance_evidence_state_untrusted") from error
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or info.st_gid != gid or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or len(raw) > MAXIMUM_SIZE
            or not isinstance(value, dict) or value.get("schema") != schema
            or canonical(value) != raw):
        raise ArchiveError("acceptance_evidence_state_untrusted")
    return value, raw

def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)

def load_committed_history(history: Path, uid: int, gid: int) -> dict[str, dict]:
    trusted_directory(history, uid, gid)
    journals = {}
    for path in sorted(history.iterdir(), key=lambda item: item.name):
        if path.suffix != ".json" or UUID4.fullmatch(path.stem) is None:
            raise ArchiveError("acceptance_evidence_history_untrusted")
        journal, _ = read_json(path, JOURNAL_SCHEMA, uid, gid)
        transaction = checked_uuid4(journal.get("transaction_id"), "history_transaction")
        if transaction != path.stem or journal.get("phase") != "committed":
            raise ArchiveError("acceptance_evidence_history_untrusted")
        journals[transaction] = journal
    return journals

def validate_evidence_history(evidence: dict, journal: dict, state_root: Path,
                              uid: int, gid: int) -> bool:
    if not all(evidence.get(name) == journal.get(name) for name in COMMITTED_FIELDS):
        return False
    attempt = evidence.get("acceptance_attempt_number")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        return False
    receipts = state_root / "phase-receipts"
    trusted_directory(receipts, uid, gid)
    receipt, _ = read_json(
        receipts / f"{evidence['transaction_id']}.acceptance-{attempt}.json",
        PHASE_RECEIPT_SCHEMA, uid, gid,
    )
    return (receipt.get("outcome") == "succeeded"
            and receipt.get("phase") == "acceptance"
            and all(receipt.get(name) == evidence.get(name) for name in (
                "transaction_id", "generation_id", "generation_epoch"))
            and receipt.get("journal_sha256") == journal.get("prior_record_sha256"))

def validate_archive(archive: Path, journals: dict[str, dict], state_root: Path,
                     uid: int, gid: int) -> dict[str, bytes]:
    trusted_directory(archive, uid, gid, create=True)
    entries = {}
    for path in sorted(archive.iterdir(), key=lambda item: item.name):
        if path.suffix != ".json" or UUID4.fullmatch(path.stem) is None:
            raise ArchiveError("acceptance_evidence_archive_untrusted")
        evidence, raw = read_json(path, EVIDENCE_SCHEMA, uid, gid)
        transaction = checked_uuid4(evidence.get("transaction_id"), "archive_transaction")
        journal = journals.get(transaction)
        if (transaction != path.stem or journal is None
                or not validate_evidence_history(evidence, journal, state_root, uid, gid)):
            raise ArchiveError("acceptance_evidence_archive_untrusted")
        entries[transaction] = raw
    if len(entries) > MAX_ARCHIVED: raise ArchiveError("acceptance_evidence_archive_limit_exceeded")
    return entries

def expected_predecessor(current: dict, journals: dict[str, dict]) -> tuple[str, dict]:
    previous_id = checked_uuid4(current.get("previous_generation_id"), "previous_generation_id")
    previous_epoch = current.get("previous_generation_epoch")
    matches = [(tid, journal) for tid, journal in journals.items()
               if journal.get("generation_id") == previous_id
               and journal.get("generation_epoch") == previous_epoch]
    if len(matches) != 1: raise ArchiveError("acceptance_evidence_predecessor_history_invalid")
    return matches[0]

def archive_predecessor(current_transaction: str, *, state_root: Path = STATE_ROOT,
        expected_uid: int = 0, expected_gid: int = 0,
        fault: Callable[[str], None] | None = None) -> dict:
    current_transaction = checked_uuid4(current_transaction, "current_transaction")
    fault = fault or (lambda _point: None)
    trusted_directory(state_root, expected_uid, expected_gid)
    journals = load_committed_history(state_root / "history", expected_uid, expected_gid)
    current, _ = read_json(state_root / "journal.json", JOURNAL_SCHEMA, expected_uid, expected_gid)
    if current.get("transaction_id") != current_transaction or current.get("phase") not in {"acceptance", "committed"}:
        raise ArchiveError("acceptance_evidence_current_journal_invalid")
    predecessor_transaction, predecessor_journal = expected_predecessor(current, journals)
    archive = state_root / "acceptance-evidence-history"
    entries = validate_archive(archive, journals, state_root, expected_uid, expected_gid)
    predecessor_archived = predecessor_transaction in entries
    singleton = state_root / "acceptance-evidence.json"
    if not lexists(singleton):
        if not predecessor_archived: raise ArchiveError("acceptance_evidence_predecessor_missing")
        return {"schema":RESULT_SCHEMA, "status":"absent", "archived_transaction_id":predecessor_transaction, "current_transaction_id":current_transaction}
    evidence, raw = read_json(singleton, EVIDENCE_SCHEMA, expected_uid, expected_gid)
    singleton_transaction = checked_uuid4(evidence.get("transaction_id"), "evidence_transaction")
    if singleton_transaction == current_transaction:
        if not predecessor_archived: raise ArchiveError("acceptance_evidence_predecessor_missing")
        return {"schema":RESULT_SCHEMA, "status":"current", "archived_transaction_id":predecessor_transaction, "current_transaction_id":current_transaction}
    if (singleton_transaction != predecessor_transaction
            or not validate_evidence_history(
                evidence, predecessor_journal, state_root, expected_uid, expected_gid)):
        raise ArchiveError("acceptance_evidence_history_mismatch")
    target = archive / f"{predecessor_transaction}.json"
    if predecessor_archived:
        if entries[predecessor_transaction] != raw: raise ArchiveError("acceptance_evidence_archive_conflict")
        singleton.unlink()
    else:
        if len(entries) >= MAX_ARCHIVED: raise ArchiveError("acceptance_evidence_archive_limit_exceeded")
        os.replace(singleton, target)
    fault("after_replace")
    fsync_directory(archive); fault("after_archive_fsync")
    fsync_directory(state_root); fault("after_state_fsync")
    entries = validate_archive(archive, journals, state_root, expected_uid, expected_gid)
    if predecessor_transaction not in entries or lexists(singleton):
        raise ArchiveError("acceptance_evidence_archive_postcondition_failed")
    return {"schema":RESULT_SCHEMA, "status":"archived", "archived_transaction_id":predecessor_transaction, "current_transaction_id":current_transaction}

def main() -> int:
    if os.geteuid() != 0: raise ArchiveError("root_required")
    if len(sys.argv) != 2: raise ArchiveError("current_transaction_invalid")
    print(json.dumps(archive_predecessor(sys.argv[1]), separators=(",", ":"), sort_keys=True))
    return 0

if __name__ == "__main__":
    try: raise SystemExit(main())
    except ArchiveError as error:
        print(str(error), file=sys.stderr); raise SystemExit(1)
