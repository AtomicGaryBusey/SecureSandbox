#!/usr/bin/env python3
"""Root-only append-only adjudication and disposition control plane."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from findings_broker import (
    STATE_DIR, WORKSPACE, UUID4_RE, SHA256_RE, FindingError, canonical,
    canonical_uuid4, clean_text, safe_relative,
)

JOURNAL_SCHEMA = "secure-sandbox-finding-adjudication-event-v1"
TRUSTED_UID = 0
STATES = {"candidate", "needs_evidence", "disputed", "validated", "rejected", "withdrawn"}
TERMINAL = {"validated", "rejected", "withdrawn"}
RELATIONS = {"duplicate_of", "supersedes", "disputes"}
METHODS = {"re_executed", "inspected_evidence", "reasoning_only"}
ROLES = {"research_lead", "architect", "independent_reviewer"}
TRANSITIONS = {
    "candidate": {"needs_evidence", "disputed", "validated", "rejected", "withdrawn"},
    "needs_evidence": {"disputed", "validated", "rejected", "withdrawn"},
    "disputed": {"needs_evidence", "validated", "rejected", "withdrawn"},
    "validated": set(), "rejected": set(), "withdrawn": set(),
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("finding administration requires root")


def paths(state: Path = STATE_DIR) -> dict[str, Path]:
    return {name: state / name for name in ("candidates", "amendments", "adjudication", "snapshots", "archive")}


def load_json(path: Path, schema: str) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
        raise FindingError("finding_record_untrusted")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != schema:
        raise FindingError("finding_record_invalid")
    if "content_sha256" in value:
        recorded = value["content_sha256"]; unsigned = dict(value); unsigned.pop("content_sha256", None)
        if recorded != hashlib.sha256(canonical(unsigned)).hexdigest():
            raise FindingError("finding_record_invalid")
    return value


def candidate_path(finding_id: str, state: Path = STATE_DIR) -> Path:
    direct = state / "candidates" / f"{finding_id}.json"
    archived = state / "archive" / finding_id / "candidate.json"
    if direct.is_file() and not direct.is_symlink(): return direct
    if archived.is_file() and not archived.is_symlink(): return archived
    raise FindingError("finding_not_found")


def load_candidate(finding_id: str, state: Path = STATE_DIR) -> dict[str, Any]:
    return load_json(candidate_path(canonical_uuid4(finding_id, "finding_id"), state), "secure-sandbox-candidate-finding-v1")


def load_amendments(finding_id: str, state: Path = STATE_DIR) -> list[dict[str, Any]]:
    root = state / "amendments"
    archive = state / "archive" / finding_id / "amendments"
    result = []
    for directory in (root, archive):
        if not directory.exists(): continue
        for item in sorted(directory.iterdir()):
            try:
                value = load_json(item, "secure-sandbox-finding-amendment-v1")
                if value.get("finding_id") == finding_id: result.append(value)
            except (OSError, ValueError, json.JSONDecodeError, FindingError):
                continue
    return result


def verify_journal(path: Path) -> list[dict[str, Any]]:
    if not path.exists(): return []
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o027:
        raise FindingError("adjudication_journal_untrusted")
    events, previous = [], "0" * 64
    with path.open(encoding="utf-8") as handle:
        for sequence, line in enumerate(handle, 1):
            try: event = json.loads(line)
            except (ValueError, json.JSONDecodeError) as error: raise FindingError("adjudication_journal_invalid") from error
            if (not isinstance(event, dict) or event.get("schema") != JOURNAL_SCHEMA
                    or event.get("seq") != sequence or event.get("prev_entry_sha256") != previous):
                raise FindingError("adjudication_journal_invalid")
            recorded = event.get("entry_sha256"); unsigned = dict(event); unsigned.pop("entry_sha256", None)
            calculated = hashlib.sha256(canonical(unsigned)).hexdigest()
            if recorded != calculated: raise FindingError("adjudication_journal_invalid")
            previous = recorded; events.append(event)
    return events


def current_state(finding_id: str, events: list[dict[str, Any]]) -> str:
    state = "candidate"
    for event in events:
        if event.get("finding_id") != finding_id: continue
        if event.get("event") == "state_changed": state = event["to_state"]
        elif event.get("event") == "reopened": state = "needs_evidence"
    return state


def all_evidence(candidate: dict[str, Any], amendments: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for evidence in candidate.get("evidence", []): result[hashlib.sha256(canonical(evidence)).hexdigest()] = evidence
    for amendment in amendments:
        for evidence in amendment.get("evidence", []): result[hashlib.sha256(canonical(evidence)).hexdigest()] = evidence
    return result


def actor(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"id", "role"} or value.get("role") not in ROLES:
        raise FindingError("adjudicator_invalid")
    return {"id": clean_text(value["id"], "adjudicator_id", 96, multiline=False), "role": value["role"]}


def base_request(value: dict[str, Any], exact: set[str]) -> tuple[str, dict[str, str], str, str]:
    if set(value) != exact: raise FindingError("adjudication_schema_invalid")
    finding_id = canonical_uuid4(value["finding_id"], "finding_id")
    return (finding_id, actor(value["actor"]), clean_text(value["rationale"], "rationale", 4096),
            clean_text(value["conflict_note"], "conflict_note", 1024))


def snapshot_reports(
    finding_id: str, evidence: dict[str, dict[str, Any]], state: Path = STATE_DIR,
    workspace: Path | None = None, known_evidence: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if workspace is None: workspace = WORKSPACE
    if known_evidence is None: known_evidence = evidence
    report_items = [(digest, item) for digest, item in evidence.items() if item.get("class") == "report_reference"]
    if not report_items: return []
    destination = state / "snapshots" / finding_id
    if destination.exists():
        info = destination.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != TRUSTED_UID or info.st_mode & 0o077):
            raise FindingError("evidence_snapshot_invalid")
        for target in list(destination.iterdir()):
            temporary = re.fullmatch(r"\.([0-9a-f]{64})\.([1-9][0-9]*)\.new", target.name)
            if temporary:
                info = target.lstat()
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != TRUSTED_UID or info.st_mode & 0o077):
                    raise FindingError("evidence_snapshot_invalid")
                target.unlink(); continue
            match = re.fullmatch(r"([0-9a-f]{64})\.evidence", target.name)
            item = known_evidence.get(match.group(1)) if match else None
            if item is None or item.get("class") != "report_reference":
                raise FindingError("evidence_snapshot_invalid")
            try:
                info = target.lstat()
                if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o377:
                    raise FindingError("evidence_snapshot_invalid")
                calculated = hashlib.sha256(target.read_bytes()).hexdigest()
            except OSError as error:
                raise FindingError("evidence_snapshot_invalid") from error
            if calculated != item["content_sha256"] or info.st_size != item["size"]:
                raise FindingError("evidence_snapshot_invalid")
        records = []
        for digest, item in report_items:
            target = destination / f"{digest}.evidence"
            if not target.exists():
                relative = safe_relative(item["path"], "evidence_path", prefix="reports")
                source = workspace / relative
                descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                temporary = destination / f".{digest}.{os.getpid()}.new"
                calculated = hashlib.sha256(); size = 0
                try:
                    with os.fdopen(descriptor, "rb") as reader, temporary.open("xb") as writer:
                        while chunk := reader.read(65536):
                            size += len(chunk)
                            if size > 1024 * 1024: raise FindingError("evidence_report_invalid")
                            calculated.update(chunk); writer.write(chunk)
                        writer.flush(); os.fsync(writer.fileno())
                    os.chmod(temporary, 0o400)
                    if calculated.hexdigest() != item["content_sha256"] or size != item["size"]:
                        raise FindingError("evidence_report_changed")
                    os.rename(temporary, target)
                except Exception:
                    try: temporary.unlink()
                    except OSError: pass
                    raise
            info = target.lstat(); calculated = hashlib.sha256(target.read_bytes()).hexdigest()
            if calculated != item["content_sha256"] or info.st_size != item["size"]:
                raise FindingError("evidence_snapshot_invalid")
            records.append({"evidence_sha256":digest,"content_sha256":calculated,"snapshot":target.name})
        descriptor=os.open(destination,os.O_RDONLY|os.O_DIRECTORY); os.fsync(descriptor); os.close(descriptor)
        return records
    temporary = state / "snapshots" / f".{finding_id}.{os.getpid()}.new"
    temporary.mkdir(mode=0o700)
    records = []
    try:
        for digest, item in report_items:
            relative = safe_relative(item["path"], "evidence_path", prefix="reports")
            source = workspace / relative
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            target = temporary / f"{digest}.evidence"
            calculated = hashlib.sha256(); size = 0
            with os.fdopen(descriptor, "rb") as reader, target.open("xb") as writer:
                while chunk := reader.read(65536):
                    size += len(chunk)
                    if size > 1024 * 1024: raise FindingError("evidence_report_invalid")
                    calculated.update(chunk); writer.write(chunk)
                writer.flush(); os.fsync(writer.fileno())
            os.chmod(target, 0o400)
            if calculated.hexdigest() != item["content_sha256"] or size != item["size"]:
                raise FindingError("evidence_report_changed")
            records.append({"evidence_sha256": digest, "content_sha256": calculated.hexdigest(), "snapshot": target.name})
        descriptor = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY); os.fsync(descriptor); os.close(descriptor)
        os.replace(temporary, destination)
        descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY); os.fsync(descriptor); os.close(descriptor)
        return records
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def build_event(request: dict[str, Any], events: list[dict[str, Any]], state: Path = STATE_DIR) -> dict[str, Any]:
    action = request.get("action")
    if action == "transition":
        finding_id, adjudicator, rationale, conflict = base_request(
            request, {"action","finding_id","to_state","verification_method","consulted_evidence","actor","rationale","conflict_note"})
        candidate = load_candidate(finding_id, state); amendments = load_amendments(finding_id, state)
        before = current_state(finding_id, events); after = request["to_state"]
        if after not in STATES or after not in TRANSITIONS[before]: raise FindingError("transition_invalid")
        method = request["verification_method"]
        if method not in METHODS: raise FindingError("verification_method_invalid")
        consulted = request["consulted_evidence"]
        if not isinstance(consulted, list) or len(consulted) > 16 or len(set(consulted)) != len(consulted):
            raise FindingError("consulted_evidence_invalid")
        available = all_evidence(candidate, amendments)
        for digest in consulted:
            sha256 = digest if isinstance(digest, str) and SHA256_RE.fullmatch(digest) else None
            if sha256 is None or sha256 not in available: raise FindingError("consulted_evidence_invalid")
        if after == "validated":
            if method == "reasoning_only" or not consulted: raise FindingError("validation_evidence_required")
            if candidate.get("claim_requires_execution") and method != "re_executed":
                raise FindingError("execution_reverification_required")
            snapshots = snapshot_reports(
                finding_id, {key: available[key] for key in consulted}, state,
                known_evidence=available,
            )
        else: snapshots = []
        result = {"event":"state_changed","finding_id":finding_id,"from_state":before,"to_state":after,
                "verification_method":method,"consulted_evidence":consulted,"evidence_snapshots":snapshots,
                "actor":adjudicator,"rationale":rationale,"conflict_note":conflict}
        if after in TERMINAL:
            # Freeze what was already known when the finding became terminal.
            # Reopen freshness must not depend on wall-clock ordering.
            result["terminal_evidence_sha256"] = sorted(available)
            result["terminal_report_content_sha256"] = sorted({
                item["content_sha256"] for item in available.values()
                if item.get("class") == "report_reference"
            })
        return result
    if action == "relation":
        finding_id, adjudicator, rationale, conflict = base_request(
            request, {"action","finding_id","relation","target_finding_id","actor","rationale","conflict_note"})
        load_candidate(finding_id, state); target = canonical_uuid4(request["target_finding_id"], "target_finding_id")
        load_candidate(target, state)
        if target == finding_id or request["relation"] not in RELATIONS: raise FindingError("relation_invalid")
        return {"event":"relation_added","finding_id":finding_id,"relation":request["relation"],
                "target_finding_id":target,"actor":adjudicator,"rationale":rationale,"conflict_note":conflict}
    if action == "reopen":
        finding_id, adjudicator, rationale, conflict = base_request(
            request, {"action","finding_id","new_evidence_sha256","actor","rationale","conflict_note"})
        candidate = load_candidate(finding_id, state); amendments = load_amendments(finding_id, state)
        if current_state(finding_id, events) not in TERMINAL: raise FindingError("reopen_invalid")
        digest = request["new_evidence_sha256"]
        terminal_event = next((event for event in reversed(events)
            if event.get("finding_id") == finding_id and event.get("event") == "state_changed"
            and event.get("to_state") in TERMINAL), None)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or terminal_event is None:
            raise FindingError("reopen_evidence_required")
        terminal_inventory = terminal_event.get("terminal_evidence_sha256")
        if terminal_inventory is not None:
            if (not isinstance(terminal_inventory, list) or len(terminal_inventory) > 272
                    or len(set(terminal_inventory)) != len(terminal_inventory)
                    or any(not isinstance(item, str) or not SHA256_RE.fullmatch(item)
                           for item in terminal_inventory)):
                raise FindingError("adjudication_journal_invalid")
            earlier = set(terminal_inventory)
            report_inventory = terminal_event.get("terminal_report_content_sha256")
            if (not isinstance(report_inventory, list) or len(report_inventory) > 272
                    or len(set(report_inventory)) != len(report_inventory)
                    or any(not isinstance(item, str) or not SHA256_RE.fullmatch(item)
                           for item in report_inventory)):
                raise FindingError("adjudication_journal_invalid")
            earlier_report_content = set(report_inventory)
        else:
            # Compatibility for journal entries written before the inventory was
            # introduced. This fallback is deliberately fail-closed on malformed
            # timestamps; all new events use the clock-independent inventory.
            cutoff = terminal_event.get("recorded_at")
            if not isinstance(cutoff, str): raise FindingError("adjudication_journal_invalid")
            try: cutoff_time = datetime.fromisoformat(cutoff.replace("Z", "+00:00"))
            except ValueError as error: raise FindingError("adjudication_journal_invalid") from error
            earlier = {hashlib.sha256(canonical(item)).hexdigest() for item in candidate.get("evidence", [])}
            earlier_report_content = {
                item["content_sha256"] for item in candidate.get("evidence", [])
                if item.get("class") == "report_reference"
            }
            for amendment in amendments:
                try: submitted = datetime.fromisoformat(str(amendment.get("submitted_at", "")).replace("Z", "+00:00"))
                except ValueError as error: raise FindingError("finding_record_invalid") from error
                if submitted <= cutoff_time:
                    earlier.update(hashlib.sha256(canonical(item)).hexdigest()
                                   for item in amendment.get("evidence", []))
                    earlier_report_content.update(
                        item["content_sha256"] for item in amendment.get("evidence", [])
                        if item.get("class") == "report_reference"
                    )
        available = all_evidence(candidate, amendments)
        selected = available.get(digest)
        if (selected is None or digest in earlier
                or (selected.get("class") == "report_reference"
                    and selected.get("content_sha256") in earlier_report_content)):
            raise FindingError("reopen_evidence_required")
        return {"event":"reopened","finding_id":finding_id,"new_evidence_sha256":digest,
                "actor":adjudicator,"rationale":rationale,"conflict_note":conflict}
    raise FindingError("action_invalid")


def append_event(request: dict[str, Any], state: Path = STATE_DIR) -> dict[str, Any]:
    journal = state / "adjudication" / "journal.jsonl"
    journal.parent.mkdir(mode=0o750, exist_ok=True)
    lock_path = state / "adjudication" / ".lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        events = verify_journal(journal)
        value = build_event(request, events, state)
        value.update(schema=JOURNAL_SCHEMA, event_id=str(uuid.uuid4()), seq=len(events)+1,
                     prev_entry_sha256=events[-1]["entry_sha256"] if events else "0"*64, recorded_at=now(),
                     authority="operator_adjudication")
        value["entry_sha256"] = hashlib.sha256(canonical(value)).hexdigest()
        descriptor = os.open(journal, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
        with os.fdopen(descriptor, "ab") as handle:
            handle.write(canonical(value)+b"\n"); handle.flush(); os.fsync(handle.fileno())
        if os.geteuid() == 0: os.chown(journal, 0, journal.parent.stat().st_gid)
        os.chmod(journal, 0o640)
        directory = os.open(journal.parent, os.O_RDONLY | os.O_DIRECTORY); os.fsync(directory); os.close(directory)
        return {"status":"recorded","finding_id":value["finding_id"],"event_id":value["event_id"],
                "entry_sha256":value["entry_sha256"],"authority":"operator_adjudication"}


def disposition(request: dict[str, Any], state: Path = STATE_DIR) -> dict[str, Any]:
    if set(request) != {"action","finding_id","actor","rationale","conflict_note"} or request.get("action") != "dispose":
        raise FindingError("adjudication_schema_invalid")
    finding_id, adjudicator, rationale, conflict = base_request(request, set(request))
    events = verify_journal(state/"adjudication"/"journal.jsonl")
    terminal = current_state(finding_id, events)
    if terminal not in TERMINAL: raise FindingError("disposition_requires_terminal_state")
    source = state/"candidates"/f"{finding_id}.json"; destination = state/"archive"/finding_id
    if destination.exists():
        archived = load_json(destination/"candidate.json", "secure-sandbox-candidate-finding-v1")
        marker = load_json(destination/"disposition.json", "secure-sandbox-finding-disposition-v1")
        if archived.get("finding_id") != finding_id or marker.get("finding_id") != finding_id or marker.get("state") != terminal:
            raise FindingError("disposition_archive_invalid")
    else:
        if not source.is_file() or source.is_symlink(): raise FindingError("finding_not_available")
        candidate = load_json(source, "secure-sandbox-candidate-finding-v1")
        temporary = state/"archive"/f".{finding_id}.new"
        if temporary.exists():
            info = temporary.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != TRUSTED_UID:
                raise FindingError("disposition_archive_invalid")
            shutil.rmtree(temporary)
        temporary.mkdir(mode=0o700)
        amendment_dir = temporary/"amendments"; amendment_dir.mkdir(mode=0o700)
        records = [(source, candidate, temporary/"candidate.json")]
        for item in (state/"amendments").iterdir():
            try: value = load_json(item, "secure-sandbox-finding-amendment-v1")
            except Exception: continue
            if value.get("finding_id") == finding_id: records.append((item, value, amendment_dir/item.name))
        for _, value, target in records:
            with target.open("xb") as handle:
                handle.write(canonical(value)+b"\n"); handle.flush(); os.fsync(handle.fileno())
            if os.geteuid() == 0: os.chown(target, 0, 0)
            os.chmod(target, 0o400)
        marker = {"schema":"secure-sandbox-finding-disposition-v1","finding_id":finding_id,"state":terminal,
                  "actor":adjudicator,"rationale":rationale,"conflict_note":conflict,"disposed_at":now()}
        marker["content_sha256"] = hashlib.sha256(canonical(marker)).hexdigest()
        with (temporary/"disposition.json").open("xb") as handle:
            handle.write(canonical(marker)+b"\n"); handle.flush(); os.fsync(handle.fileno())
        if os.geteuid() == 0: os.chown(temporary/"disposition.json", 0, 0)
        os.chmod(temporary/"disposition.json", 0o400)
        for directory in (amendment_dir, temporary):
            if os.geteuid() == 0: os.chown(directory, 0, 0)
            os.chmod(directory, 0o700)
            descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY); os.fsync(descriptor); os.close(descriptor)
        os.replace(temporary, destination)
        descriptor=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY); os.fsync(descriptor); os.close(descriptor)
    if source.exists():
        current = load_json(source, "secure-sandbox-candidate-finding-v1")
        archived = load_json(destination/"candidate.json", "secure-sandbox-candidate-finding-v1")
        if current["content_sha256"] != archived["content_sha256"]: raise FindingError("disposition_archive_invalid")
        source.unlink()
    for item in (state/"amendments").iterdir():
        try: value = load_json(item, "secure-sandbox-finding-amendment-v1")
        except Exception: continue
        if value.get("finding_id") == finding_id:
            archived = destination/"amendments"/item.name
            if load_json(archived,"secure-sandbox-finding-amendment-v1")["content_sha256"] != value["content_sha256"]:
                raise FindingError("disposition_archive_invalid")
            item.unlink()
    for directory in (state/"candidates",state/"amendments"):
        descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY); os.fsync(descriptor); os.close(descriptor)
    return {"status":"disposed","finding_id":finding_id,"terminal_state":terminal,
            "content_sha256":marker["content_sha256"],"authority":"operator_adjudication"}


def disposition_status(finding_id: str, state: Path = STATE_DIR) -> dict[str, Any]:
    finding_id = canonical_uuid4(finding_id, "finding_id")
    archived = state / "archive" / finding_id
    marker = load_json(archived / "disposition.json", "secure-sandbox-finding-disposition-v1")
    candidate = load_json(archived / "candidate.json", "secure-sandbox-candidate-finding-v1")
    if (marker.get("finding_id") != finding_id or candidate.get("finding_id") != finding_id
            or marker.get("state") not in TERMINAL):
        raise FindingError("disposition_archive_invalid")
    return {"schema":"secure-sandbox-finding-disposition-status-v1",
            "finding_id":finding_id,"state":marker["state"],
            "content_sha256":marker["content_sha256"],
            "candidate_sha256":candidate["content_sha256"]}


def list_findings(state: Path = STATE_DIR) -> list[dict[str, Any]]:
    try: events = verify_journal(state/"adjudication"/"journal.jsonl")
    except Exception as error: events=[]; journal_error=type(error).__name__
    else: journal_error=""
    result=[]
    locations=[("active",state/"candidates"),("archived",state/"archive")]
    for disposition_name,directory in locations:
        if not directory.exists(): continue
        items = directory.iterdir()
        for item in sorted(items):
            path = item/"candidate.json" if item.is_dir() else item
            try:
                value=load_json(path,"secure-sandbox-candidate-finding-v1"); fid=canonical_uuid4(value["finding_id"],"finding_id")
                result.append({"finding_id":fid,"submitted_at":value["submitted_at"],"proposed_severity":value["proposed_severity"],
                               "state":current_state(fid,events),"disposition":disposition_name,"content_sha256":value["content_sha256"],
                               "journal_error":journal_error})
            except Exception as error:
                result.append({"record":path.name,"state":"invalid","error":type(error).__name__,"journal_error":journal_error})
    return result


def show_finding(finding_id: str, state: Path = STATE_DIR) -> dict[str, Any]:
    finding_id=canonical_uuid4(finding_id,"finding_id"); candidate=load_candidate(finding_id,state)
    amendments=load_amendments(finding_id,state); events=verify_journal(state/"adjudication"/"journal.jsonl")
    return {"candidate":candidate,"amendments":amendments,"events":[e for e in events if e.get("finding_id")==finding_id],
            "current_state":current_state(finding_id,events)}


def main() -> None:
    require_root()
    try:
        if len(sys.argv)==2 and sys.argv[1]=="list": output=list_findings()
        elif len(sys.argv)==3 and sys.argv[1]=="show": output=show_finding(sys.argv[2])
        elif len(sys.argv)==3 and sys.argv[1]=="disposition-status": output=disposition_status(sys.argv[2])
        elif len(sys.argv)==3 and sys.argv[1]=="apply":
            request_path=Path(sys.argv[2]); info=request_path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size>16*1024: raise FindingError("request_file_invalid")
            request=json.loads(request_path.read_text())
            if not isinstance(request,dict): raise FindingError("adjudication_schema_invalid")
            output=disposition(request) if request.get("action")=="dispose" else append_event(request)
        else: raise SystemExit("usage: finding_admin.py list | show FINDING_ID | apply REQUEST.json")
        print(json.dumps(output,ensure_ascii=False,separators=(",",":"),sort_keys=True))
    except (FindingError,OSError,ValueError,json.JSONDecodeError) as error:
        print(json.dumps({"status":"rejected","error":str(error) or "adjudication_invalid"},separators=(",",":"),sort_keys=True))
        raise SystemExit(2)


if __name__ == "__main__": main()
