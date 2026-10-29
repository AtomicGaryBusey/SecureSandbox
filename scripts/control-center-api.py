#!/usr/bin/env python3
"""Bounded, read-only, versioned host catalog for the Control Center app."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import selectors
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
LABCTL = ROOT / "scripts" / "labctl"
SCHEMA = "secure-sandbox-control-center-v1"
MAX_OUTPUT = 8 * 1024 * 1024
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def host_error(raw: bytes, status: int) -> str:
    messages = {
        "github_status_422": "GitHub did not accept that ref. Check the branch or tag name.",
        "github_status_404": "The public repository or ref was not found.",
        "github_status_403": "GitHub denied the source lookup. Try again after its rate limit resets.",
        "endpoint_unavailable": "The Gateway could not reach its pinned source endpoint.",
        "fetcher_failed": "The Gateway source fetcher failed. Check source acquisition diagnostics.",
    }
    for line in reversed(raw.decode("utf-8", "replace").splitlines()[-12:]):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == "secure-sandbox-host-lifecycle-v1":
            phase = value.get("phase")
            failures = value.get("action_failures")
            if (isinstance(phase, str) and re.fullmatch(r"[a-z_]{1,40}", phase)
                    and isinstance(failures, list) and 0 < len(failures) <= 10
                    and all(isinstance(item, str) and re.fullmatch(r"[a-z_]{1,80}", item) for item in failures)):
                return (f"The VM transition stopped during {phase}: {', '.join(failures)}. "
                        "Refresh live status before another action.")
        code = value.get("error") if isinstance(value, dict) else None
        if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,80}", code):
            return messages.get(code, f"The host rejected the operation ({code}).")
    return f"The host operation failed with status {status}."


def run_labctl(*args: str) -> str:
    # No shell. Callers validate every variable argument before this boundary.
    timeout = (1200 if args in (("start",), ("stop",))
               else 600 if args[:2] in (("source", "apply"), ("dependencies", "apply"), ("corpus", "index"), ("codegraph", "index")) or args == ("verify",)
               else 330 if args[:2] == ("source", "plan")
               else 180 if args == ("artifacts",) or args[:1] == ("artifact",)
               else 30)
    completed = bounded_command([str(LABCTL), *args], timeout=timeout)
    if completed.returncode:
        raise RuntimeError(host_error(completed.stderr[-4096:], completed.returncode))
    return completed.stdout.decode("utf-8", "strict")


def bounded_command(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True)
    assert process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    selector.register(process.stderr, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.fileobj is process.stdout:
                    stdout.extend(chunk)
                    if len(stdout) > MAX_OUTPUT:
                        raise ValueError("catalog response exceeds its size limit")
                else:
                    stderr.extend(chunk)
                    if len(stderr) > 4096:
                        del stderr[:-4096]
        process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(command, process.returncode, bytes(stdout), bytes(stderr))
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()


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
    if name == "maintenance":
        return maintenance()
    raw = run_labctl({"overview": "status", "sessions": "sessions", "sources": "sources", "findings": "findings", "activity": "logs", "artifacts": "artifacts"}[name])
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
    if name == "artifacts":
        rows = table(raw, 6)
        if any(UUID.fullmatch(row[1]) is None or UUID.fullmatch(row[4]) is None
               or re.fullmatch(r"v[1-9][0-9]{0,8}", row[2]) is None
               or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(md|txt|json)", row[3]) is None
               or re.fullmatch(r"[0-9a-f]{64}", row[5]) is None for row in rows):
            raise ValueError("Artifact catalog identity is invalid")
        return [dict(zip(("captured_at", "id", "version", "file_name", "run_id", "sha256"), row)) for row in rows]
    if name == "activity":
        lines = raw.splitlines()
        if len(lines) > 1_000:
            raise ValueError("activity catalog exceeds its record limit")
        events = []
        for sequence, line in enumerate(lines):
            row = json.loads(line)
            if (not isinstance(row, dict) or not isinstance(row.get("TimeGenerated"), str)
                    or not isinstance(row.get("EventType"), str)
                    or not isinstance(row.get("Severity"), str)):
                raise ValueError("activity record is invalid")
            event = {key: row.get(key) for key in
                     ("TimeGenerated", "EventType", "Severity", "Decision", "Status", "VmId", "Message")}
            event["sequence"] = sequence
            if any(isinstance(value, str) and len(value) > 500 for value in event.values()):
                raise ValueError("activity field exceeds its size limit")
            events.append(event)
        return events
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) > 10_000 or any(not isinstance(row, dict) or UUID.fullmatch(str(row.get("finding_id", ""))) is None for row in value):
        raise ValueError("findings catalog is invalid")
    return value


def maintenance() -> dict[str, str]:
    result = {}
    try:
        check_time_output(run_labctl("time-sync"))
        result["time_sync"] = "verified"
    except (RuntimeError, ValueError):
        result["time_sync"] = "attention"
    try:
        raw = run_labctl("snapshots")
        if len(raw.splitlines()) != 3:
            raise ValueError("snapshot response is invalid")
        result["snapshot_policy"] = "verified"
    except (RuntimeError, ValueError):
        result["snapshot_policy"] = "attention"
    return result


def check_time_output(raw: str) -> None:
    lines = raw.splitlines()
    names = ("sandbox-gateway", "sandbox-research-admin", "sandbox-target-admin")
    matches = [re.fullmatch(re.escape(name) + r": skew=([0-9]+)s", line)
               for name, line in zip(names, lines[:3])]
    if (len(lines) != 4 or len(matches) != 3 or any(match is None or int(match[1]) > 5 for match in matches)
            or lines[-1] != "SecureSandbox guest clocks are within 5s of the Mac."):
        raise ValueError("Time synchronization response is invalid")


def apply_time_sync() -> dict[str, str]:
    overview = catalog("overview")
    if overview["status"] != "verified" or any(
            overview["observed"][vm] != "running" for vm in ("gateway", "research", "target")):
        raise ValueError("All three VMs must be running before clock synchronization")
    check_time_output(run_labctl("time-sync", "--apply"))
    check_time_output(run_labctl("time-sync"))
    return {"status": "verified", "operation": "time-sync"}


def safety_audit() -> dict[str, str | bool | int]:
    completed = subprocess.run([str(LABCTL), "safety-audit"], cwd=ROOT,
                               capture_output=True, check=False, timeout=600)
    if len(completed.stdout) > MAX_OUTPUT:
        raise ValueError("Safety audit response exceeds its size limit")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict) or value.get("schema") != "secure-sandbox-external-containment-audit-v1":
        raise ValueError("Safety audit schema is invalid")
    host = value.get("host_direct")
    secure = value.get("secure_sandbox_launch_path")
    if (not isinstance(host, dict) or not isinstance(secure, dict)
            or not isinstance(host.get("posture_tier"), int)
            or not isinstance(secure.get("verified"), bool)):
        raise ValueError("Safety audit posture is invalid")
    verified = secure["verified"] and completed.returncode == 0
    error = secure.get("error", "")
    if verified:
        detail = "The protected launch path and off-host evidence are verified."
    elif isinstance(error, str) and "active_release_source_mismatch" in error:
        detail = "The installed protected controller differs from reviewed source; deployment and verification are pending."
    else:
        detail = "The complete protected launch posture is not verified; inspect the operator audit."
    return {"verified": verified, "host_direct_tier": host["posture_tier"], "detail": detail}


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


def plan_npm(package: str, version: str) -> dict[str, str]:
    if (re.fullmatch(r"(@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}", package) is None
            or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?", version) is None):
        raise ValueError("Enter an exact npm package name and semantic version")
    raw = run_labctl("source", "npm-plan", package, version)
    lines = [line.split(":", 1) for line in raw.splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("npm plan response is invalid")
    fields = {key.strip(): value.strip() for key, value in lines}
    if (set(fields) != {"Plan", "Package", "Version", "Integrity", "Expires"}
            or UUID.fullmatch(fields["Plan"]) is None
            or fields["Package"] != package or fields["Version"] != version
            or SHA.fullmatch(fields["Integrity"]) is None):
        raise ValueError("npm plan identity is invalid")
    repository = f"npm/{package[1:].replace('/', '--') if package.startswith('@') else package}"
    return {"plan_id": fields["Plan"], "repository": repository,
            "requested_ref": version, "resolved_commit": fields["Integrity"],
            "expires_at": fields["Expires"]}


def label_session(session_id: str, label: str) -> dict[str, str]:
    if UUID.fullmatch(session_id) is None:
        raise ValueError("A canonical session ID is required")
    if (not label or label != label.strip() or len(label.encode("utf-8")) > 120
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in label)):
        raise ValueError("The label must be 1–120 UTF-8 bytes without control characters")
    raw = run_labctl("session", "label", session_id, label)
    if raw != f"labeled\t{session_id}\t{label}\n":
        raise ValueError("Session label response is invalid")
    return {"session_id": session_id, "label": label}


def unlabel_session(session_id: str) -> dict[str, str]:
    if UUID.fullmatch(session_id) is None:
        raise ValueError("A canonical session ID is required")
    raw = run_labctl("session", "unlabel", session_id)
    if raw != f"unlabeled\t{session_id}\n":
        raise ValueError("Session unlabel response is invalid")
    return {"session_id": session_id, "label": ""}


def source_status(plan_id: str) -> dict[str, str]:
    if UUID.fullmatch(plan_id) is None:
        raise ValueError("A canonical plan ID is required")
    value = json.loads(run_labctl("source", "status", plan_id))
    if (not isinstance(value, dict)
            or value.get("schema") != "secure-sandbox-source-plan-status-v1"
            or value.get("plan_id") != plan_id
            or value.get("state") not in {"planned", "claimed", "fetched", "exported", "failed", "expired", "completed"}
            or SHA.fullmatch(str(value.get("resolved_commit", ""))) is None):
        raise ValueError("Source plan status is invalid")
    if value["state"] == "completed" and UUID.fullmatch(str(value.get("source_id", ""))) is None:
        raise ValueError("Completed source identity is invalid")
    return value


def apply_source(plan_id: str) -> dict[str, str]:
    before = source_status(plan_id)
    if before["state"] != "planned":
        raise ValueError("This source plan is no longer available for import")
    raw = run_labctl("source", "apply", plan_id)
    lines = [line.split(":", 1) for line in raw.splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("Source import response is invalid; inspect the plan status before another action")
    fields = {key.strip(): value.strip() for key, value in lines}
    after = source_status(plan_id)
    if (set(fields) != {"Source", "Baseline", "Repository", "Index", "Evidence"}
            or after["state"] != "completed" or fields["Source"] != after["source_id"]
            or fields["Index"] != "repos/INDEX.json"
            or fields["Evidence"] != "archived and verified"):
        raise ValueError("Source import outcome is ambiguous; inspect the plan status")
    return {"plan_id": plan_id, "source_id": after["source_id"], "repository": after["repository"]}


def finding_detail(finding_id: str) -> dict:
    if UUID.fullmatch(finding_id) is None:
        raise ValueError("A canonical finding ID is required")
    value = json.loads(run_labctl("finding", "show", finding_id))
    if not isinstance(value, dict) or set(value) != {"candidate", "amendments", "events", "current_state"}:
        raise ValueError("Finding detail response is invalid")
    candidate = value["candidate"]
    if (not isinstance(candidate, dict) or candidate.get("finding_id") != finding_id
            or not isinstance(value["amendments"], list)
            or not isinstance(value["events"], list)
            or not isinstance(value["current_state"], str)
            or not isinstance(candidate.get("evidence"), list)
            or len(value["amendments"]) > 1_000 or len(value["events"]) > 1_000):
        raise ValueError("Finding identity or history is invalid")
    fields = ("claim", "counterargument", "limitations", "claim_evidence_support",
              "proposed_severity", "submitted_at")
    if any(not isinstance(candidate.get(key), str) or len(candidate[key]) > 32_000 for key in fields):
        raise ValueError("Finding text is invalid")
    return {"finding_id": finding_id, "current_state": value["current_state"],
            **{key: candidate[key] for key in fields},
            "evidence_count": len(candidate.get("evidence", [])),
            "amendment_count": len(value["amendments"]), "event_count": len(value["events"])}


def artifact_detail(artifact_id: str) -> dict[str, str]:
    if UUID.fullmatch(artifact_id) is None:
        raise ValueError("A canonical artifact ID is required")
    raw = run_labctl("artifact", artifact_id)
    lines = raw.split("\n", 6)
    if len(lines) != 7 or lines[0] != f"Artifact: {artifact_id}" or lines[5] != "---":
        raise ValueError("Artifact rendering is invalid")
    fields = [line.split(": ", 1) for line in lines[1:5]]
    if any(len(field) != 2 for field in fields) or [field[0] for field in fields] != ["Captured", "Source", "Run", "SHA-256"]:
        raise ValueError("Artifact metadata is invalid")
    source = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]{0,126}\.(?:md|txt|json)) \(version ([1-9][0-9]{0,8})\)", fields[1][1])
    if (source is None or UUID.fullmatch(fields[2][1]) is None
            or re.fullmatch(r"[0-9a-f]{64}", fields[3][1]) is None
            or len(lines[6].encode("utf-8")) > 4 * 1024 * 1024):
        raise ValueError("Artifact content or identity is invalid")
    return {"id": artifact_id, "captured_at": fields[0][1], "file_name": source[1],
            "version": source[2], "run_id": fields[2][1], "sha256": fields[3][1],
            "content": lines[6]}


def dependency_rows(raw: str) -> list[dict[str, str]]:
    rows = table(raw, 4)
    if len(rows) > 1_000:
        raise ValueError("Dependency plan exceeds its row limit")
    for state, package, version, source_id in rows:
        if (state not in {"READY", "MISSING"}
                or re.fullmatch(r"(@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,127}", package) is None
                or re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?", version) is None
                or (source_id != "-" and UUID.fullmatch(source_id) is None)
                or (state == "READY") != (source_id != "-")):
            raise ValueError("Dependency row is invalid")
    return [dict(zip(("state", "package", "version", "source_id"), row)) for row in rows]


def dependency_plan(source_id: str) -> dict:
    if UUID.fullmatch(source_id) is None:
        raise ValueError("A canonical source ID is required")
    lines = run_labctl("dependencies", "plan", source_id).splitlines()
    if len(lines) < 4:
        raise ValueError("Dependency plan is incomplete")
    header = [line.split(":", 1) for line in lines[:4]]
    if any(len(field) != 2 for field in header):
        raise ValueError("Dependency plan header is invalid")
    fields = {key.strip(): value.strip() for key, value in header}
    root = fields.get("Root", "").rsplit("@", 1)
    if (set(fields) != {"Plan", "Root", "Set SHA256", "Expires"}
            or UUID.fullmatch(fields["Plan"]) is None
            or len(root) != 2 or not root[0] or not root[1]
            or re.fullmatch(r"[0-9a-f]{64}", fields["Set SHA256"]) is None):
        raise ValueError("Dependency plan identity is invalid")
    return {"plan_id": fields["Plan"], "root": fields["Root"],
            "dependency_set_sha256": fields["Set SHA256"], "expires_at": fields["Expires"],
            "dependencies": dependency_rows("\n".join(lines[4:]))}


def dependency_status(plan_id: str) -> dict:
    if UUID.fullmatch(plan_id) is None:
        raise ValueError("A canonical dependency plan ID is required")
    return {"plan_id": plan_id,
            "dependencies": dependency_rows(run_labctl("dependencies", "status", plan_id))}


def dependency_bundles() -> list[dict[str, str]]:
    rows = table(run_labctl("dependencies", "list"), 5)
    if any(UUID.fullmatch(row[1]) is None or re.fullmatch(r"[0-9]{1,5}", row[3]) is None
           or re.fullmatch(r"[0-9a-f]{64}", row[4]) is None for row in rows):
        raise ValueError("Dependency bundle catalog is invalid")
    return [dict(zip(("created_at", "id", "root", "dependency_count", "dependency_set_sha256"), row)) for row in rows]


def dependency_apply(plan_id: str, expected_digest: str) -> dict[str, str]:
    if UUID.fullmatch(plan_id) is None or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise ValueError("Dependency plan identity is invalid")
    before = dependency_status(plan_id)
    if any(item["state"] != "READY" for item in before["dependencies"]):
        raise ValueError("Import the missing exact package versions before assembling the bundle")
    lines = [line.split(":", 1) for line in run_labctl("dependencies", "apply", plan_id).splitlines()]
    if len(lines) != 5 or any(len(line) != 2 for line in lines):
        raise ValueError("Dependency assembly response is invalid; inspect bundle catalog")
    fields = {key.strip(): value.strip() for key, value in lines}
    if (set(fields) != {"Bundle", "Root", "Dependencies", "Set SHA256", "Lifecycle"}
            or UUID.fullmatch(fields["Bundle"]) is None
            or fields["Set SHA256"] != expected_digest or fields["Lifecycle"] != "disabled"
            or not fields["Dependencies"].isdigit()
            or int(fields["Dependencies"]) != len(before["dependencies"])):
        raise ValueError("Dependency assembly outcome is invalid; inspect bundle catalog")
    matches = [item for item in dependency_bundles() if item["id"] == fields["Bundle"]]
    if len(matches) != 1 or matches[0]["dependency_set_sha256"] != expected_digest:
        raise ValueError("Dependency bundle readback did not match the plan")
    return {"bundle_id": fields["Bundle"], "root": fields["Root"],
            "dependency_set_sha256": expected_digest, "dependency_count": fields["Dependencies"]}


def index_source(kind: str, source_id: str) -> dict[str, str | int]:
    if kind not in {"corpus", "codegraph"} or UUID.fullmatch(source_id) is None:
        raise ValueError("A selected source and supported index are required")
    value = json.loads(run_labctl(kind, "index", source_id))
    schema = ("secure-sandbox-corpus-index-v1" if kind == "corpus"
              else "secure-sandbox-codegraph-index-v1")
    digest_key = "index_content_sha256" if kind == "corpus" else "codegraph_index_sha256"
    count_key = "indexed_documents" if kind == "corpus" else "nodes_created"
    if (not isinstance(value, dict) or value.get("schema") != schema
            or value.get("source_id") != source_id or value.get("status") != "indexed"
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get(digest_key, ""))) is None
            or not isinstance(value.get(count_key), int) or value[count_key] < 0):
        raise ValueError("Sealed index result is invalid")
    return {"kind": kind, "source_id": source_id, "status": "indexed",
            "digest": value[digest_key], "item_count": value[count_key]}


def vm_footprint() -> dict[str, int]:
    result = {}
    for role in ("Gateway", "Research", "Target"):
        root = ROOT / "vms" / f"SecureSandbox-{role}.pvm"
        if not stat.S_ISDIR(root.lstat().st_mode):
            raise ValueError("A VM bundle is missing or is not a directory")
        total = 0
        for base, directories, files in os.walk(root, followlinks=False):
            for name in directories + files:
                mode = (Path(base) / name).lstat().st_mode
                if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise ValueError("A VM bundle contains an unsupported entry")
                if stat.S_ISREG(mode):
                    total += (Path(base) / name).lstat().st_size
        result[role.lower()] = total
    return result


def destination_volume(path: Path) -> dict[str, str | bool]:
    output = subprocess.run(["/bin/df", "-P", str(path)], capture_output=True,
                            check=True, timeout=10).stdout.decode("ascii", "strict").splitlines()
    if len(output) != 2:
        raise ValueError("Destination volume could not be identified")
    device = output[1].split()[0]
    if re.fullmatch(r"/dev/disk[0-9]+s[0-9]+", device) is None:
        raise ValueError("Destination must be on a local APFS volume")
    info = plistlib.loads(subprocess.run(["/usr/sbin/diskutil", "info", "-plist", device],
                                        capture_output=True, check=True, timeout=10).stdout)
    if not isinstance(info, dict) or info.get("FilesystemName") != "APFS":
        raise ValueError("Destination must be on APFS")
    volume_id = info.get("VolumeUUID")
    if not isinstance(volume_id, str) or re.fullmatch(
            r"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", volume_id) is None:
        raise ValueError("Destination volume identity is unavailable")
    encrypted = (info.get("Encryption") is True
                 and info.get("EncryptionThisVolumeProper") is True
                 and info.get("FileVault") is True)
    return {"volume_uuid": volume_id, "encrypted": encrypted}


def backup_preflight(destination: str) -> dict:
    if not destination.startswith("/") or len(destination) > 1024:
        raise ValueError("Select an existing absolute destination folder")
    if Path(destination).is_symlink():
        raise ValueError("Select a destination folder, not a symbolic link")
    path = Path(destination).resolve(strict=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError("Select an existing destination folder")
    vms = ROOT / "vms"
    if path == vms or vms in path.parents:
        raise ValueError("A VM bundle cannot contain its own backup")
    sizes = vm_footprint()
    logical_bytes = sum(sizes.values())
    free_bytes = os.statvfs(path).f_bavail * os.statvfs(path).f_frsize
    reserve_bytes = max(10 * 1024**3, logical_bytes // 10)
    volume = destination_volume(path)
    observed = catalog("overview")
    stopped = observed["status"] == "verified" and all(
        observed["observed"][role] == "stopped" for role in ("gateway", "research", "target"))
    return {"destination": str(path), "volume_uuid": volume["volume_uuid"],
            "encrypted": volume["encrypted"], "free_bytes": free_bytes,
            "logical_bytes": logical_bytes, "reserve_bytes": reserve_bytes,
            "vm_bytes": sizes, "stack_stopped": stopped,
            "ready": bool(volume["encrypted"] and free_bytes >= logical_bytes + reserve_bytes and stopped)}


def verify_boundaries() -> dict[str, int | str]:
    raw = run_labctl("verify")
    lines = raw.splitlines()
    if not lines or lines[-1] != "BOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use.":
        raise ValueError("Boundary verification did not return its success marker")
    passed = sum(line.startswith("PASS  ") for line in lines)
    gates = sum(line.startswith("GATE  ") for line in lines)
    if passed < 1:
        raise ValueError("Boundary verification has no passed checks")
    return {"status": "verified", "passed_checks": passed, "gate_notices": gates}


def lifecycle(operation: str) -> dict[str, str]:
    if operation not in ("start", "stop"):
        raise ValueError("Unsupported lifecycle action")
    before = catalog("overview")
    if before["status"] != "verified":
        raise ValueError("The current VM state is not verified")
    gui = subprocess.run(["/usr/bin/pgrep", "-x", "prl_client_app"],
                         capture_output=True, timeout=5, check=False)
    if gui.returncode == 0:
        raise ValueError("Quit Parallels Desktop before changing VM state")
    if gui.returncode != 1:
        raise ValueError("Parallels Desktop state could not be checked")
    raw = run_labctl(operation)
    try:
        result = json.loads(raw.splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise ValueError("Lifecycle completion record is missing") from error
    if (not isinstance(result, dict) or result.get("schema") != "secure-sandbox-host-lifecycle-v1"
            or result.get("operation") != operation or result.get("status") != "verified"
            or result.get("phase") != "complete"):
        raise ValueError("Lifecycle completion was not verified")
    after = catalog("overview")
    expected = "running" if operation == "start" else "stopped"
    if (after["status"] != "verified"
            or any(after["observed"][vm] != expected for vm in ("gateway", "research", "target"))):
        raise ValueError("The independent VM state readback did not match the requested state")
    if operation == "start" and (after["observed"].get("gateway_net0") != "connected"
            or any(after.get("reachability", {}).get(vm) != "reachable"
                   for vm in ("gateway", "research", "target"))):
        raise ValueError("Start completed but uplink or guest reachability is incomplete")
    return {"operation": operation, "status": "verified", "gateway": expected,
            "research": expected, "target": expected}


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    catalog_parser = subparsers.add_parser("catalog")
    catalog_parser.add_argument("name", choices=("overview", "sessions", "sources", "findings", "artifacts", "activity", "maintenance"))
    plan_parser = subparsers.add_parser("plan-source")
    plan_parser.add_argument("url")
    plan_parser.add_argument("ref")
    npm_parser = subparsers.add_parser("plan-npm")
    npm_parser.add_argument("package")
    npm_parser.add_argument("version")
    label_parser = subparsers.add_parser("label-session")
    label_parser.add_argument("session_id")
    label_parser.add_argument("label")
    unlabel_parser = subparsers.add_parser("unlabel-session")
    unlabel_parser.add_argument("session_id")
    status_parser = subparsers.add_parser("source-status")
    status_parser.add_argument("plan_id")
    apply_parser = subparsers.add_parser("apply-source")
    apply_parser.add_argument("plan_id")
    finding_parser = subparsers.add_parser("finding-detail")
    finding_parser.add_argument("finding_id")
    artifact_parser = subparsers.add_parser("artifact-detail")
    artifact_parser.add_argument("artifact_id")
    subparsers.add_parser("verify-boundaries")
    lifecycle_parser = subparsers.add_parser("lifecycle")
    lifecycle_parser.add_argument("operation", choices=("start", "stop"))
    dependency_parser = subparsers.add_parser("dependency-plan")
    dependency_parser.add_argument("source_id")
    dependency_status_parser = subparsers.add_parser("dependency-status")
    dependency_status_parser.add_argument("plan_id")
    dependency_apply_parser = subparsers.add_parser("dependency-apply")
    dependency_apply_parser.add_argument("plan_id")
    dependency_apply_parser.add_argument("expected_digest")
    subparsers.add_parser("dependency-bundles")
    index_parser = subparsers.add_parser("index-source")
    index_parser.add_argument("kind", choices=("corpus", "codegraph"))
    index_parser.add_argument("source_id")
    backup_parser = subparsers.add_parser("backup-preflight")
    backup_parser.add_argument("destination")
    subparsers.add_parser("apply-time-sync")
    subparsers.add_parser("safety-audit")
    args = parser.parse_args()
    name = {"catalog": getattr(args, "name", None), "plan-source": "source-plan",
            "plan-npm": "source-plan",
            "label-session": "session-label", "unlabel-session": "session-label",
            "source-status": "source-status",
            "apply-source": "source-import", "finding-detail": "finding-detail",
            "artifact-detail": "artifact-detail", "verify-boundaries": "boundary-verification",
            "lifecycle": "lifecycle", "dependency-plan": "dependency-plan",
            "dependency-status": "dependency-status", "dependency-apply": "dependency-apply",
            "dependency-bundles": "dependency-bundles", "index-source": "source-index",
            "backup-preflight": "backup-preflight", "apply-time-sync": "time-sync",
            "safety-audit": "safety-audit"}[args.action]
    try:
        if args.action == "catalog":
            data = catalog(name)
        elif args.action == "plan-source":
            data = plan_source(args.url, args.ref)
        elif args.action == "plan-npm":
            data = plan_npm(args.package, args.version)
        elif args.action == "label-session":
            data = label_session(args.session_id, args.label)
        elif args.action == "unlabel-session":
            data = unlabel_session(args.session_id)
        elif args.action == "source-status":
            data = source_status(args.plan_id)
        elif args.action == "apply-source":
            data = apply_source(args.plan_id)
        elif args.action == "finding-detail":
            data = finding_detail(args.finding_id)
        elif args.action == "artifact-detail":
            data = artifact_detail(args.artifact_id)
        elif args.action == "lifecycle":
            data = lifecycle(args.operation)
        elif args.action == "dependency-plan":
            data = dependency_plan(args.source_id)
        elif args.action == "dependency-status":
            data = dependency_status(args.plan_id)
        elif args.action == "dependency-apply":
            data = dependency_apply(args.plan_id, args.expected_digest)
        elif args.action == "dependency-bundles":
            data = dependency_bundles()
        elif args.action == "index-source":
            data = index_source(args.kind, args.source_id)
        elif args.action == "backup-preflight":
            data = backup_preflight(args.destination)
        elif args.action == "apply-time-sync":
            data = apply_time_sync()
        elif args.action == "safety-audit":
            data = safety_audit()
        else:
            data = verify_boundaries()
        payload = {"schema": SCHEMA, "catalog": name, "data": data}
        print(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
        return 0
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"schema": SCHEMA, "catalog": name, "error": str(error)[:500]}, ensure_ascii=True))
        return 1


if __name__ == "__main__":
    sys.exit(main())
