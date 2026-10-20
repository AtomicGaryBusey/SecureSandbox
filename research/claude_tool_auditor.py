#!/usr/bin/env python3
"""Extract content-free high-risk tool intent from Claude Code journals."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path


PROJECTS_ROOT = Path("/home/agent/.claude/projects")
STATE_DIRECTORY = Path("/var/lib/secure-sandbox/tool-auditor")
STATE_FILE = STATE_DIRECTORY / "state.json"
RUN_ID_FILE = Path("/run/secure-sandbox/run-id")
AGENT_UID = 1001
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_READ_BYTES = 8 * 1024 * 1024
MAX_TRACKED_FILES = 256

SIGNAL_EVENT = {
    "sandbox_bypass": ("sandbox_bypass_requested", "critical"),
    "privilege_escalation": ("privilege_escalation_requested", "high"),
    "security_policy_change": ("security_policy_change_requested", "critical"),
    "network_tunnel": ("network_tunnel_requested", "high"),
}

PRIVILEGE_PATTERN = re.compile(
    r"(?:^|[;&|()\s])(?:sudo|su|pkexec|doas)(?:\s|$)", re.IGNORECASE
)
POLICY_PATTERN = re.compile(
    r"(?:^|[;&|()\s])(?:nft|iptables|ip6tables|auditctl|augenrules|sysctl|setcap)"
    r"(?:\s|$)|/proc/sys/|/etc/(?:nftables|audit|sysctl|systemd)/",
    re.IGNORECASE,
)
TUNNEL_PATTERN = re.compile(
    r"(?:^|[;&|()\s])(?:socat|ncat|nc|chisel|cloudflared|proxychains|tailscale|"
    r"wg-quick)(?:\s|$)|(?:^|[;&|()\s])ssh\s+[^;&|]*(?:-[DLR]|ProxyCommand)",
    re.IGNORECASE,
)
BYPASS_KEYS = {
    "dangerouslydisablesandbox",
    "dangerouslyskippermissions",
    "bypasspermissions",
    "allowunsandboxedcommands",
}


def current_run_id() -> str:
    try:
        value = RUN_ID_FILE.read_text(encoding="ascii")[:64].strip()
    except OSError:
        return "preflight"
    if value == "boundary-test":
        return value
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return "preflight"
    return str(parsed) if parsed.version == 4 and str(parsed) == value.lower() else "preflight"


def has_truthy_bypass_key(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).replace("_", "").lower() in BYPASS_KEYS and item is True:
                return True
            if has_truthy_bypass_key(item):
                return True
    elif isinstance(value, list):
        return any(has_truthy_bypass_key(item) for item in value)
    return False


def classify_tool_use(tool: dict) -> tuple[list[str], str]:
    tool_input = tool.get("input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    command = tool_input.get("command")
    if not isinstance(command, str):
        command = ""
    signals: list[str] = []
    if has_truthy_bypass_key(tool_input):
        signals.append("sandbox_bypass")
    if PRIVILEGE_PATTERN.search(command):
        signals.append("privilege_escalation")
    if POLICY_PATTERN.search(command):
        signals.append("security_policy_change")
    if TUNNEL_PATTERN.search(command):
        signals.append("network_tunnel")
    command_hash = hashlib.sha256(command.encode("utf-8")).hexdigest() if command else ""
    return signals, command_hash


def safe_identifier(value: object, limit: int = 128) -> str:
    text = str(value or "")[:limit]
    return text if re.fullmatch(r"[A-Za-z0-9_.:-]*", text) else "invalid"


def audit_event(
    event_type: str,
    severity: str,
    decision: str,
    tool_use_id: str,
    message: str,
) -> dict:
    return {
        "event": "claude_tool_audit",
        "event_type": event_type,
        "severity": severity,
        "decision": decision,
        "request_id": safe_identifier(tool_use_id),
        "run_id": current_run_id(),
        "message": message[:256],
    }


def process_record(record: object, pending: dict[str, list[dict]]) -> list[dict]:
    if not isinstance(record, dict):
        return []
    events: list[dict] = []
    if record.get("type") == "assistant":
        assistant_uuid = safe_identifier(record.get("uuid"))
        message = record.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            return []
        risks: list[dict] = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            signals, command_hash = classify_tool_use(block)
            tool_name = safe_identifier(block.get("name"), 64)
            tool_use_id = safe_identifier(block.get("id"))
            for signal in signals:
                event_type, severity = SIGNAL_EVENT[signal]
                message_value = f"signal={signal} tool={tool_name}"
                if command_hash:
                    message_value += f" command_sha256={command_hash}"
                events.append(
                    audit_event(event_type, severity, "request", tool_use_id, message_value)
                )
                risks.append(
                    {"signal": signal, "tool": tool_name, "tool_use_id": tool_use_id}
                )
        if risks and assistant_uuid != "invalid":
            pending[assistant_uuid] = risks
    decision_value = record.get("permissionDecision")
    source_uuid = safe_identifier(record.get("sourceToolAssistantUUID"))
    if isinstance(decision_value, dict) and source_uuid in pending:
        decision = safe_identifier(decision_value.get("decision"), 32)
        source = safe_identifier(decision_value.get("source"), 64)
        for risk in pending.pop(source_uuid):
            severity = "critical" if decision == "accept" else "warning"
            events.append(
                audit_event(
                    "risky_tool_approval",
                    severity,
                    decision,
                    risk["tool_use_id"],
                    f"signal={risk['signal']} tool={risk['tool']} approval_source={source}",
                )
            )
    return events


def load_state() -> tuple[dict, bool]:
    try:
        with open(STATE_FILE, encoding="utf-8") as handle:
            state = json.load(handle)
        if not isinstance(state, dict):
            raise ValueError
        return state, False
    except (OSError, ValueError, json.JSONDecodeError):
        return {"files": {}, "pending": {}}, True


def save_state(state: dict) -> None:
    STATE_DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = STATE_DIRECTORY / f".state.{os.getpid()}"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE_FILE)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def journal_files() -> list[Path]:
    try:
        files = sorted(PROJECTS_ROOT.glob("*/*.jsonl"))
    except OSError:
        return []
    return files[-MAX_TRACKED_FILES:]


def read_records(
    path: Path, previous: object, bootstrap: bool
) -> tuple[list[dict], int, str]:
    parent_descriptor = os.open(
        path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_descriptor
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != AGENT_UID:
            raise PermissionError("journal ownership or type is invalid")
        identity = f"{metadata.st_dev}:{metadata.st_ino}"
        if not isinstance(previous, dict) or previous.get("identity") != identity:
            offset = metadata.st_size if bootstrap else 0
        else:
            offset = int(previous.get("offset", 0))
        if offset > metadata.st_size:
            offset = 0
        records: list[dict] = []
        consumed = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            handle.seek(offset)
            while consumed < MAX_READ_BYTES:
                line_start = handle.tell()
                line = handle.readline(MAX_LINE_BYTES + 1)
                if not line:
                    break
                consumed += len(line)
                offset = handle.tell()
                if not line.endswith(b"\n") and len(line) <= MAX_LINE_BYTES:
                    offset = line_start
                    break
                if len(line) > MAX_LINE_BYTES or not line.endswith(b"\n"):
                    continue
                try:
                    value = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(value, dict):
                    records.append(value)
        return records, offset, identity
    finally:
        try:
            os.close(descriptor)
        except UnboundLocalError:
            pass
        os.close(parent_descriptor)


def scan_once(state: dict, bootstrap: bool = False) -> list[dict]:
    events: list[dict] = []
    files_state = state.setdefault("files", {})
    pending = state.setdefault("pending", {})
    if not isinstance(files_state, dict) or not isinstance(pending, dict):
        raise ValueError("invalid auditor state")
    for path in journal_files():
        key = str(path)
        previous = files_state.get(key)
        try:
            records, offset, identity = read_records(path, previous, bootstrap)
        except (OSError, PermissionError, ValueError):
            continue
        files_state[key] = {"identity": identity, "offset": offset}
        for record in records:
            events.extend(process_record(record, pending))
    known = set(str(path) for path in journal_files())
    for stale in list(files_state):
        if stale not in known:
            files_state.pop(stale, None)
    return events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    state, bootstrap = load_state()
    while True:
        for event in scan_once(state, bootstrap):
            print(json.dumps(event, separators=(",", ":"), sort_keys=True), flush=True)
        bootstrap = False
        save_state(state)
        if args.once:
            return
        time.sleep(0.5)


if __name__ == "__main__":
    main()
