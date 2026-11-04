#!/usr/bin/env python3
"""Root-only, replay-safe guest actuator for native vendor egress rotation.

The Host coordinator supplies one canonical step request through the protected
control plane.  This actuator does not trust the requested transition: it
validates the complete successor grant, applies one role-specific mutation,
and independently reads the resulting service, policy, and connection state
before producing a content-free receipt.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from shared import native_egress


REQUEST_SCHEMA = "secure-sandbox-native-stack-step-request-v1"
RESULT_SCHEMA = "secure-sandbox-native-stack-step-result-v1"
CLOSED_SCHEMA = "secure-sandbox-native-egress-closed-v1"
DENY_SCHEMA = "secure-sandbox-native-egress-deny-transition-v1"
MAX_REQUEST_BYTES = 256 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
WATCHDOG_POLL_SECONDS = 0.25

STATE_ROOT = Path("/var/lib/secure-sandbox/native-egress-control")
GRANT_ROOT = Path("/var/lib/secure-sandbox/native-egress")
ACTIVE_GRANT = GRANT_ROOT / "active.json"
RETIRED_GRANT = STATE_ROOT / "retired.json"
DENY_TRANSITION = STATE_ROOT / "deny-transition.json"
CLOSED_GRANT = STATE_ROOT / "closed-grant-absent"
NFT_POLICY = Path("/etc/nftables.conf")
INSTALL_STATE = Path("/etc/secure-sandbox/native-egress-installed")
ROLE_STATE = Path("/etc/secure-sandbox/native-egress-role")


def _no_crash(_phase: str) -> None:
    return None


# Test-only phase injection.  Production leaves this as a no-op; tests use it
# to prove that every durable deny phase recovers to a closed live ruleset.
CRASH_HOOK: Callable[[str], None] = _no_crash

ROLE = {
    "gateway": {
        "identity": "native-tunnel",
        "service": "native-opaque-tunnel.service",
        "renderer": "/usr/local/libexec/secure-sandbox/render_gateway_firewall.py",
        "mark_domain": "provider",
    },
    "research": {
        "identity": "native-harness",
        "service": "native-harness-supervisor.service",
        "renderer": "/usr/local/libexec/secure-sandbox/render_research_firewall.py",
        "mark_domain": "research",
    },
}

STEP_ROLE = {
    "stop-research-native-harness": "research",
    "stop-gateway-native-tunnel": "gateway",
    "apply-research-deny-only": "research",
    "apply-gateway-deny-only": "gateway",
    "delete-research-native-conntrack": "research",
    "delete-gateway-native-conntrack": "gateway",
    "apply-gateway-successor-policy": "gateway",
    "apply-research-successor-policy": "research",
    "start-gateway-native-tunnel": "gateway",
    "start-research-native-harness": "research",
    "stop-bound-runs": "research",
}

STEP_ALIAS = {
    "deny-only": lambda role: f"apply-{role}-deny-only",
    "conntrack-delete": lambda role: f"delete-{role}-native-conntrack",
    "successor-policy": lambda role: f"apply-{role}-successor-policy",
}


class NativeGuestControlError(RuntimeError):
    """Stable fail-closed guest control error."""


def canonical(value: object) -> bytes:
    try:
        raw = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeGuestControlError("native_guest_value_invalid") from error
    if len(raw) > MAX_REQUEST_BYTES:
        raise NativeGuestControlError("native_guest_value_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _uuid4(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, AttributeError) as error:
        raise NativeGuestControlError(f"native_guest_{label}_invalid") from error
    if parsed.version != 4 or str(parsed) != value:
        raise NativeGuestControlError(f"native_guest_{label}_invalid")
    return str(parsed)


def validate_closed(value: object, request: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "schema", "action_id", "plan_sha256", "stack_id", "stack_sha256",
        "state", "policy_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeGuestControlError("native_guest_closed_policy_invalid")
    policy = dict(value)
    body = {key: policy[key] for key in fields - {"schema", "policy_sha256"}}
    if (
        policy["schema"] != CLOSED_SCHEMA
        or policy["state"] != "closed"
        or policy["action_id"] != request["action_id"]
        or policy["plan_sha256"] != request["plan_sha256"]
        or not isinstance(policy["stack_id"], str)
        or not 1 <= len(policy["stack_id"]) <= 63
        or SHA256.fullmatch(str(policy["stack_sha256"])) is None
        or SHA256.fullmatch(str(policy["policy_sha256"])) is None
        or policy["policy_sha256"] != digest(body)
    ):
        raise NativeGuestControlError("native_guest_closed_policy_invalid")
    return policy


def validate_request(value: object, expected_step: str, role: str) -> dict[str, Any]:
    fields = {
        "schema", "action_id", "plan_sha256", "authorization_sha256",
        "step", "successor",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeGuestControlError("native_guest_request_fields_invalid")
    request = dict(value)
    if (
        request["schema"] != REQUEST_SCHEMA
        or request["step"] != expected_step
        or STEP_ROLE.get(expected_step) != role
        or SHA256.fullmatch(str(request["plan_sha256"])) is None
        or SHA256.fullmatch(str(request["authorization_sha256"])) is None
    ):
        raise NativeGuestControlError("native_guest_request_invalid")
    _uuid4(request["action_id"], "action_id")
    successor = request["successor"]
    if isinstance(successor, Mapping) and successor.get("schema") == CLOSED_SCHEMA:
        request["successor"] = validate_closed(successor, request)
    else:
        try:
            request["successor"] = native_egress.validate_grant(successor, now=int(time.time()))
        except native_egress.NativeEgressError as error:
            raise NativeGuestControlError("native_guest_successor_invalid") from error
    canonical(request)
    return request


def read_request(stream: Any = sys.stdin.buffer) -> object:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if not 2 <= len(raw) <= MAX_REQUEST_BYTES:
        raise NativeGuestControlError("native_guest_request_size_invalid")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeGuestControlError("native_guest_request_json_invalid") from error
    if raw != canonical(value):
        raise NativeGuestControlError("native_guest_request_not_canonical")
    return value


def installed_role(path: Path = ROLE_STATE) -> str:
    try:
        parent = path.parent.lstat()
        info = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            opened = os.fstat(descriptor)
            raw = os.read(descriptor, 32)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise NativeGuestControlError("native_guest_role_state_unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & 0o022
        or not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
        or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        or opened.st_uid != 0
        or opened.st_gid != 0
        or stat.S_IMODE(opened.st_mode) != 0o600
    ):
        raise NativeGuestControlError("native_guest_role_state_untrusted")
    try:
        role = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise NativeGuestControlError("native_guest_role_state_invalid") from error
    if role not in ROLE or raw != (role + "\n").encode("ascii"):
        raise NativeGuestControlError("native_guest_role_state_invalid")
    return role


def _open_trusted_directory(
    path: Path, *, uid: int, gid: int, mode: int, create: bool = False
) -> int:
    """Open an exact directory without repairing an existing object."""
    try:
        parent_before = path.parent.lstat()
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as error:
        raise NativeGuestControlError("native_guest_state_parent_untrusted") from error
    try:
        parent_opened = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or stat.S_ISLNK(parent_before.st_mode)
            or parent_before.st_uid != 0
            or parent_before.st_mode & 0o022
            or (parent_before.st_dev, parent_before.st_ino)
            != (parent_opened.st_dev, parent_opened.st_ino)
        ):
            raise NativeGuestControlError("native_guest_state_parent_untrusted")
        created = False
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            if not create:
                raise
            os.mkdir(path.name, mode, dir_fd=parent_descriptor)
            created = True
            descriptor = os.open(
                path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent_descriptor,
            )
        try:
            if created:
                os.fchown(descriptor, uid, gid)
                os.fchmod(descriptor, mode)
                os.fsync(parent_descriptor)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != uid
                or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != mode
            ):
                raise NativeGuestControlError("native_guest_state_root_untrusted")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise
    finally:
        os.close(parent_descriptor)


def _trusted_directory(path: Path, *, create: bool = False) -> int:
    return _open_trusted_directory(
        path, uid=0, gid=0, mode=0o700, create=create
    )


def _open_grant_directory(role: str, *, create: bool = False) -> tuple[int, int]:
    try:
        group_id = pwd.getpwnam(str(ROLE[role]["identity"])).pw_gid
    except KeyError as error:
        raise NativeGuestControlError("native_guest_identity_missing") from error
    descriptor = _open_trusted_directory(
        GRANT_ROOT, uid=0, gid=group_id, mode=0o750, create=create
    )
    return group_id, descriptor


def _grant_directory(role: str, *, create: bool = False) -> int:
    group_id, descriptor = _open_grant_directory(role, create=create)
    os.close(descriptor)
    return group_id


def atomic_bytes(
    path: Path,
    raw: bytes,
    *,
    uid: int,
    gid: int,
    mode: int,
    parent_validator: Callable[[], int] | None = None,
) -> None:
    if parent_validator is None:
        parent_descriptor = _trusted_directory(path.parent, create=True)
    else:
        parent_descriptor = parent_validator()
    temporary = f".{path.name}.{uuid.uuid4()}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=parent_descriptor,
        )
        try:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise NativeGuestControlError("native_guest_state_write_failed")
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(
            temporary,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        os.fsync(parent_descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        os.close(parent_descriptor)


def _run(
    command: Sequence[str],
    *,
    timeout: int = 30,
    accepted: set[int] | None = None,
    input_bytes: bytes | None = None,
    maximum_output: int = MAX_REQUEST_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    accepted = {0} if accepted is None else accepted
    try:
        result = subprocess.run(
            list(command),
            input=input_bytes,
            stdin=None if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise NativeGuestControlError("native_guest_command_failed") from error
    if result.returncode not in accepted or len(result.stdout) > maximum_output:
        raise NativeGuestControlError("native_guest_command_failed")
    return result


def _service_state(service: str) -> str:
    loaded = _run(
        [
            "/usr/bin/systemctl", "show", "--property=LoadState", "--value",
            service,
        ]
    ).stdout.decode("ascii", "strict").strip()
    if loaded != "loaded":
        raise NativeGuestControlError("native_guest_service_unit_untrusted")
    result = _run(
        ["/usr/bin/systemctl", "is-active", service], accepted={0, 3}
    )
    state = result.stdout.decode("ascii", "strict").strip()
    if state not in {"active", "inactive", "failed"}:
        raise NativeGuestControlError("native_guest_service_state_invalid")
    return state


def _render(role: str, output: Path, *, grant_path: Path = ACTIVE_GRANT) -> None:
    renderer = str(ROLE[role]["renderer"])
    if role == "gateway":
        command = [
            renderer,
            "--broker-config", "/etc/secure-sandbox/broker.json",
            "--azure-config", "/etc/secure-sandbox/azure-shipper.json",
            "--archive-config", "/etc/secure-sandbox/conversation-azure.json",
            "--source-config", "/etc/secure-sandbox/source-acquisition.json",
            "--native-grant", str(grant_path),
            "--output", str(output),
        ]
    else:
        command = [
            renderer, "--native-grant", str(grant_path),
            "--output", str(output),
        ]
    _run(command)
    _run(["/usr/sbin/nft", "-c", "-f", str(output)])


def _nested(value: object) -> list[object]:
    result = [value]
    if isinstance(value, Mapping):
        for item in value.values():
            result.extend(_nested(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(_nested(item))
    return result


def _verdict(expressions: object, name: str) -> bool:
    return isinstance(expressions, list) and any(
        isinstance(item, Mapping) and set(item) == {name}
        for item in expressions
    )


def _exact_match(
    expression: object, left: Mapping[str, object], operator: str, right: object
) -> bool:
    match = expression.get("match") if isinstance(expression, Mapping) else None
    return (
        isinstance(match, Mapping)
        and match.get("left") == left
        and match.get("op") == operator
        and match.get("right") == right
    )


def _contains_any(value: object, expected: set[object]) -> bool:
    return any(item in expected for item in _nested(value) if isinstance(
        item, (str, int)
    ))


def _native_accept(
    rule: Mapping[str, object], *, native_uids: set[int], marks: set[object]
) -> bool:
    expressions = rule.get("expr")
    if not _verdict(expressions, "accept"):
        return False
    values = _nested(expressions)
    if any(
        isinstance(value, int) and (value in native_uids or value == 8643)
        for value in values
    ):
        return True
    if any(
        isinstance(value, str)
        and ("native_provider_ipv4" in value or "native_gateway_ipv4" in value)
        for value in values
    ):
        return True
    if marks and _contains_any(expressions, marks):
        return True
    # A native accept always reads or writes a conntrack mark.  This catches a
    # stale/tampered rule even when its grant-specific mark is no longer known.
    return any(
        isinstance(value, Mapping)
        and value.get("ct") == {"key": "mark"}
        for value in values
    )


def _set_addresses(items: list[object], name: str) -> set[str]:
    addresses: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping):
            continue
        candidate = item.get("set") or item.get("element")
        if not isinstance(candidate, Mapping) or candidate.get("name") != name:
            continue
        for value in _nested(candidate.get("elem")):
            if not isinstance(value, str):
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.version == 4:
                addresses.add(str(address))
    return addresses


def _verify_live_policy(
    role: str, *, expected_grant: Mapping[str, Any] | None = None
) -> str:
    """Validate native authority from nft's structured kernel readback.

    Text-token checks are deliberately forbidden here: nft normalizes rules,
    marks, sets, and ordering in JSON, so an old literal accept rule cannot hide
    behind a closed-looking policy string.
    """
    result = _run(["/usr/sbin/nft", "-n", "-j", "list", "ruleset"])
    try:
        value = json.loads(result.stdout)
        items = value.get("nftables") if isinstance(value, Mapping) else None
        native_uid = pwd.getpwnam(str(ROLE[role]["identity"])).pw_uid
        provider_uids = (() if role != "research" else (
            pwd.getpwnam("native-claude").pw_uid,
            pwd.getpwnam("native-codex").pw_uid,
        ))
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as error:
        raise NativeGuestControlError("native_guest_live_policy_untrusted") from error
    if not isinstance(items, list):
        raise NativeGuestControlError("native_guest_live_policy_untrusted")
    tables = [
        item["table"] for item in items
        if isinstance(item, Mapping) and isinstance(item.get("table"), Mapping)
    ]
    if (
        len(tables) != 1
        or tables[0].get("family") != "inet"
        or tables[0].get("name") != "filter"
    ):
        raise NativeGuestControlError("native_guest_live_policy_untrusted")
    chains = {
        chain.get("name"): chain
        for item in items if isinstance(item, Mapping)
        for chain in [item.get("chain")] if isinstance(chain, Mapping)
    }
    hooks = {"input": "input", "forward": "forward", "output": "output"}
    if set(chains) != set(hooks):
        raise NativeGuestControlError("native_guest_live_policy_untrusted")
    for name, hook in hooks.items():
        chain = chains[name]
        if (
            chain.get("family") != "inet"
            or chain.get("table") != "filter"
            or chain.get("type") != "filter"
            or chain.get("hook") != hook
            or chain.get("prio") != 0
            or chain.get("policy") != "drop"
        ):
            raise NativeGuestControlError("native_guest_live_policy_untrusted")
    sets = {
        item["set"].get("name"): item["set"]
        for item in items
        if isinstance(item, Mapping) and isinstance(item.get("set"), Mapping)
    }
    rules: dict[str, list[Mapping[str, object]]] = {name: [] for name in hooks}
    for item in items:
        rule = item.get("rule") if isinstance(item, Mapping) else None
        if not isinstance(rule, Mapping):
            continue
        if (
            rule.get("family") != "inet"
            or rule.get("table") != "filter"
            or rule.get("chain") not in rules
        ):
            raise NativeGuestControlError("native_guest_live_policy_untrusted")
        expressions = rule.get("expr")
        if not isinstance(expressions, list) or any(
            isinstance(item, Mapping) and ("jump" in item or "goto" in item)
            for item in expressions
        ):
            raise NativeGuestControlError("native_guest_live_policy_untrusted")
        rules[str(rule["chain"])].append(rule)

    native_uids = {native_uid, *provider_uids}
    marks: set[object] = set()
    if expected_grant is not None:
        for domain in ("research",) if role == "research" else (
            "provider", "research"
        ):
            mark = native_egress.conntrack_mark(expected_grant, domain)
            marks.update((mark, int(mark, 16)))
    native_accepts = [
        rule for chain in rules.values() for rule in chain
        if _native_accept(rule, native_uids=native_uids, marks=marks)
    ]
    native_sets = {
        name for name in sets
        if isinstance(name, str) and name.startswith("native_")
    }

    mark_left = {"ct": {"key": "mark"}}
    uid_left = {"meta": {"key": "skuid"}}
    mark_drop_index: dict[str, int] = {}
    for chain_name in ("input", "output"):
        for index, rule in enumerate(rules[chain_name]):
            expressions = rule["expr"]
            if _verdict(expressions, "drop") and any(
                _exact_match(item, mark_left, "!=", 0) for item in expressions
            ):
                mark_drop_index[chain_name] = index
                break
    if set(mark_drop_index) != {"input", "output"}:
        raise NativeGuestControlError("native_guest_live_policy_untrusted")
    owner_drop_index: dict[int, int] = {}
    for uid in native_uids:
        owner_drops = [
            index for index, rule in enumerate(rules["output"])
            if _verdict(rule["expr"], "drop") and any(
                _exact_match(item, uid_left, "==", uid)
                for item in rule["expr"]
            )
        ]
        if len(owner_drops) != 1:
            raise NativeGuestControlError("native_guest_live_policy_untrusted")
        owner_drop_index[uid] = owner_drops[0]

    # Before the nonzero-mark guard, only loopback or the exact active native
    # grant may accept.  A generic early accept would bypass every later drop.
    for chain_name in ("input", "output"):
        for index, rule in enumerate(rules[chain_name]):
            if not _verdict(rule["expr"], "accept"):
                continue
            if not any(
                isinstance(item, Mapping) and "match" in item
                for item in rule["expr"]
            ):
                raise NativeGuestControlError("native_guest_live_policy_untrusted")
            native = rule in native_accepts
            if index < mark_drop_index[chain_name]:
                if "lo" in _nested(rule["expr"]):
                    continue
                if not native:
                    raise NativeGuestControlError(
                        "native_guest_live_policy_untrusted"
                    )
            elif native:
                raise NativeGuestControlError(
                    "native_guest_live_policy_untrusted"
                )
            if chain_name == "output":
                matched_uids = {
                    uid for uid in native_uids
                    if any(
                        _exact_match(item, uid_left, "==", uid)
                        for item in rule["expr"]
                    )
                }
                if any(index >= owner_drop_index[uid] for uid in matched_uids):
                    raise NativeGuestControlError(
                        "native_guest_live_policy_untrusted"
                    )
                if not native and any(index <= drop for drop in owner_drop_index.values()):
                    raise NativeGuestControlError(
                        "native_guest_live_policy_untrusted"
                    )

    if expected_grant is None:
        if native_accepts or native_sets:
            raise NativeGuestControlError("native_guest_live_policy_not_closed")
    else:
        expected_set = (
            "native_gateway_ipv4" if role == "research"
            else "native_provider_ipv4"
        )
        expected_count = 5 if role == "research" else 6
        expected_addresses = (
            {"172.30.10.1"} if role == "research"
            else set(native_egress.flattened_ipv4(expected_grant))
        )
        set_value = sets.get(expected_set)
        flags = set_value.get("flags") if isinstance(set_value, Mapping) else None
        if (
            native_sets != {expected_set}
            or len(native_accepts) != expected_count
            or not isinstance(flags, list)
            or flags != ["timeout"]
            or _set_addresses(items, expected_set) != expected_addresses
            or not all(_contains_any(rule["expr"], marks) for rule in native_accepts)
        ):
            raise NativeGuestControlError("native_guest_live_policy_grant_missing")
    return hashlib.sha256(result.stdout).hexdigest()


def _rendered_policy(role: str, output: Path, *, closed: bool) -> bytes:
    if closed:
        try:
            CLOSED_GRANT.lstat()
        except FileNotFoundError:
            pass
        else:
            raise NativeGuestControlError("native_guest_closed_sentinel_present")
    _render(role, output, grant_path=CLOSED_GRANT if closed else ACTIVE_GRANT)
    info = output.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or not 2 <= info.st_size <= MAX_REQUEST_BYTES
    ):
        raise NativeGuestControlError("native_guest_rendered_policy_untrusted")
    descriptor = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        raw = bytearray()
        while len(raw) <= MAX_REQUEST_BYTES:
            block = os.read(
                descriptor, min(65536, MAX_REQUEST_BYTES + 1 - len(raw))
            )
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        identity(info) != identity(opened)
        or identity(opened) != identity(after)
        or len(raw) != opened.st_size
        or len(raw) > MAX_REQUEST_BYTES
    ):
        raise NativeGuestControlError("native_guest_rendered_policy_untrusted")
    return bytes(raw)


def _publish_persistent_policy(raw: bytes) -> None:
    parent = NFT_POLICY.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_mode & 0o022
    ):
        raise NativeGuestControlError("native_guest_policy_parent_untrusted")
    temporary = NFT_POLICY.parent / f".{NFT_POLICY.name}.native-{uuid.uuid4()}.tmp"
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o644,
        )
        try:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o644)
            view = memoryview(raw)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise NativeGuestControlError(
                        "native_guest_policy_write_failed"
                    )
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, NFT_POLICY)
        directory = os.open(
            NFT_POLICY.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _verify_persistent_closed_policy(role: str) -> str:
    temporary = Path("/run") / f"secure-sandbox-native-closed-{uuid.uuid4()}.nft"
    try:
        expected = _rendered_policy(role, temporary, closed=True)
        observed = NFT_POLICY.read_bytes()
        if observed != expected:
            raise NativeGuestControlError(
                "native_guest_persistent_policy_not_closed"
            )
        return hashlib.sha256(observed).hexdigest()
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _install_policy(role: str, *, closed: bool = False) -> str:
    live = Path("/run") / f"secure-sandbox-native-live-{uuid.uuid4()}.nft"
    persistent = Path("/run") / f"secure-sandbox-native-closed-{uuid.uuid4()}.nft"
    try:
        live_raw = _rendered_policy(role, live, closed=closed)
        closed_raw = live_raw if closed else _rendered_policy(
            role, persistent, closed=True
        )
        # The durable boot policy is always deny-only.  A live grant is loaded
        # only from its validated temporary image and therefore cannot reopen
        # after reboot or nftables.service restart.
        _publish_persistent_policy(closed_raw)
        _run(["/usr/sbin/nft", "-f", str(NFT_POLICY if closed else live)])
        grant = None if closed else _active_grant(role, now=int(time.time()))
        _verify_live_policy(role, expected_grant=grant)
        _verify_persistent_closed_policy(role)
        return hashlib.sha256(live_raw).hexdigest()
    finally:
        for path in (live, persistent):
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _active_grant(role: str, *, now: int | None = None) -> dict[str, Any] | None:
    group_id = _grant_directory(role, create=True)
    try:
        return native_egress.load_grant(
            ACTIVE_GRANT,
            now=now,
            expected_uid=0,
            expected_gid=group_id,
            expected_mode=0o640,
        )
    except native_egress.NativeEgressError as error:
        if not ACTIVE_GRANT.exists():
            return None
        raise NativeGuestControlError("native_guest_active_grant_untrusted") from error


def _retired_grant() -> dict[str, Any] | None:
    if not RETIRED_GRANT.exists():
        return None
    try:
        return native_egress.load_grant(
            RETIRED_GRANT,
            expected_uid=0,
            expected_gid=0,
            expected_mode=0o600,
        )
    except native_egress.NativeEgressError as error:
        raise NativeGuestControlError("native_guest_retired_grant_untrusted") from error


def _write_grant(role: str, grant: Mapping[str, Any]) -> None:
    group_id = _grant_directory(role, create=True)
    atomic_bytes(
        ACTIVE_GRANT,
        native_egress.canonical_bytes(grant),
        uid=0,
        gid=group_id,
        mode=0o640,
        parent_validator=lambda: _open_grant_directory(role, create=True)[1],
    )
    readback = _active_grant(role, now=int(time.time()))
    if readback is None or readback["grant_sha256"] != grant["grant_sha256"]:
        raise NativeGuestControlError("native_guest_grant_readback_failed")


def _unlink_active_grant(role: str) -> None:
    _group_id, descriptor = _open_grant_directory(role, create=True)
    try:
        try:
            os.unlink(ACTIVE_GRANT.name, dir_fd=descriptor)
        except FileNotFoundError:
            return
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _checkpoint(phase: str) -> None:
    CRASH_HOOK(phase)


def _deny_record(role: str, grant: Mapping[str, Any] | None) -> dict[str, Any]:
    body = {
        "role": role,
        "grant_sha256": None if grant is None else grant["grant_sha256"],
        "conntrack_mark": None if grant is None else native_egress.conntrack_mark(
            grant, str(ROLE[role]["mark_domain"])
        ),
        "created_at": int(time.time()),
    }
    return {"schema": DENY_SCHEMA, **body, "transition_sha256": digest(body)}


def _validate_deny_record(value: object, role: str) -> dict[str, Any]:
    fields = {
        "schema", "role", "grant_sha256", "conntrack_mark", "created_at",
        "transition_sha256",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise NativeGuestControlError("native_guest_deny_transition_invalid")
    record = dict(value)
    body = {name: record[name] for name in fields - {"schema", "transition_sha256"}}
    mark = record["conntrack_mark"]
    if (
        record["schema"] != DENY_SCHEMA
        or record["role"] != role
        or (record["grant_sha256"] is None) != (mark is None)
        or (
            record["grant_sha256"] is not None
            and SHA256.fullmatch(str(record["grant_sha256"])) is None
        )
        or (mark is not None and re.fullmatch(r"0x[0-9a-f]{8}", str(mark)) is None)
        or not isinstance(record["created_at"], int)
        or isinstance(record["created_at"], bool)
        or record["created_at"] < 1
        or record["transition_sha256"] != digest(body)
    ):
        raise NativeGuestControlError("native_guest_deny_transition_invalid")
    return record


def _read_deny_record(role: str) -> dict[str, Any] | None:
    try:
        descriptor = os.open(
            DENY_TRANSITION, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 2 <= info.st_size <= 4096
        ):
            raise NativeGuestControlError("native_guest_deny_transition_untrusted")
        raw = os.read(descriptor, 4097)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeGuestControlError("native_guest_deny_transition_invalid") from error
    if raw != canonical(value):
        raise NativeGuestControlError("native_guest_deny_transition_invalid")
    return _validate_deny_record(value, role)


def _apply_emergency_fence(role: str) -> None:
    try:
        uids = [pwd.getpwnam(str(ROLE[role]["identity"])).pw_uid]
        if role == "research":
            uids.extend((
                pwd.getpwnam("native-claude").pw_uid,
                pwd.getpwnam("native-codex").pw_uid,
            ))
    except KeyError as error:
        raise NativeGuestControlError("native_guest_identity_missing") from error
    input_port = "sport" if role == "research" else "dport"
    lines = [
        "insert rule inet filter input ct mark != 0 drop",
        "insert rule inet filter output ct mark != 0 drop",
        f'insert rule inet filter input iifname "ctl0" tcp {input_port} 8643 drop',
        *(f"insert rule inet filter output meta skuid {uid} drop" for uid in uids),
    ]
    _run(
        ["/usr/sbin/nft", "-f", "-"],
        input_bytes=("\n".join(lines) + "\n").encode("ascii"),
    )


def _unlink_deny_record() -> None:
    descriptor = _trusted_directory(STATE_ROOT, create=True)
    try:
        try:
            os.unlink(DENY_TRANSITION.name, dir_fd=descriptor)
        except FileNotFoundError:
            return
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _delete_conntrack_mark(mark: str | None) -> dict[str, Any]:
    if mark is None:
        return {"mark": None, "absence": "no-retired-grant"}
    _run(
        ["/usr/sbin/conntrack", "-D", "-m", "mark", "--mark", mark],
        accepted={0, 1},
    )
    observed = _run(
        ["/usr/sbin/conntrack", "-L", "-m", "mark", "--mark", mark]
    )
    if observed.stdout.strip():
        raise NativeGuestControlError("native_guest_conntrack_not_empty")
    return {"mark": mark, "absence": "verified"}


def _recover_deny_transition(role: str) -> dict[str, Any] | None:
    record = _read_deny_record(role)
    if record is None:
        return None
    _stop_service(role)
    try:
        _apply_emergency_fence(role)
    except NativeGuestControlError:
        # A missing or malformed live table cannot accept an insert. Loading
        # the independently rendered closed image is the atomic fallback.
        _install_policy(role, closed=True)
    _checkpoint("deny-fence")
    current = _active_grant(role)
    if current is not None:
        if current["grant_sha256"] != record["grant_sha256"]:
            raise NativeGuestControlError("native_guest_deny_transition_conflict")
        atomic_bytes(
            RETIRED_GRANT,
            native_egress.canonical_bytes(current),
            uid=0,
            gid=0,
            mode=0o600,
        )
    _checkpoint("deny-retired")
    _unlink_active_grant(role)
    _checkpoint("deny-unlinked")
    policy_sha256 = _install_policy(role, closed=True)
    _checkpoint("deny-policy")
    conntrack = _delete_conntrack_mark(record["conntrack_mark"])
    _checkpoint("deny-conntrack")
    if _active_grant(role) is not None:
        raise NativeGuestControlError("native_guest_deny_readback_failed")
    _verify_live_policy(role, expected_grant=None)
    _verify_persistent_closed_policy(role)
    if _service_state(str(ROLE[role]["service"])) == "active":
        raise NativeGuestControlError("native_guest_closed_service_active")
    _checkpoint("deny-verified")
    _unlink_deny_record()
    _checkpoint("deny-complete")
    return {
        "policy_sha256": policy_sha256,
        "retired_grant_sha256": record["grant_sha256"],
        "conntrack": conntrack,
    }


def _deny_only(role: str) -> dict[str, Any]:
    recovered = _recover_deny_transition(role)
    if recovered is not None:
        return recovered
    current = _active_grant(role)
    record = _deny_record(role, current)
    atomic_bytes(
        DENY_TRANSITION,
        canonical(record),
        uid=0,
        gid=0,
        mode=0o600,
    )
    _checkpoint("deny-journal")
    recovered = _recover_deny_transition(role)
    if recovered is None:
        raise NativeGuestControlError("native_guest_deny_transition_missing")
    return recovered


def _delete_conntrack(role: str) -> dict[str, Any]:
    retired = _retired_grant()
    mark = None if retired is None else native_egress.conntrack_mark(
        retired, str(ROLE[role]["mark_domain"])
    )
    return _delete_conntrack_mark(mark)


def _apply_successor(role: str, successor: Mapping[str, Any]) -> dict[str, Any]:
    if successor["schema"] == CLOSED_SCHEMA:
        if _active_grant(role) is not None:
            raise NativeGuestControlError("native_guest_closed_successor_has_grant")
        policy_sha256 = _install_policy(role, closed=True)
        return {"state": "closed", "policy_sha256": policy_sha256}
    _write_grant(role, successor)
    try:
        policy_sha256 = _install_policy(role)
    except Exception:
        _unlink_active_grant(role)
        _install_policy(role, closed=True)
        raise
    return {
        "state": "open",
        "grant_sha256": successor["grant_sha256"],
        "policy_sha256": policy_sha256,
    }


def _stop_service(role: str) -> dict[str, Any]:
    service = str(ROLE[role]["service"])
    _run(["/usr/bin/systemctl", "stop", service])
    state = _service_state(service)
    if state == "active":
        raise NativeGuestControlError("native_guest_service_still_active")
    return {"service": service, "state": state}


def _start_service(role: str) -> dict[str, Any]:
    service = str(ROLE[role]["service"])
    grant = _active_grant(role, now=int(time.time()))
    if grant is None:
        state = _service_state(service)
        if state == "active":
            raise NativeGuestControlError("native_guest_closed_service_active")
        return {"service": service, "state": state, "grant_sha256": None}
    _run(["/usr/bin/systemctl", "start", service])
    state = _service_state(service)
    if state != "active":
        raise NativeGuestControlError("native_guest_service_not_active")
    return {"service": service, "state": state, "grant_sha256": grant["grant_sha256"]}


def _stop_bound_runs() -> dict[str, Any]:
    # Native sessions are transient systemd scopes selected by their immutable
    # prefix. Stop the root supervisor first; then terminate all matching units
    # and require an empty independent list readback.
    _stop_service("research")
    listed = _run(
        ["/usr/bin/systemctl", "list-units", "--all", "--full", "--plain", "--no-legend", "secure-sandbox-native-run-*.scope"]
    )
    units: list[str] = []
    for line in listed.stdout.decode("ascii", "strict").splitlines():
        unit = line.split(None, 1)[0] if line.split(None, 1) else ""
        if re.fullmatch(r"secure-sandbox-native-run-[0-9a-f]{32}\.scope", unit):
            units.append(unit)
    for unit in sorted(set(units)):
        _run(["/usr/bin/systemctl", "stop", unit])
    observed = _run(
        ["/usr/bin/systemctl", "list-units", "--state=active,activating", "--full", "--plain", "--no-legend", "secure-sandbox-native-run-*.scope"]
    )
    if observed.stdout.strip():
        raise NativeGuestControlError("native_guest_bound_runs_still_active")
    return {"stopped_units": len(set(units)), "active_units": 0}


def execute(role: str, step: str, request: Mapping[str, Any]) -> dict[str, Any]:
    if step.startswith("stop-") and step != "stop-bound-runs":
        evidence = _stop_service(role)
    elif step == "stop-bound-runs":
        evidence = _stop_bound_runs()
    elif "deny-only" in step:
        evidence = _deny_only(role)
    elif "conntrack-delete" in step:
        evidence = _delete_conntrack(role)
    elif "successor-policy" in step:
        evidence = _apply_successor(role, request["successor"])
    elif step.startswith("start-"):
        evidence = _start_service(role)
    else:
        raise NativeGuestControlError("native_guest_step_invalid")
    evidence_body = {
        "role": role,
        "step": step,
        "action_id": request["action_id"],
        "observed": evidence,
    }
    return {
        "schema": RESULT_SCHEMA,
        "action_id": request["action_id"],
        "plan_sha256": request["plan_sha256"],
        "authorization_sha256": request["authorization_sha256"],
        "step": step,
        "status": "verified",
        "evidence_sha256": digest(evidence_body),
    }


def _prior_receipt(
    directory: int, name: str, request: Mapping[str, Any]
) -> dict[str, Any] | None:
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_gid != 0
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 2 <= before.st_size <= MAX_REQUEST_BYTES
        ):
            raise NativeGuestControlError("native_guest_receipt_untrusted")
        raw = bytearray()
        while len(raw) <= MAX_REQUEST_BYTES:
            block = os.read(
                descriptor, min(65536, MAX_REQUEST_BYTES + 1 - len(raw))
            )
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(raw) != before.st_size
        or len(raw) > MAX_REQUEST_BYTES
    ):
        raise NativeGuestControlError("native_guest_receipt_untrusted")
    try:
        prior = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeGuestControlError("native_guest_receipt_untrusted") from error
    if (
        not isinstance(prior, dict)
        or set(prior) != {"schema", "request_sha256", "result"}
        or prior.get("schema") != "secure-sandbox-native-guest-step-receipt-v1"
        or bytes(raw) != canonical(prior)
        or prior.get("request_sha256") != digest(request)
    ):
        raise NativeGuestControlError("native_guest_step_replay_mismatch")
    result = prior.get("result")
    if (
        not isinstance(result, dict)
        or set(result) != {
            "schema", "action_id", "plan_sha256", "authorization_sha256",
            "step", "status", "evidence_sha256",
        }
        or result.get("schema") != RESULT_SCHEMA
        or result.get("action_id") != request["action_id"]
        or result.get("plan_sha256") != request["plan_sha256"]
        or result.get("authorization_sha256") != request["authorization_sha256"]
        or result.get("step") != request["step"]
        or result.get("status") != "verified"
        or SHA256.fullmatch(str(result.get("evidence_sha256"))) is None
    ):
        raise NativeGuestControlError("native_guest_receipt_untrusted")
    return prior


@contextlib.contextmanager
def _actuator_locked(*, blocking: bool) -> Any:
    state_descriptor = _trusted_directory(STATE_ROOT, create=True)
    descriptor = os.open(
        ".lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=state_descriptor,
    )
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise NativeGuestControlError("native_guest_lock_untrusted")
        try:
            # Installation holds this same lock across its transaction.  A
            # request must never queue on old/partial state and then execute
            # after commit or rollback changes the installation beneath it.
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            fcntl.flock(descriptor, flags)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise NativeGuestControlError("native_guest_control_busy") from error
            raise
        yield state_descriptor
    finally:
        os.close(descriptor)
        os.close(state_descriptor)


def verify_closed_state(role: str) -> dict[str, Any]:
    if _active_grant(role) is not None:
        raise NativeGuestControlError("native_guest_closed_state_has_grant")
    if _read_deny_record(role) is not None:
        raise NativeGuestControlError("native_guest_deny_recovery_required")
    service = _service_state(str(ROLE[role]["service"]))
    if service == "active":
        raise NativeGuestControlError("native_guest_closed_service_active")
    return {
        "live_policy_sha256": _verify_live_policy(
            role, expected_grant=None
        ),
        "persistent_policy_sha256": _verify_persistent_closed_policy(role),
        "service": service,
        "state": "closed",
    }


def watchdog_once(role: str, *, now: int | None = None) -> int | None:
    timestamp = int(time.time()) if now is None else now
    with _actuator_locked(blocking=True):
        recovered = _recover_deny_transition(role)
        if recovered is not None:
            verify_closed_state(role)
            return None
        try:
            grant = _active_grant(role)
        except NativeGuestControlError:
            # Even an unparseable grant must not leave its old kernel rules
            # usable.  Fence first, publish closed boot/live policy, then fail
            # so systemd retries rather than treating ambiguous state as clean.
            _stop_service(role)
            try:
                _apply_emergency_fence(role)
            except NativeGuestControlError:
                pass
            _install_policy(role, closed=True)
            _verify_live_policy(role, expected_grant=None)
            _verify_persistent_closed_policy(role)
            raise
        if grant is None:
            try:
                verify_closed_state(role)
            except NativeGuestControlError:
                _deny_only(role)
                verify_closed_state(role)
            return None
        if timestamp >= grant["expires_at"]:
            _deny_only(role)
            verify_closed_state(role)
            return None
        _verify_live_policy(role, expected_grant=grant)
        _verify_persistent_closed_policy(role)
        return int(grant["expires_at"])


def watchdog(role: str) -> None:
    observed: tuple[int, int, int, int] | None = None
    deadline: int | None = None
    next_audit = 0.0
    while True:
        try:
            info = ACTIVE_GRANT.lstat()
            identity = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)
        except FileNotFoundError:
            identity = None
        timestamp = time.time()
        if (
            identity != observed
            or (deadline is not None and timestamp >= deadline)
            or timestamp >= next_audit
        ):
            deadline = watchdog_once(role)
            try:
                info = ACTIVE_GRANT.lstat()
                observed = (
                    info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size
                )
            except FileNotFoundError:
                observed = None
            next_audit = time.time() + 30.0
        remaining = 30.0 if deadline is None else max(
            0.0, float(deadline) - time.time()
        )
        time.sleep(min(WATCHDOG_POLL_SECONDS, remaining))


def operation(role: str, step: str, value: object) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise NativeGuestControlError("native_guest_root_required")
    if role not in ROLE:
        raise NativeGuestControlError("native_guest_role_invalid")
    if installed_role() != role:
        raise NativeGuestControlError("native_guest_installed_role_mismatch")
    if not native_egress.load_install_state(INSTALL_STATE):
        raise NativeGuestControlError("native_guest_feature_not_installed")
    request = validate_request(value, step, role)
    with _actuator_locked(blocking=False) as state_descriptor:
        _recover_deny_transition(role)
        receipt = STATE_ROOT / f"{request['action_id']}-{step}.json"
        prior = _prior_receipt(state_descriptor, receipt.name, request)
        if prior is not None:
            # A prior receipt cannot substitute for current-state evidence.
            # Re-establish and independently read back this idempotent step.
            return execute(role, step, request)
        result = execute(role, step, request)
        record = {
            "schema": "secure-sandbox-native-guest-step-receipt-v1",
            "request_sha256": digest(request),
            "result": result,
        }
        atomic_bytes(
            receipt,
            canonical(record),
            uid=0,
            gid=0,
            mode=0o600,
            parent_validator=lambda: os.dup(state_descriptor),
        )
        return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=[*sorted(ROLE), "installed"])
    parser.add_argument(
        "step",
        choices=[
            *sorted(STEP_ROLE), *sorted(STEP_ALIAS),
            "watchdog", "watchdog-once", "verify-closed",
        ],
    )
    args = parser.parse_args()
    try:
        role = installed_role() if args.role == "installed" else args.role
        if os.geteuid() != 0:
            raise NativeGuestControlError("native_guest_root_required")
        if installed_role() != role:
            raise NativeGuestControlError("native_guest_installed_role_mismatch")
        if not native_egress.load_install_state(INSTALL_STATE):
            raise NativeGuestControlError("native_guest_feature_not_installed")
        if args.step == "watchdog":
            watchdog(role)
            return 0
        if args.step == "watchdog-once":
            result = {"deadline": watchdog_once(role), "status": "verified"}
            sys.stdout.buffer.write(canonical(result))
            return 0
        if args.step == "verify-closed":
            with _actuator_locked(blocking=True):
                result = verify_closed_state(role)
            sys.stdout.buffer.write(canonical(result))
            return 0
        step = STEP_ALIAS[args.step](role) if args.step in STEP_ALIAS else args.step
        result = operation(role, step, read_request())
    except (NativeGuestControlError, native_egress.NativeEgressError, OSError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
