#!/usr/bin/env python3
"""Content-free Host adapter for protected native vendor stack operations.

The root manager passes one self-digested Host ticket. This adapter independently
revalidates the Touch ID receipt and protected catalog, prepares DNS-pinned
egress, invokes content-free guest controls, and delegates OpenAI credential
custody to one exact Developer-ID-signed Swift client. It never accepts an
OAuth secret or raw provider response.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import pwd
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
SUPPORT = HERE / "native_stack_support"
if SUPPORT.is_file():
    sys.path.insert(0, str(SUPPORT))
elif (HERE.parent / "shared/native_egress.py").is_file():
    sys.path.insert(0, str(HERE.parent))

from shared import model_stack_runtime_binding
from shared import native_egress
from shared import native_stack_operations as operations
from shared import native_stack_runtime_binding
from shared import native_vendor_stack
from shared import runtime_authority
from shared import session_context_binding


def _load_manager() -> Any:
    path = next(
        (candidate for candidate in (
            HERE / "native_stack_manager", HERE / "native_stack_manager.py"
        ) if candidate.is_file()),
        None,
    )
    if path is None:
        raise RuntimeError("native_stack_manager_unavailable")
    loader = importlib.machinery.SourceFileLoader(
        "native_stack_backend_manager", str(path)
    )
    specification = importlib.util.spec_from_loader(loader.name, loader)
    if specification is None:
        raise RuntimeError("native_stack_manager_unavailable")
    module = importlib.util.module_from_spec(specification)
    loader.exec_module(module)
    return module


MANAGER = _load_manager()
MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 128 * 1024
HOST_TICKET_SCHEMA = "secure-sandbox-native-stack-host-ticket-v1"
PROVIDER_RESULT_SCHEMA = "secure-sandbox-native-stack-provider-result-v1"
CREDENTIAL_HANDOFF_SCHEMA = "secure-sandbox-native-credential-client-handoff-v1"
CREDENTIAL_TICKET_SCHEMA = "secure-sandbox-native-credential-authorization-ticket-v1"
CREDENTIAL_TICKET_ROOT = Path("/usr/local/var/lib/secure-sandbox/native-credential-tickets")
AUTHORIZATION_RECEIPT_ROOT = Path("/usr/local/var/log/secure-sandbox/authorization-receipts")
CATALOG_PATH = Path("/usr/local/var/lib/secure-sandbox/native-stack-catalog/catalog.json")
CONTROL_CLIENT = HERE / "control_client"
SSH_CONFIG = HERE / "ssh_config"
SIGNED_CREDENTIAL_CLIENT = HERE / "native_stack_credential_client"
LAUNCHCTL = Path("/bin/launchctl")

QUALIFICATION_PERSONA_SHA256 = hashlib.sha256(
    b"secure-sandbox-native-entitlement-qualification-persona-v1\n"
).hexdigest()
QUALIFICATION_TOOL_CATALOG_SHA256 = hashlib.sha256(
    b'{"schema":"secure-sandbox-native-qualification-tools-v1","tools":[]}\n'
).hexdigest()
QUALIFICATION_EXTENSION_SET_SHA256 = hashlib.sha256(
    b'{"extensions":[],"schema":"secure-sandbox-native-qualification-extensions-v1"}\n'
).hexdigest()


class NativeStackBackendError(RuntimeError):
    """Stable fail-closed adapter rejection."""


def canonical(value: object) -> bytes:
    try:
        raw = (
            json.dumps(value, allow_nan=False, ensure_ascii=True,
                       separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeStackBackendError("native_stack_backend_value_invalid") from error
    if len(raw) > MAX_INPUT:
        raise NativeStackBackendError("native_stack_backend_value_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_canonical(stream: Any = sys.stdin.buffer) -> dict[str, Any]:
    raw = stream.read(MAX_INPUT + 1)
    if not 2 <= len(raw) <= MAX_INPUT:
        raise NativeStackBackendError("native_stack_backend_input_size_invalid")
    if any(name in raw.lower() for name in MANAGER.FORBIDDEN_SERIALIZED_NAMES):
        raise NativeStackBackendError("native_stack_backend_secret_field_forbidden")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_input_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeStackBackendError("native_stack_backend_input_not_canonical")
    return value


def validate_host_ticket(
    value: object,
    *,
    now: int,
    expected_host_release_id: str,
    receipt_root: Path = AUTHORIZATION_RECEIPT_ROOT,
    catalog_path: Path = CATALOG_PATH,
    trusted_uid: int = 0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    if not isinstance(value, dict) or set(value) != {
        "schema", "plan", "authorization", "ticket_sha256"
    }:
        raise NativeStackBackendError("native_stack_backend_ticket_fields_invalid")
    body = {"schema": value.get("schema"), "plan": value.get("plan"),
            "authorization": value.get("authorization")}
    if (value["schema"] != HOST_TICKET_SCHEMA
            or value["ticket_sha256"] != digest(body)):
        raise NativeStackBackendError("native_stack_backend_ticket_invalid")
    try:
        plan = operations.validate_plan(value["plan"], now=now, require_fresh=True)
        authorization = MANAGER.validate_authorization(
            value["authorization"], plan, now=now, require_fresh=True,
            expected_host_release_id=expected_host_release_id,
        )
        MANAGER.verify_authorization_receipt(
            authorization, plan, receipt_root=receipt_root, trusted_uid=trusted_uid,
        )
        stack, catalog_sha256 = MANAGER.authoritative_stack(plan, catalog_path)
    except (MANAGER.NativeStackManagerError,
            operations.NativeStackOperationError) as error:
        raise NativeStackBackendError("native_stack_backend_authority_rejected") from error
    if MANAGER.expected_plan_identity(stack) != plan["identity"]:
        raise NativeStackBackendError("native_stack_backend_catalog_mismatch")
    return plan, authorization, stack, catalog_sha256


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=0.5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait(timeout=1)


def run_bounded(
    command: Sequence[str], input_bytes: bytes, *, timeout: float,
    maximum_output: int = MAX_OUTPUT, pass_fds: tuple[int, ...] = (),
) -> bytes:
    if not input_bytes or len(input_bytes) > MAX_INPUT:
        raise NativeStackBackendError("native_stack_backend_child_input_invalid")
    process = subprocess.Popen(
        list(command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
        pass_fds=pass_fds,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
    )
    if process.stdin is None or process.stdout is None:
        _terminate(process)
        raise NativeStackBackendError("native_stack_backend_child_failed")
    os.set_blocking(process.stdin.fileno(), False)
    os.set_blocking(process.stdout.fileno(), False)
    poller = select.poll()
    poller.register(process.stdin.fileno(), select.POLLOUT)
    poller.register(process.stdout.fileno(), select.POLLIN | select.POLLHUP)
    sent, output, stdout_open = 0, bytearray(), True
    deadline = time.monotonic() + timeout
    try:
        while stdout_open or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeStackBackendError("native_stack_backend_child_timeout")
            for descriptor, _events in poller.poll(
                max(1, int(min(remaining, 0.25) * 1000))
            ):
                if descriptor == process.stdin.fileno():
                    if sent < len(input_bytes):
                        try:
                            sent += os.write(process.stdin.fileno(), input_bytes[sent:])
                        except BlockingIOError:
                            pass
                    if sent == len(input_bytes):
                        poller.unregister(process.stdin.fileno())
                        process.stdin.close()
                elif descriptor == process.stdout.fileno():
                    try:
                        block = os.read(
                            process.stdout.fileno(),
                            min(65536, maximum_output + 1 - len(output)),
                        )
                    except BlockingIOError:
                        continue
                    if block:
                        output.extend(block)
                        if len(output) > maximum_output:
                            raise NativeStackBackendError(
                                "native_stack_backend_child_output_oversized"
                            )
                    else:
                        poller.unregister(process.stdout.fileno())
                        stdout_open = False
                        process.stdout.close()
            if process.poll() is not None and not stdout_open:
                break
        result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        if result != 0 or not 2 <= len(output) <= maximum_output:
            raise NativeStackBackendError("native_stack_backend_child_failed")
        return bytes(output)
    except Exception:
        _terminate(process)
        raise
    finally:
        if not process.stdin.closed:
            process.stdin.close()
        if not process.stdout.closed:
            process.stdout.close()


def _resolver_child(hostname: str, descriptor: int) -> None:
    try:
        values = socket.getaddrinfo(
            hostname, 443, family=socket.AF_INET,
            type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
        raw = canonical({
            "hostname": hostname,
            "ipv4": sorted({item[4][0] for item in values}),
        })
        if len(raw) > 4096:
            raise ValueError
        os.write(descriptor, raw)
        os._exit(0)
    except BaseException:
        os._exit(1)


def resolve_once(hostname: str, *, timeout: float = 5.0) -> tuple[str, ...]:
    if (native_egress.HOSTNAME.fullmatch(hostname) is None
            or hostname != hostname.lower()):
        raise NativeStackBackendError("native_stack_backend_hostname_invalid")
    reader, writer = os.pipe2(os.O_CLOEXEC)
    child = os.fork()
    if child == 0:
        os.close(reader)
        _resolver_child(hostname, writer)
    os.close(writer)
    output, deadline, status = bytearray(), time.monotonic() + timeout, None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise NativeStackBackendError("native_stack_backend_dns_timeout")
            readable, _, _ = select.select([reader], [], [], min(remaining, 0.1))
            if readable:
                block = os.read(reader, 4097 - len(output))
                if not block:
                    break
                output.extend(block)
                if len(output) > 4096:
                    raise NativeStackBackendError("native_stack_backend_dns_oversized")
            waited, observed = os.waitpid(child, os.WNOHANG)
            if waited == child:
                status = observed
                if not readable:
                    output.extend(os.read(reader, 4097 - len(output)))
                    break
        if status is None:
            _, status = os.waitpid(child, 0)
        if status != 0:
            raise NativeStackBackendError("native_stack_backend_dns_failed")
    except Exception:
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(child, 0)
        except ChildProcessError:
            pass
        raise
    finally:
        os.close(reader)
    try:
        value = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_dns_invalid") from error
    if (not isinstance(value, dict)
            or set(value) != {"hostname", "ipv4"}
            or value["hostname"] != hostname
            or bytes(output) != canonical(value)
            or not isinstance(value["ipv4"], list)
            or not 1 <= len(value["ipv4"]) <= 16
            or value["ipv4"] != sorted(set(value["ipv4"]))):
        raise NativeStackBackendError("native_stack_backend_dns_invalid")
    result = []
    for item in value["ipv4"]:
        try:
            address = ipaddress.ip_address(item)
        except ValueError as error:
            raise NativeStackBackendError(
                "native_stack_backend_dns_address_invalid"
            ) from error
        if address.version != 4 or not address.is_global or str(address) != item:
            raise NativeStackBackendError("native_stack_backend_dns_address_invalid")
        result.append(item)
    return tuple(result)


def resolve_policy(
    policy_id: str, phase: str, *,
    resolver: Callable[[str], tuple[str, ...]] = resolve_once,
) -> dict[str, list[str]]:
    policy = native_egress.POLICIES.get(policy_id)
    specification = None if policy is None else policy["phases"].get(phase)
    if specification is None:
        raise NativeStackBackendError("native_stack_backend_egress_phase_invalid")
    result = {}
    for hostname in sorted(specification["hosts"]):
        stable = sorted(set(resolver(hostname)) & set(resolver(hostname)))
        if not stable or len(stable) > 16:
            raise NativeStackBackendError(
                "native_stack_backend_dns_rebinding_ambiguous"
            )
        result[hostname] = stable
    return result


def guest_call(operation: str, payload: object) -> dict[str, Any]:
    raw = run_bounded([
        str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
        "--timeout-seconds", "120", "sandbox-research-control", "pipe", operation,
    ], canonical(payload), timeout=150)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_guest_reply_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeStackBackendError("native_stack_backend_guest_reply_invalid")
    return value


def qualification_request(
    plan: Mapping[str, Any], authorization: Mapping[str, Any]
) -> dict[str, Any]:
    body = {
        "action_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "session_id": plan["action_id"],
        "persona_sha256": QUALIFICATION_PERSONA_SHA256,
        "tool_catalog_sha256": QUALIFICATION_TOOL_CATALOG_SHA256,
        "extension_set_sha256": QUALIFICATION_EXTENSION_SET_SHA256,
    }
    return {"schema": "secure-sandbox-native-stack-qualification-request-v1",
            **body, "request_sha256": digest(body)}


def validate_qualification_authority(
    value: object, *, plan: Mapping[str, Any], stack: Mapping[str, Any]
) -> dict[str, Any]:
    try:
        authority = runtime_authority.validate_binding(value)
        expected_model = model_stack_runtime_binding.make_binding(
            model_stack_runtime_binding.NATIVE_MODE,
            native_stack_runtime_binding.make_binding(stack),
        )
        expected_session = session_context_binding.make_binding(
            session_id=plan["action_id"], source_id=None,
            source_manifest_sha256=None,
            persona_sha256=QUALIFICATION_PERSONA_SHA256,
            tool_catalog_sha256=QUALIFICATION_TOOL_CATALOG_SHA256,
            extension_set_sha256=QUALIFICATION_EXTENSION_SET_SHA256,
        )
    except Exception as error:
        raise NativeStackBackendError(
            "native_stack_backend_qualification_invalid"
        ) from error
    harness = authority["harness_binding"]
    if (authority["model_stack_binding"] != expected_model
            or authority["session_context_binding"] != expected_session
            or harness["harness_id"] != plan["identity"]["harness_id"]
            or harness["harness_generation_id"]
                != plan["identity"]["harness_generation_id"]
            or harness["harness_adapter_id"]
                != plan["identity"]["harness_adapter_id"]):
        raise NativeStackBackendError("native_stack_backend_qualification_mismatch")
    return authority


def prepare_grant(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *, now: int,
    resolver: Callable[[str], tuple[str, ...]] = resolve_once,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    phase = plan["requested_network_phase"]
    if (phase == "closed" or (
        plan["identity"]["vendor_id"] == "openai"
        and plan["action"] in {"signin-begin", "status-verify", "logout"}
    )):
        return {"schema": MANAGER.CLOSED_POLICY_SCHEMA, "state": "closed"}
    if phase == native_egress.PHASE_LOGIN:
        kind, binding = "stack-intent", native_egress.make_stack_intent(stack)
    elif phase == native_egress.PHASE_STATUS_LOGOUT:
        kind, binding = "native-stack", native_stack_runtime_binding.make_binding(stack)
    elif phase == native_egress.PHASE_INFERENCE:
        reply = guest("native-qualification-authority",
                      qualification_request(plan, authorization))
        if (set(reply) != {"schema", "authority", "evidence_sha256"}
                or reply["schema"]
                    != "secure-sandbox-native-stack-qualification-reply-v1"
                or operations.SHA256.fullmatch(
                    str(reply["evidence_sha256"])
                ) is None):
            raise NativeStackBackendError(
                "native_stack_backend_qualification_reply_invalid"
            )
        kind = "runtime-authority"
        binding = validate_qualification_authority(
            reply["authority"], plan=plan, stack=stack
        )
    else:
        raise NativeStackBackendError("native_stack_backend_phase_invalid")
    pins = resolve_policy(
        plan["identity"]["network_policy_id"], phase, resolver=resolver
    )
    maximum = native_egress.POLICIES[
        plan["identity"]["network_policy_id"]
    ]["phases"][phase]["maximum_duration_seconds"]
    expires_at = min(plan["expires_at"], now + maximum)
    if expires_at <= now:
        raise NativeStackBackendError("native_stack_backend_grant_expired")
    return native_egress.make_grant(
        binding_kind=kind, binding_value=binding, phase=phase,
        resolved_ipv4=pins, issued_at=now, expires_at=expires_at,
    )


def _ensure_root_directory(path: Path, mode: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
                or parent.st_uid != 0 or parent.st_mode & 0o022):
            raise NativeStackBackendError("native_stack_backend_state_parent_untrusted")
        os.mkdir(path, mode)
        info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode):
        raise NativeStackBackendError("native_stack_backend_state_root_untrusted")


def _atomic_ticket(path: Path, value: object) -> None:
    _ensure_root_directory(path.parent, 0o755)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), 0, 0)
            os.fchmod(handle.fileno(), 0o644)
            handle.write(canonical(value)); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def make_credential_ticket(
    *, operation: str, action: str, plan: Mapping[str, Any],
    authorization: Mapping[str, Any], session_authority_sha256: str | None = None,
) -> dict[str, Any]:
    body = {
        "ticket_id": authorization["authorization_id"],
        "operation_id": plan["action_id"],
        "request_id": authorization["authorization_id"],
        "operation": operation, "action": action, "provider": "openAIChatGPT",
        "plan_sha256": plan["plan_sha256"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "session_authority_sha256": session_authority_sha256,
        "request_sha256": authorization["request_sha256"],
        "authorization_receipt_sha256": authorization["pending_receipt_sha256"],
        "issued_at": authorization["authorized_at"],
        "expires_at": authorization["expires_at"], "status": "authorized",
    }
    return {"schema": CREDENTIAL_TICKET_SCHEMA, **body,
            "ticket_sha256": digest(body)}


def credential_handoff(
    *, operation: str, operation_id: str, plan: Mapping[str, Any] | None,
    authorization: Mapping[str, Any] | None,
    session_authority_sha256: str | None = None,
) -> dict[str, Any]:
    body = {
        "operation_id": operation_id, "operation": operation,
        "authorization_ticket_id": None if authorization is None else authorization["authorization_id"],
        "plan_sha256": None if plan is None else plan["plan_sha256"],
        "operator_request_sha256": None if authorization is None else authorization["request_sha256"],
        "stack_sha256": None if plan is None else plan["identity"]["stack_sha256"],
        "session_authority_sha256": session_authority_sha256,
        "authorization_receipt_sha256": None if authorization is None else authorization["pending_receipt_sha256"],
    }
    return {"schema": CREDENTIAL_HANDOFF_SCHEMA, **body,
            "handoff_sha256": digest(body)}


def validate_credential_reply(value: object) -> dict[str, Any]:
    expected = {"schema", "operation_id", "verified", "status", "projection",
                "error_code", "response_sha256", "reply_sha256"}
    if not isinstance(value, dict) or set(value) != expected:
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid")
    body = {key: value[key] for key in expected - {"schema", "reply_sha256"}}
    if (value["schema"] != "secure-sandbox-native-credential-client-reply-v1"
            or operations.SHA256.fullmatch(str(value["response_sha256"])) is None
            or value["reply_sha256"] != digest(body)
            or not isinstance(value["verified"], bool)
            or (value["verified"] and value["error_code"] is not None)
            or (not value["verified"] and value["error_code"] is None)):
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid")
    if not value["verified"]:
        raise NativeStackBackendError("native_stack_backend_credential_rejected")
    return dict(value)


def console_uid(console: Path = Path("/dev/console")) -> int:
    try:
        uid = console.stat().st_uid
        account = pwd.getpwuid(uid)
    except (OSError, KeyError) as error:
        raise NativeStackBackendError("native_stack_backend_console_user_unavailable") from error
    if (uid <= 0 or account.pw_uid != uid
            or account.pw_dir in {"", "/var/empty", "/nonexistent"}
            or account.pw_shell.endswith("nologin")):
        raise NativeStackBackendError("native_stack_backend_console_user_invalid")
    return uid


def _trusted_executable(path: Path) -> None:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        opened = os.fstat(descriptor); os.close(descriptor)
    except OSError as error:
        raise NativeStackBackendError("native_stack_backend_signed_client_unavailable") from error
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != 0 or before.st_gid != 0 or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o555
            or not 1 <= before.st_size <= 64 * 1024 * 1024
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)):
        raise NativeStackBackendError("native_stack_backend_signed_client_untrusted")


def signed_credential_call(
    handoff: Mapping[str, Any], *, client: Path = SIGNED_CREDENTIAL_CLIENT,
    launchctl: Path = LAUNCHCTL, uid: int | None = None,
    state_root: Path = Path("/usr/local/var/run/secure-sandbox"),
) -> dict[str, Any]:
    _trusted_executable(client)
    _ensure_root_directory(state_root, 0o700)
    operator_uid = console_uid() if uid is None else uid
    descriptor, name = tempfile.mkstemp(prefix="native-credential-handoff.", dir=state_root)
    try:
        os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o400)
        os.write(descriptor, canonical(handoff)); os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET); os.unlink(name)
        output = run_bounded(
            [str(launchctl), "asuser", str(operator_uid), str(client),
             "--request-fd", str(descriptor)],
            b"\n", timeout=180, maximum_output=32 * 1024,
            pass_fds=(descriptor,),
        )
    finally:
        os.close(descriptor)
        try: os.unlink(name)
        except FileNotFoundError: pass
    try:
        value = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid") from error
    if not isinstance(value, dict) or output != canonical(value):
        raise NativeStackBackendError("native_stack_backend_credential_reply_invalid")
    return validate_credential_reply(value)


def credential_operation(
    operation: str, action: str, plan: Mapping[str, Any],
    authorization: Mapping[str, Any], *,
    call: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
) -> dict[str, Any]:
    _atomic_ticket(
        CREDENTIAL_TICKET_ROOT / f"{authorization['authorization_id']}.json",
        make_credential_ticket(operation=operation, action=action, plan=plan,
                               authorization=authorization),
    )
    return call(credential_handoff(
        operation=operation, operation_id=plan["action_id"], plan=plan,
        authorization=authorization,
    ))


def qualification_authority(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    reply = guest("native-qualification-authority",
                  qualification_request(plan, authorization))
    if (set(reply) != {"schema", "authority", "evidence_sha256"}
            or reply["schema"] != "secure-sandbox-native-stack-qualification-reply-v1"
            or operations.SHA256.fullmatch(str(reply["evidence_sha256"])) is None):
        raise NativeStackBackendError("native_stack_backend_qualification_reply_invalid")
    return validate_qualification_authority(reply["authority"], plan=plan, stack=stack)


def provider_action(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], *,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    evidence: list[str] = []
    if plan["identity"]["vendor_id"] == "openai":
        operation = {
            "signin-begin": "login", "status-verify": "status",
            "entitlement-verify": "refresh", "logout": "logout",
            "credential-destroy": "destroyLocalCredential",
            "recover": "recoverLocalState",
        }.get(plan["action"])
        if operation == "status":
            reply = credential(credential_handoff(
                operation="status", operation_id=str(uuid.uuid4()),
                plan=None, authorization=None,
            ))
            evidence.append(reply["reply_sha256"])
        elif operation is not None:
            reply = credential_operation(
                operation, plan["action"], plan, authorization, call=credential
            )
            evidence.append(reply["reply_sha256"])
        # Activation does not project a token or launch Codex. Projection is
        # reserved for the separate Touch-ID-bound session-start ceremony.
    authority = None
    if plan["action"] == "entitlement-verify":
        authority = qualification_authority(plan, authorization, stack, guest=guest)
    body = {
        "operation_id": plan["action_id"],
        "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "action": plan["action"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "harness_generation_id": plan["identity"]["harness_generation_id"],
        "runtime_authority": authority,
    }
    request = {"schema": "secure-sandbox-native-provider-guest-request-v1",
               **body, "request_sha256": digest(body)}
    reply = guest("native-provider-action", request)
    expected = {"schema", "action_id", "action", "plan_sha256",
                "authorization_sha256", "status", "evidence_sha256"}
    if (set(reply) != expected or reply["schema"] != PROVIDER_RESULT_SCHEMA
            or reply["action_id"] != plan["action_id"]
            or reply["action"] != plan["action"]
            or reply["plan_sha256"] != plan["plan_sha256"]
            or reply["authorization_sha256"] != authorization["authorization_sha256"]
            or reply["status"] != "verified"
            or operations.SHA256.fullmatch(str(reply["evidence_sha256"])) is None):
        raise NativeStackBackendError("native_stack_backend_guest_provider_invalid")
    evidence.append(reply["evidence_sha256"])
    return {**reply, "evidence_sha256": digest(evidence)}


def protected_status_request(
    plan: Mapping[str, Any], authorization: Mapping[str, Any], catalog_sha256: str
) -> dict[str, Any]:
    body = {
        "operation_id": plan["action_id"], "plan_sha256": plan["plan_sha256"],
        "authorization_sha256": authorization["authorization_sha256"],
        "stack_id": plan["identity"]["stack_id"],
        "stack_sha256": plan["identity"]["stack_sha256"],
        "catalog_sha256": catalog_sha256,
    }
    return {"schema": "secure-sandbox-native-stack-guest-status-request-v1",
            **body, "request_sha256": digest(body)}


def merge_openai_status(
    guest_status: Mapping[str, Any], credential_reply: Mapping[str, Any],
    stack: Mapping[str, Any], *, now: int,
) -> dict[str, Any]:
    status = credential_reply.get("status")
    if not isinstance(status, dict) or credential_reply.get("projection") is not None:
        raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
    fields = {"provider", "state", "client_id_sha256", "account_subject_sha256",
              "workspace_sha256", "scope_sha256", "access_expires_at_ms",
              "earliest_refresh_at_ms", "refresh_expires_at_ms",
              "custody_state", "custody_tombstone_sha256",
              "custody_projection_count"}
    if set(status) != fields or status["provider"] != "openAIChatGPT":
        raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
    state = status["state"]
    evidence = credential_reply["reply_sha256"]
    if state == "loggedOut":
        auth_state, binding_state, account, workspace = "signed-out", "unbound", None, None
    elif state in {"ready", "refreshRequired"}:
        auth_state = "signed-in" if state == "ready" else "expired"
        account, workspace = status["account_subject_sha256"], status["workspace_sha256"]
        if (operations.SHA256.fullmatch(str(account)) is None
                or operations.SHA256.fullmatch(str(workspace)) is None):
            raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
        configured = stack["account_binding"]
        if configured["account_subject_sha256"] is None:
            binding_state = "observed"
        elif (account, workspace) == (configured["account_subject_sha256"],
                                      configured["workspace_sha256"]):
            binding_state = "bound"
        else:
            binding_state = "mismatch"
    elif state == "blocked":
        auth_state, binding_state, account, workspace = "ambiguous", "ambiguous", None, None
    else:
        raise NativeStackBackendError("native_stack_backend_credential_status_invalid")
    authentication = {"state": auth_state, "observed_at": now,
                      "evidence_sha256": evidence}
    account_binding = {
        "state": binding_state, "observed_at": now, "evidence_sha256": evidence,
        "account_subject_sha256": account, "workspace_sha256": workspace,
    }
    credential_custody = {
        "state": status["custody_state"],
        "observed_at": now,
        "evidence_sha256": evidence,
        "tombstone_sha256": status["custody_tombstone_sha256"],
        "projection_count": status["custody_projection_count"],
    }
    return operations.make_status(
        stack=stack, harness=guest_status["harness"],
        authentication=authentication, account_binding=account_binding,
        credential_custody=credential_custody,
        program_entitlement=guest_status["program_entitlement"],
        model_entitlement=guest_status["model_entitlement"],
        network=guest_status["network"], activation=guest_status["activation"],
        live_run_count=guest_status["live_run_count"],
        fence_reason=guest_status["fence_reason"],
    )


def status(
    plan: Mapping[str, Any], authorization: Mapping[str, Any],
    stack: Mapping[str, Any], catalog_sha256: str, *, now: int,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    observed = operations.validate_status(guest(
        "native-stack-status",
        protected_status_request(plan, authorization, catalog_sha256),
    ))
    if plan["identity"]["vendor_id"] != "openai":
        return observed
    reply = credential(credential_handoff(
        operation="status", operation_id=str(uuid.uuid4()),
        plan=None, authorization=None,
    ))
    return merge_openai_status(observed, reply, stack, now=now)


def validate_inspect_request(
    value: object, *, catalog_path: Path = CATALOG_PATH
) -> tuple[dict[str, Any], dict[str, Any], str]:
    fields = {"schema", "operation_id", "stack_id", "stack_sha256",
              "catalog_sha256", "request_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeStackBackendError("native_stack_backend_inspect_fields_invalid")
    body = {key: value[key] for key in fields - {"schema", "request_sha256"}}
    if (value["schema"] != "secure-sandbox-native-stack-inspect-request-v1"
            or operations.UUID4.fullmatch(str(value["operation_id"])) is None
            or operations.SHA256.fullmatch(str(value["stack_sha256"])) is None
            or operations.SHA256.fullmatch(str(value["catalog_sha256"])) is None
            or value["request_sha256"] != digest(body)):
        raise NativeStackBackendError("native_stack_backend_inspect_invalid")
    try:
        MANAGER._trusted_directory(catalog_path.parent, os.geteuid())
        catalog = native_vendor_stack.load_catalog(catalog_path, private=True)
        catalog_sha256 = hashlib.sha256(
            native_vendor_stack.canonical_bytes(catalog)
        ).hexdigest()
        stack = native_vendor_stack.stack_by_id(catalog, value["stack_id"])
    except (
        OSError,
        MANAGER.NativeStackManagerError,
        native_vendor_stack.NativeVendorStackError,
    ) as error:
        raise NativeStackBackendError("native_stack_backend_catalog_untrusted") from error
    if (catalog_sha256 != value["catalog_sha256"]
            or native_vendor_stack.stack_revision(stack) != value["stack_sha256"]):
        raise NativeStackBackendError("native_stack_backend_inspect_catalog_changed")
    return dict(value), stack, catalog_sha256


def inspect_status(
    request: Mapping[str, Any], stack: Mapping[str, Any], *, now: int,
    credential: Callable[[Mapping[str, Any]], dict[str, Any]] = signed_credential_call,
    guest: Callable[[str, object], dict[str, Any]] = guest_call,
) -> dict[str, Any]:
    guest_body = {key: request[key] for key in (
        "operation_id", "stack_id", "stack_sha256", "catalog_sha256"
    )}
    guest_request = {
        "schema": "secure-sandbox-native-stack-inspect-status-request-v1",
        **guest_body, "request_sha256": digest(guest_body),
    }
    observed = operations.validate_status(
        guest("native-stack-inspect-status", guest_request)
    )
    if stack["vendor_id"] != "openai":
        return observed
    reply = credential(credential_handoff(
        operation="status", operation_id=request["operation_id"],
        plan=None, authorization=None,
    ))
    return merge_openai_status(observed, reply, stack, now=now)


def installed_release_id() -> str:
    release = Path(__file__).resolve().parent.name
    if operations.SHA256.fullmatch(release) is None:
        raise NativeStackBackendError("native_stack_backend_release_invalid")
    return release


def dispatch(operation: str, value: Mapping[str, Any], *, now: int) -> dict[str, Any]:
    if operation == "inspect-status":
        request, stack, _catalog_sha256 = validate_inspect_request(value)
        return inspect_status(request, stack, now=now)
    plan, authorization, stack, catalog_sha256 = validate_host_ticket(
        value, now=now, expected_host_release_id=installed_release_id()
    )
    if operation == "status":
        return status(
            plan, authorization, stack, catalog_sha256, now=now
        )
    if operation == "prepare-grant":
        return prepare_grant(plan, authorization, stack, now=now)
    if operation == "provider-action":
        return provider_action(plan, authorization, stack)
    raise NativeStackBackendError("native_stack_backend_operation_invalid")


def main() -> int:
    parser = __import__("argparse").ArgumentParser()
    parser.add_argument(
        "operation",
        choices=("status", "prepare-grant", "provider-action", "inspect-status"),
    )
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise NativeStackBackendError("native_stack_backend_root_required")
        result = dispatch(args.operation, read_canonical(), now=int(time.time()))
    except (NativeStackBackendError, OSError, KeyError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
