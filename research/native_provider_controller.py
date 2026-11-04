#!/usr/bin/env python3
"""Root-only content-free controller for Research native vendor stacks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "shared") not in sys.path:
    sys.path.insert(0, str(ROOT / "shared"))

from research import native_claude_adapter, native_lifecycle_fence
from shared import (
    harness_runtime_binding,
    model_stack_runtime_binding,
    native_egress,
    native_stack_operations,
    native_stack_runtime_binding,
    native_vendor_stack,
    runtime_authority,
    session_context_binding,
)
from shared.harness_generation_store import GenerationStore, GenerationStoreError


PROVIDER_REQUEST_SCHEMA = "secure-sandbox-native-provider-guest-request-v1"
PROVIDER_RESULT_SCHEMA = "secure-sandbox-native-stack-provider-result-v1"
STATUS_REQUEST_SCHEMA = "secure-sandbox-native-stack-status-request-v1"
INSPECT_REQUEST_SCHEMA = "secure-sandbox-native-stack-inspect-status-request-v1"
QUALIFICATION_REQUEST_SCHEMA = "secure-sandbox-native-stack-qualification-request-v1"
QUALIFICATION_REPLY_SCHEMA = "secure-sandbox-native-stack-qualification-reply-v1"
IDLE_REQUEST_SCHEMA = "secure-sandbox-native-stack-lifecycle-idle-request-v1"
IDLE_REPLY_SCHEMA = "secure-sandbox-native-stack-lifecycle-idle-reply-v1"
RELEASE_REQUEST_SCHEMA = "secure-sandbox-native-stack-lifecycle-release-request-v1"
RELEASE_REPLY_SCHEMA = "secure-sandbox-native-stack-lifecycle-release-reply-v1"
ERROR_SCHEMA = "secure-sandbox-native-provider-controller-error-v1"
MAX_REQUEST_BYTES = 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

CATALOG_PATH = Path("/etc/secure-sandbox/native-vendor-stacks.json")
BINDING_KEY_PATH = Path(
    "/var/lib/secure-sandbox/native-vendor/anthropic/account-binding.key"
)
STATE_ROOT = Path("/var/lib/secure-sandbox/native-vendor/controller")
TOMBSTONE_ROOT = STATE_ROOT / "credential-tombstones"
LOGIN_PROOF_ROOT = STATE_ROOT / "login-proofs"
CLAUDE_HOME = Path("/var/empty")
CLAUDE_CONFIG_ROOT = Path("/var/lib/secure-sandbox/native-vendor/anthropic")
ACTIVE_GRANT = Path("/var/lib/secure-sandbox/native-egress/active.json")
SESSION_STATE_ROOT = Path("/run/secure-sandbox/native-codex/session-state")
RELEASE_ROOT = Path("/usr/local/libexec/secure-sandbox-harnesses")
HARNESS_STATE_ROOT = Path("/var/lib/secure-sandbox/harnesses")
IDENTITY = "native-harness"

QUALIFICATION_PERSONA_SHA256 = hashlib.sha256(
    b"secure-sandbox-native-entitlement-qualification-persona-v1\n"
).hexdigest()
QUALIFICATION_TOOL_CATALOG_SHA256 = hashlib.sha256(
    b'{"schema":"secure-sandbox-native-qualification-tools-v1","tools":[]}\n'
).hexdigest()
QUALIFICATION_EXTENSION_SET_SHA256 = hashlib.sha256(
    b'{"extensions":[],"schema":"secure-sandbox-native-qualification-extensions-v1"}\n'
).hexdigest()

FORBIDDEN_SERIALIZED_NAMES = (
    b"access_token", b"refresh_token", b"authorization_code", b"pkce",
    b"client_secret", b"api_key", b"email", b"orgname",
    b"subscriptiontype", b"credential_path",
)


class NativeProviderControllerError(RuntimeError):
    """Stable fail-closed controller error."""


def canonical(value: object) -> bytes:
    try:
        raw = (json.dumps(
            value, allow_nan=False, ensure_ascii=True,
            separators=(",", ":"), sort_keys=True,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise NativeProviderControllerError("native_provider_value_invalid") from error
    if len(raw) > MAX_REQUEST_BYTES:
        raise NativeProviderControllerError("native_provider_value_oversized")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_canonical(stream: Any = sys.stdin.buffer) -> dict[str, Any]:
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if not 2 <= len(raw) <= MAX_REQUEST_BYTES:
        raise NativeProviderControllerError("native_provider_request_size_invalid")
    if any(name in raw.lower() for name in FORBIDDEN_SERIALIZED_NAMES):
        raise NativeProviderControllerError("native_provider_secret_field_forbidden")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeProviderControllerError("native_provider_request_json_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeProviderControllerError("native_provider_request_not_canonical")
    return value


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise NativeProviderControllerError(f"native_provider_{label}_fields_invalid")
    return value


def _uuid4(value: object, label: str) -> str:
    if not isinstance(value, str) or UUID4.fullmatch(value) is None:
        raise NativeProviderControllerError(f"native_provider_{label}_invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise NativeProviderControllerError(f"native_provider_{label}_invalid")
    return value


def _request_digest(request: Mapping[str, Any]) -> None:
    body = {key: request[key] for key in request
            if key not in {"schema", "request_sha256"}}
    if _sha256(request.get("request_sha256"), "request_sha256") != digest(body):
        raise NativeProviderControllerError("native_provider_request_digest_mismatch")


def validate_provider_request(value: object) -> dict[str, Any]:
    request = _exact(value, {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "action", "stack_sha256", "harness_generation_id",
        "runtime_authority", "request_sha256",
    }, "action_request")
    if request["schema"] != PROVIDER_REQUEST_SCHEMA:
        raise NativeProviderControllerError("native_provider_action_schema_invalid")
    _uuid4(request["operation_id"], "operation_id")
    for field in ("plan_sha256", "authorization_sha256", "stack_sha256",
                  "harness_generation_id"):
        _sha256(request[field], field)
    if request["action"] not in native_stack_operations.ACTIONS:
        raise NativeProviderControllerError("native_provider_action_invalid")
    if (request["action"] == "entitlement-verify") != (
        request["runtime_authority"] is not None
    ):
        raise NativeProviderControllerError("native_provider_runtime_authority_scope_invalid")
    if request["runtime_authority"] is not None:
        try:
            runtime_authority.validate_binding(request["runtime_authority"])
        except runtime_authority.RuntimeAuthorityError as error:
            raise NativeProviderControllerError(
                "native_provider_runtime_authority_invalid"
            ) from error
    _request_digest(request)
    return request


def validate_status_request(value: object, *, inspect: bool) -> dict[str, Any]:
    fields = ({"schema", "operation_id", "stack_id", "stack_sha256",
               "catalog_sha256", "request_sha256"} if inspect else {
        "schema", "operation_id", "plan_sha256", "authorization_sha256",
        "stack_id", "stack_sha256", "catalog_sha256", "request_sha256",
    })
    request = _exact(value, fields, "status_request")
    expected = INSPECT_REQUEST_SCHEMA if inspect else STATUS_REQUEST_SCHEMA
    if request["schema"] != expected:
        raise NativeProviderControllerError("native_provider_status_schema_invalid")
    _uuid4(request["operation_id"], "operation_id")
    if (not isinstance(request["stack_id"], str)
            or native_vendor_stack.IDENTIFIER.fullmatch(request["stack_id"]) is None):
        raise NativeProviderControllerError("native_provider_stack_id_invalid")
    for field in ("stack_sha256", "catalog_sha256"):
        _sha256(request[field], field)
    if not inspect:
        _sha256(request["plan_sha256"], "plan_sha256")
        _sha256(request["authorization_sha256"], "authorization_sha256")
    _request_digest(request)
    return request


def validate_qualification_request(value: object) -> dict[str, Any]:
    request = _exact(value, {
        "schema", "action_id", "plan_sha256", "authorization_sha256",
        "stack_sha256", "session_id", "persona_sha256",
        "tool_catalog_sha256", "extension_set_sha256", "request_sha256",
    }, "qualification_request")
    if request["schema"] != QUALIFICATION_REQUEST_SCHEMA:
        raise NativeProviderControllerError("native_provider_qualification_schema_invalid")
    _uuid4(request["action_id"], "action_id")
    _uuid4(request["session_id"], "session_id")
    for field in ("plan_sha256", "authorization_sha256", "stack_sha256",
                  "persona_sha256", "tool_catalog_sha256",
                  "extension_set_sha256"):
        _sha256(request[field], field)
    if (request["session_id"] != request["action_id"]
            or request["persona_sha256"] != QUALIFICATION_PERSONA_SHA256
            or request["tool_catalog_sha256"] != QUALIFICATION_TOOL_CATALOG_SHA256
            or request["extension_set_sha256"] != QUALIFICATION_EXTENSION_SET_SHA256):
        raise NativeProviderControllerError("native_provider_qualification_scope_invalid")
    _request_digest(request)
    return request


def validate_idle_request(value: object) -> dict[str, Any]:
    request = _exact(value, {
        "schema", "promotion_id", "plan_sha256", "catalog_sha256",
        "request_sha256",
    }, "idle_request")
    if request["schema"] != IDLE_REQUEST_SCHEMA:
        raise NativeProviderControllerError("native_provider_idle_schema_invalid")
    _uuid4(request["promotion_id"], "promotion_id")
    _sha256(request["plan_sha256"], "plan_sha256")
    _sha256(request["catalog_sha256"], "catalog_sha256")
    _request_digest(request)
    return request


def validate_release_request(value: object) -> dict[str, Any]:
    request = _exact(value, {
        "schema", "promotion_id", "plan_sha256", "catalog_sha256",
        "request_sha256",
    }, "release_request")
    if request["schema"] != RELEASE_REQUEST_SCHEMA:
        raise NativeProviderControllerError("native_provider_release_schema_invalid")
    _uuid4(request["promotion_id"], "promotion_id")
    for field in ("plan_sha256", "catalog_sha256"):
        _sha256(request[field], field)
    _request_digest(request)
    return request


def load_binding_key(path: Path = BINDING_KEY_PATH, *,
                     trusted_uid: int = 0, trusted_gid: int = 0) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1 or info.st_uid != trusted_uid
            or info.st_gid != trusted_gid or stat.S_IMODE(info.st_mode) != 0o400
            or info.st_size != 32):
        raise NativeProviderControllerError("native_provider_binding_key_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        raw = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
            or len(raw) != 32):
        raise NativeProviderControllerError("native_provider_binding_key_untrusted")
    return raw


def load_stack(stack_sha256: str, *, stack_id: str | None = None,
               catalog_sha256: str | None = None,
               catalog_path: Path = CATALOG_PATH) -> tuple[dict[str, Any], str]:
    try:
        catalog = native_vendor_stack.load_catalog(catalog_path, private=False)
    except (OSError, native_vendor_stack.NativeVendorStackError) as error:
        raise NativeProviderControllerError("native_provider_catalog_untrusted") from error
    observed = hashlib.sha256(native_vendor_stack.canonical_bytes(catalog)).hexdigest()
    if catalog_sha256 is not None and observed != catalog_sha256:
        raise NativeProviderControllerError("native_provider_catalog_digest_mismatch")
    matches = [item for item in catalog["stacks"]
               if native_vendor_stack.stack_revision(item) == stack_sha256
               and (stack_id is None or item["stack_id"] == stack_id)]
    if len(matches) != 1:
        raise NativeProviderControllerError("native_provider_stack_revision_missing")
    return matches[0], observed


def generation_runtime(generation_id: str, *, release_root: Path = RELEASE_ROOT,
                       state_root: Path = HARNESS_STATE_ROOT) -> dict[str, str]:
    try:
        store = GenerationStore(release_root, state_root)
        with store.inspection_locked():
            value = store.runtime_binding(generation_id)
        return harness_runtime_binding.validate_binding(value)
    except (GenerationStoreError, OSError,
            harness_runtime_binding.HarnessBindingError) as error:
        raise NativeProviderControllerError("native_provider_harness_unavailable") from error


def make_authority(stack: Mapping[str, Any], harness: Mapping[str, Any], *,
                   session_id: str, persona_sha256: str,
                   tool_catalog_sha256: str,
                   extension_set_sha256: str) -> dict[str, Any]:
    if (stack["harness"]["generation_id"] != harness["harness_generation_id"]
            or stack["harness"]["harness_id"] != harness["harness_id"]
            or stack["harness"]["adapter_id"] != harness["harness_adapter_id"]):
        raise NativeProviderControllerError("native_provider_harness_pairing_mismatch")
    try:
        return runtime_authority.make_binding(
            model_stack_binding=model_stack_runtime_binding.make_binding(
                model_stack_runtime_binding.NATIVE_MODE,
                native_stack_runtime_binding.make_binding(dict(stack))),
            session_context_binding=session_context_binding.make_binding(
                session_id=session_id, source_id=None,
                source_manifest_sha256=None, persona_sha256=persona_sha256,
                tool_catalog_sha256=tool_catalog_sha256,
                extension_set_sha256=extension_set_sha256),
            harness_binding=dict(harness))
    except Exception as error:
        raise NativeProviderControllerError("native_provider_authority_invalid") from error


def qualification_authority(value: object, *, catalog_path: Path = CATALOG_PATH,
                            runtime_loader: Callable[[str], dict[str, str]] = generation_runtime
                            ) -> dict[str, Any]:
    request = validate_qualification_request(value)
    stack, _ = load_stack(request["stack_sha256"], catalog_path=catalog_path)
    generation = stack["harness"]["generation_id"]
    if generation is None:
        raise NativeProviderControllerError("native_provider_harness_not_selected")
    authority = make_authority(
        stack, runtime_loader(generation), session_id=request["session_id"],
        persona_sha256=request["persona_sha256"],
        tool_catalog_sha256=request["tool_catalog_sha256"],
        extension_set_sha256=request["extension_set_sha256"])
    return {"schema": QUALIFICATION_REPLY_SCHEMA, "authority": authority,
            "evidence_sha256": digest({
                "authority_sha256": authority["binding_sha256"],
                "request_sha256": request["request_sha256"],
            })}


def _identity() -> pwd.struct_passwd:
    try:
        identity = pwd.getpwnam(IDENTITY)
    except KeyError as error:
        raise NativeProviderControllerError("native_provider_identity_missing") from error
    if identity.pw_uid == 0 or identity.pw_gid == 0:
        raise NativeProviderControllerError("native_provider_identity_invalid")
    return identity


def _command_prefix(identity: pwd.struct_passwd) -> tuple[str, ...]:
    return (
        "/usr/bin/setpriv", f"--reuid={identity.pw_uid}",
        f"--regid={identity.pw_gid}", "--clear-groups", "--no-new-privs", "--",
    )


def _read_state(stack_sha256: str, *, state_root: Path = STATE_ROOT,
                trusted_uid: int = 0) -> dict[str, Any]:
    path = state_root / f"{stack_sha256}.json"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {}
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_nlink != 1 or info.st_uid != trusted_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 64 * 1024):
        raise NativeProviderControllerError("native_provider_state_untrusted")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NativeProviderControllerError("native_provider_state_invalid") from error
    if not isinstance(value, dict) or raw != canonical(value):
        raise NativeProviderControllerError("native_provider_state_invalid")
    return value


def _write_state(stack_sha256: str, value: Mapping[str, Any], *,
                 state_root: Path = STATE_ROOT, trusted_uid: int = 0,
                 trusted_gid: int = 0) -> None:
    info = state_root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != trusted_uid or info.st_gid != trusted_gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise NativeProviderControllerError("native_provider_state_root_untrusted")
    payload = canonical(dict(value))
    if any(name in payload.lower() for name in FORBIDDEN_SERIALIZED_NAMES):
        raise NativeProviderControllerError("native_provider_state_secret_forbidden")
    descriptor, name = tempfile.mkstemp(prefix=f".{stack_sha256}.", dir=state_root)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, trusted_uid, trusted_gid)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, state_root / f"{stack_sha256}.json")
        directory = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_tombstone(stack_sha256: str, operation_id: str, *, now: int,
                     tombstone_root: Path = TOMBSTONE_ROOT,
                     trusted_uid: int = 0, trusted_gid: int = 0) -> str:
    info = tombstone_root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != trusted_uid or info.st_gid != trusted_gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise NativeProviderControllerError("native_provider_tombstone_root_untrusted")
    body = {"operation_id": operation_id, "stack_sha256": stack_sha256,
            "destroyed_at": now}
    value = {"schema": "secure-sandbox-native-credential-tombstone-v1", **body,
             "tombstone_sha256": digest(body)}
    _write_state(stack_sha256, value, state_root=tombstone_root,
                 trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    return value["tombstone_sha256"]


def _read_tombstone(stack_sha256: str, *, tombstone_root: Path = TOMBSTONE_ROOT,
                    trusted_uid: int = 0) -> str | None:
    value = _read_state(stack_sha256, state_root=tombstone_root,
                        trusted_uid=trusted_uid)
    if not value:
        return None
    fields = {"schema", "operation_id", "stack_sha256", "destroyed_at",
              "tombstone_sha256"}
    body = {key: value.get(key) for key in (
        "operation_id", "stack_sha256", "destroyed_at")}
    if (set(value) != fields
            or value["schema"] != "secure-sandbox-native-credential-tombstone-v1"
            or value["stack_sha256"] != stack_sha256
            or UUID4.fullmatch(str(value["operation_id"])) is None
            or not isinstance(value["destroyed_at"], int)
            or value["tombstone_sha256"] != digest(body)):
        raise NativeProviderControllerError("native_provider_tombstone_invalid")
    return value["tombstone_sha256"]


def write_login_proof(*, operation_id: str, plan_sha256: str,
                      authorization_sha256: str, stack_sha256: str,
                      harness_generation_id: str,
                      authentication: Mapping[str, Any],
                      account_binding: Mapping[str, Any],
                      proof_root: Path = LOGIN_PROOF_ROOT,
                      trusted_uid: int = 0, trusted_gid: int = 0) -> str:
    if authentication.get("state") != "signed-in" or account_binding.get("state") not in {
        "observed", "bound"
    }:
        raise NativeProviderControllerError("native_provider_login_proof_state_invalid")
    body = {
        "operation_id": _uuid4(operation_id, "operation_id"),
        "plan_sha256": _sha256(plan_sha256, "plan_sha256"),
        "authorization_sha256": _sha256(
            authorization_sha256, "authorization_sha256"),
        "stack_sha256": _sha256(stack_sha256, "stack_sha256"),
        "harness_generation_id": _sha256(
            harness_generation_id, "harness_generation_id"),
        "authentication": dict(authentication),
        "account_binding": dict(account_binding),
    }
    value = {"schema": "secure-sandbox-native-claude-login-proof-v1", **body,
             "proof_sha256": digest(body)}
    _write_state(operation_id, value, state_root=proof_root,
                 trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    return value["proof_sha256"]


def consume_login_proof(request: Mapping[str, Any], *,
                        proof_root: Path = LOGIN_PROOF_ROOT,
                        trusted_uid: int = 0) -> tuple[dict[str, Any], dict[str, Any], str]:
    value = _read_state(request["operation_id"], state_root=proof_root,
                        trusted_uid=trusted_uid)
    fields = {"schema", "operation_id", "plan_sha256", "authorization_sha256",
              "stack_sha256", "harness_generation_id", "authentication",
              "account_binding", "proof_sha256"}
    body = {key: value.get(key) for key in fields - {"schema", "proof_sha256"}}
    if (set(value) != fields
            or value.get("schema") != "secure-sandbox-native-claude-login-proof-v1"
            or any(value.get(field) != request[field] for field in (
                "operation_id", "plan_sha256", "authorization_sha256",
                "stack_sha256", "harness_generation_id"))
            or value.get("proof_sha256") != digest(body)
            or value.get("authentication", {}).get("state") != "signed-in"
            or value.get("account_binding", {}).get("state") not in {
                "observed", "bound"}):
        raise NativeProviderControllerError(
            "native_claude_interactive_login_channel_required")
    path = proof_root / f"{request['operation_id']}.json"
    path.unlink()
    directory = os.open(proof_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return value["authentication"], value["account_binding"], value["proof_sha256"]


def _unknown(state: str = "unknown") -> dict[str, Any]:
    return {"state": state, "observed_at": None, "evidence_sha256": None}


def _claude_observation(stack: Mapping[str, Any], harness: Mapping[str, Any], *,
                        now: int, binding_key_path: Path,
                        config_root: Path = CLAUDE_CONFIG_ROOT,
                        command_prefix: Sequence[str] | None,
                        runner: Callable[..., subprocess.CompletedProcess[bytes]] | None
                        ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    # Status and logout must work before the first account binding exists.  The
    # executable and environment are still admitted by the exact stack/harness
    # pairing, but no fabricated session authority is needed to observe the
    # provider's content-free authentication state.
    executable = native_claude_adapter.executable_for_harness(harness)
    environment = native_claude_adapter.login_environment(
        stack, harness, home=CLAUDE_HOME, config_root=config_root)
    prefix = tuple(command_prefix) if command_prefix is not None else _command_prefix(_identity())
    status = native_claude_adapter.observe_status(
        executable, environment, runner=runner, now=now,
        binding_key=load_binding_key(binding_key_path), command_prefix=prefix)
    authentication = {
        "state": status["state"] if status["state"] in {
            "signed-in", "signed-out", "ambiguous"} else "ambiguous",
        "observed_at": status["observed_at"],
        "evidence_sha256": status["evidence_sha256"],
    }
    account_subject = status["account_subject_sha256"]
    workspace = status["workspace_sha256"]
    configured = stack["account_binding"]
    if status["state"] != "signed-in" or account_subject is None or workspace is None:
        binding_state = "unbound" if status["state"] == "signed-out" else "ambiguous"
    elif configured["account_subject_sha256"] is None and configured["workspace_sha256"] is None:
        binding_state = "observed"
    elif (configured["account_subject_sha256"] == account_subject
          and configured["workspace_sha256"] == workspace):
        binding_state = "bound"
    else:
        binding_state = "mismatch"
    account = {
        "state": binding_state, "account_subject_sha256": account_subject,
        "workspace_sha256": workspace, "observed_at": status["observed_at"],
        "evidence_sha256": status["evidence_sha256"],
    }
    private = {"executable": executable, "environment": environment,
               "prefix": prefix}
    return authentication, account, private


def _live_runs(path: Path = SESSION_STATE_ROOT) -> int:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return 0
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise NativeProviderControllerError("native_provider_session_root_untrusted")
    count = 0
    for item in path.iterdir():
        child = item.lstat()
        if (UUID4.fullmatch(item.name) is None or not stat.S_ISDIR(child.st_mode)
                or stat.S_ISLNK(child.st_mode)):
            raise NativeProviderControllerError("native_provider_session_state_ambiguous")
        count += 1
    return count


def lifecycle_idle(value: object, *, session_root: Path = SESSION_STATE_ROOT,
                   lifecycle_root: Path = native_lifecycle_fence.ROOT,
                   trusted_uid: int = 0, trusted_gid: int = 0) -> dict[str, Any]:
    request = validate_idle_request(value)
    with native_lifecycle_fence.locked(
        root=lifecycle_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    ) as lifecycle:
        runs = _live_runs(session_root)
        if runs != 0:
            raise NativeProviderControllerError("native_provider_lifecycle_busy")
        fence_sha256 = native_lifecycle_fence.acquire_locked(
            lifecycle, promotion_id=request["promotion_id"],
            plan_sha256=request["plan_sha256"],
            catalog_sha256=request["catalog_sha256"],
            trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    evidence = digest({"promotion_id": request["promotion_id"],
                       "plan_sha256": request["plan_sha256"],
                       "catalog_sha256": request["catalog_sha256"],
                       "fence_sha256": fence_sha256,
                       "state": "idle", "live_run_count": runs})
    return {"schema": IDLE_REPLY_SCHEMA, "state": "idle", "live_run_count": 0,
            "evidence_sha256": evidence}


def lifecycle_release(value: object, *,
                      lifecycle_root: Path = native_lifecycle_fence.ROOT,
                      trusted_uid: int = 0, trusted_gid: int = 0) -> dict[str, Any]:
    request = validate_release_request(value)
    with native_lifecycle_fence.locked(
        root=lifecycle_root, trusted_uid=trusted_uid,
        trusted_gid=trusted_gid,
    ) as lifecycle:
        evidence = native_lifecycle_fence.release_locked(
            lifecycle, promotion_id=request["promotion_id"],
            plan_sha256=request["plan_sha256"],
            catalog_sha256=request["catalog_sha256"],
            trusted_uid=trusted_uid, trusted_gid=trusted_gid)
    return {"schema": RELEASE_REPLY_SCHEMA, "state": "released",
            "catalog_sha256": request["catalog_sha256"],
            "evidence_sha256": evidence}


def _open_custody_parent(stack: Mapping[str, Any], *, config_root: Path,
                         trusted_uid: int, service: pwd.struct_passwd
                         ) -> tuple[int, int, int]:
    root = stack_parent = -1
    try:
        root = os.open(config_root, os.O_RDONLY | os.O_DIRECTORY
                       | os.O_NOFOLLOW | os.O_CLOEXEC)
        root_info = os.fstat(root)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != trusted_uid
                or root_info.st_mode & 0o022):
            raise NativeProviderControllerError("native_provider_config_root_untrusted")
        stack_parent = os.open(
            stack["stack_id"], os.O_RDONLY | os.O_DIRECTORY
            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        parent_info = os.fstat(stack_parent)
        if (not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != service.pw_uid
                or parent_info.st_gid != service.pw_gid
                or parent_info.st_mode & 0o022
                or parent_info.st_dev != root_info.st_dev):
            raise NativeProviderControllerError("native_provider_config_parent_untrusted")
        result, root, stack_parent = (root, stack_parent, root_info.st_dev), -1, -1
        return result
    except FileNotFoundError as error:
        raise NativeProviderControllerError("native_provider_config_root_missing") from error
    finally:
        if stack_parent >= 0:
            os.close(stack_parent)
        if root >= 0:
            os.close(root)


def _delete_tree_at(directory: int, *, device: int,
                    service: pwd.struct_passwd, depth: int = 0,
                    budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [4096]
    if depth > 16:
        raise NativeProviderControllerError("native_provider_config_tree_too_deep")
    for name in os.listdir(directory):
        budget[0] -= 1
        if budget[0] < 0 or name in {".", ".."}:
            raise NativeProviderControllerError("native_provider_config_tree_oversized")
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (before.st_dev != device or before.st_uid != service.pw_uid
                or before.st_gid != service.pw_gid or before.st_mode & 0o022):
            raise NativeProviderControllerError("native_provider_config_entry_untrusted")
        if stat.S_ISDIR(before.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                opened = os.fstat(child)
                if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                        or not stat.S_ISDIR(opened.st_mode)):
                    raise NativeProviderControllerError(
                        "native_provider_config_entry_changed")
                _delete_tree_at(child, device=device, service=service,
                                depth=depth + 1, budget=budget)
                os.fsync(child)
            finally:
                os.close(child)
            after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise NativeProviderControllerError(
                    "native_provider_config_entry_changed")
            os.rmdir(name, dir_fd=directory)
        elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory)
            try:
                opened = os.fstat(descriptor)
                if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                        or not stat.S_ISREG(opened.st_mode)
                        or opened.st_nlink != 1):
                    raise NativeProviderControllerError(
                        "native_provider_config_entry_changed")
            finally:
                os.close(descriptor)
            os.unlink(name, dir_fd=directory)
        else:
            raise NativeProviderControllerError("native_provider_config_entry_untrusted")
    os.fsync(directory)


def _destroy_claude_config(stack: Mapping[str, Any], *, operation_id: str,
                           stack_sha256: str, now: int,
                           config_root: Path = CLAUDE_CONFIG_ROOT,
                           tombstone_root: Path = TOMBSTONE_ROOT,
                           trusted_uid: int = 0, trusted_gid: int = 0,
                           identity: pwd.struct_passwd | None = None) -> str:
    service = _identity() if identity is None else identity
    root = parent = child = -1
    try:
        root, parent, device = _open_custody_parent(
            stack, config_root=config_root, trusted_uid=trusted_uid,
            service=service)
        try:
            before = os.stat("claude-config", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            before = None
        if before is not None:
            child = os.open("claude-config", os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            opened = os.fstat(child)
            if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or opened.st_dev != device or opened.st_uid != service.pw_uid
                    or opened.st_gid != service.pw_gid
                    or opened.st_mode & 0o022):
                raise NativeProviderControllerError("native_provider_config_untrusted")
            _delete_tree_at(child, device=device, service=service)
            os.close(child)
            child = -1
            after = os.stat("claude-config", dir_fd=parent, follow_symlinks=False)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise NativeProviderControllerError("native_provider_config_changed")
            os.rmdir("claude-config", dir_fd=parent)
            os.fsync(parent)
        try:
            os.stat("claude-config", dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise NativeProviderControllerError(
                "native_provider_config_destroy_failed")
    finally:
        if child >= 0:
            os.close(child)
        if parent >= 0:
            os.close(parent)
        if root >= 0:
            os.close(root)
    return _write_tombstone(
        stack_sha256, operation_id, now=now, tombstone_root=tombstone_root,
        trusted_uid=trusted_uid, trusted_gid=trusted_gid)


def credential_custody_observation(
    stack: Mapping[str, Any], *, stack_sha256: str, now: int,
    config_root: Path = CLAUDE_CONFIG_ROOT,
    tombstone_root: Path = TOMBSTONE_ROOT, trusted_uid: int = 0,
    identity: pwd.struct_passwd | None = None,
) -> dict[str, Any]:
    if stack["vendor_id"] != "anthropic":
        return {"state": "ambiguous", "observed_at": now,
                "evidence_sha256": digest({"state": "ambiguous",
                                            "stack_sha256": stack_sha256}),
                "tombstone_sha256": None, "projection_count": None}
    service = _identity() if identity is None else identity
    root = parent = child = -1
    try:
        root, parent, device = _open_custody_parent(
            stack, config_root=config_root, trusted_uid=trusted_uid,
            service=service)
        try:
            before = os.stat("claude-config", dir_fd=parent, follow_symlinks=False)
            child = os.open("claude-config", os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            opened = os.fstat(child)
            trusted = (
                stat.S_ISDIR(before.st_mode)
                and (before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino)
                and opened.st_dev == device and opened.st_uid == service.pw_uid
                and opened.st_gid == service.pw_gid and not opened.st_mode & 0o022
            )
            info = opened if trusted else False
        except FileNotFoundError:
            info = None
        except OSError:
            info = False
    except NativeProviderControllerError:
        info = False
    finally:
        if child >= 0:
            os.close(child)
        if parent >= 0:
            os.close(parent)
        if root >= 0:
            os.close(root)
    tombstone = _read_tombstone(
        stack_sha256, tombstone_root=tombstone_root, trusted_uid=trusted_uid)
    if info is None:
        state = "absent"
    elif info is not False:
        state, tombstone = "retained", None
    else:
        state, tombstone = "ambiguous", None
    projection_count = None if state == "ambiguous" else 0
    evidence = digest({"state": state, "stack_sha256": stack_sha256,
                       "tombstone_sha256": tombstone,
                       "projection_count": projection_count})
    return {"state": state, "observed_at": now,
            "evidence_sha256": evidence, "tombstone_sha256": tombstone,
            "projection_count": projection_count}


def provider_action(
    value: object, *, catalog_path: Path = CATALOG_PATH,
    binding_key_path: Path = BINDING_KEY_PATH,
    state_root: Path = STATE_ROOT, tombstone_root: Path = TOMBSTONE_ROOT,
    login_proof_root: Path = STATE_ROOT / "login-proofs",
    config_root: Path = CLAUDE_CONFIG_ROOT, now: int | None = None,
    runtime_loader: Callable[[str], dict[str, str]] = generation_runtime,
    claude_runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    command_prefix: Sequence[str] | None = None,
    trusted_uid: int | None = None, trusted_gid: int | None = None,
) -> dict[str, Any]:
    request = validate_provider_request(value)
    stack, _ = load_stack(request["stack_sha256"], catalog_path=catalog_path)
    if stack["harness"]["generation_id"] != request["harness_generation_id"]:
        raise NativeProviderControllerError("native_provider_harness_generation_mismatch")
    harness = runtime_loader(request["harness_generation_id"])
    timestamp = int(time.time()) if now is None else now
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    gid = os.getegid() if trusted_gid is None else trusted_gid
    state = _read_state(request["stack_sha256"], state_root=state_root,
                        trusted_uid=uid)
    evidence: dict[str, Any] = {
        "action": request["action"], "operation_id": request["operation_id"],
        "stack_sha256": request["stack_sha256"],
        "harness_generation_id": request["harness_generation_id"],
    }

    if stack["vendor_id"] == "anthropic":
        if request["action"] == "signin-begin":
            authentication, account, login_evidence = consume_login_proof(
                request, proof_root=login_proof_root, trusted_uid=uid)
            private = None
        else:
            authentication, account, private = _claude_observation(
                stack, harness, now=timestamp, binding_key_path=binding_key_path,
                config_root=config_root, command_prefix=command_prefix,
                runner=claude_runner)
            login_evidence = None
        state["authentication"] = authentication
        state["account_binding"] = account
        evidence["authentication_state"] = authentication["state"]
        evidence["account_binding_state"] = account["state"]
        action = request["action"]
        if action == "signin-begin":
            evidence["login_proof_sha256"] = login_evidence
        if action == "status-verify" and authentication["state"] != "signed-in":
            raise NativeProviderControllerError("native_provider_not_signed_in")
        if action == "entitlement-verify":
            supplied = runtime_authority.validate_binding(request["runtime_authority"])
            context = supplied["session_context_binding"]
            expected = make_authority(
                stack, harness, session_id=context["session_id"],
                persona_sha256=context["persona_sha256"],
                tool_catalog_sha256=context["tool_catalog_sha256"],
                extension_set_sha256=context["extension_set_sha256"])
            if supplied != expected:
                raise NativeProviderControllerError(
                    "native_provider_runtime_authority_mismatch")
            executable = native_claude_adapter.executable_for_authority(expected)
            environment = native_claude_adapter.child_environment(
                expected, home=CLAUDE_HOME, config_root=config_root)
            native_claude_adapter.validate_environment(environment)
            receipt = native_claude_adapter.verify_entitlement(
                executable, environment,
                effort=stack["model"]["settings"]["effort"],
                runner=claude_runner, now=timestamp,
                command_prefix=private["prefix"])  # type: ignore[index]
            if receipt["state"] != "verified":
                raise NativeProviderControllerError("native_provider_entitlement_denied")
            observation = {"state": "verified", "observed_at": timestamp,
                           "evidence_sha256": receipt["evidence_sha256"]}
            state["program_entitlement"] = observation
            state["model_entitlement"] = dict(observation)
            evidence["entitlement_state"] = "verified"
        elif action == "logout":
            result = native_claude_adapter._run_bounded(
                native_claude_adapter.logout_command(private["executable"]),  # type: ignore[index]
                private["environment"], maximum=native_claude_adapter.MAX_STATUS_BYTES,  # type: ignore[index]
                timeout=30, command_prefix=private["prefix"], runner=claude_runner)  # type: ignore[index]
            if result.returncode != 0:
                raise NativeProviderControllerError("native_provider_logout_failed")
            after = native_claude_adapter.observe_status(
                private["executable"], private["environment"],  # type: ignore[index]
                runner=claude_runner, now=timestamp,
                binding_key=load_binding_key(binding_key_path),
                command_prefix=private["prefix"])  # type: ignore[index]
            if after["state"] != "signed-out":
                raise NativeProviderControllerError("native_provider_logout_not_verified")
            state["authentication"] = {
                "state": "signed-out", "observed_at": timestamp,
                "evidence_sha256": after["evidence_sha256"]}
        elif action == "credential-destroy":
            if authentication["state"] != "signed-out":
                raise NativeProviderControllerError(
                    "native_provider_credential_destroy_requires_logout")
            tombstone = _destroy_claude_config(
                stack, operation_id=request["operation_id"],
                stack_sha256=request["stack_sha256"], now=timestamp,
                config_root=config_root, tombstone_root=tombstone_root,
                trusted_uid=uid, trusted_gid=gid)
            evidence["credential_custody_state"] = "absent"
            evidence["tombstone_sha256"] = tombstone
    elif request["action"] == "entitlement-verify":
        raise NativeProviderControllerError(
            "native_codex_projection_channel_required")

    action = request["action"]
    if action == "activate":
        activation_evidence = digest(evidence)
        state["activation"] = {
            "state": "active", "receipt_sha256": activation_evidence,
            "observed_at": timestamp, "evidence_sha256": activation_evidence}
    elif action in {"rollback", "logout", "credential-destroy", "recover"}:
        inactive_evidence = digest(evidence)
        state["activation"] = {
            "state": "inactive", "receipt_sha256": None,
            "observed_at": timestamp, "evidence_sha256": inactive_evidence}
        state.pop("fence_reason", None)
    evidence_sha256 = digest(evidence)
    _write_state(request["stack_sha256"], state, state_root=state_root,
                 trusted_uid=uid, trusted_gid=gid)
    return {"schema": PROVIDER_RESULT_SCHEMA,
            "action_id": request["operation_id"], "action": action,
            "plan_sha256": request["plan_sha256"],
            "authorization_sha256": request["authorization_sha256"],
            "status": "verified", "evidence_sha256": evidence_sha256}


def _network_observation(stack: Mapping[str, Any], *, now: int,
                         identity_gid: int, grant_path: Path) -> dict[str, Any]:
    try:
        grant = native_egress.load_grant(
            grant_path, now=now, expected_uid=0, expected_gid=identity_gid,
            expected_mode=0o640)
    except FileNotFoundError:
        return {"phase": "closed", "grant_sha256": None,
                "expires_at": None, "observed_at": now}
    except (OSError, native_egress.NativeEgressError):
        return {"phase": "ambiguous", "grant_sha256": None,
                "expires_at": None, "observed_at": now}
    binding = grant["binding"]
    native = (binding["value"] if binding["kind"] in {"stack-intent", "native-stack"}
              else binding["value"]["model_stack_binding"]["authority"])
    if native.get("stack_sha256") != native_vendor_stack.stack_revision(dict(stack)):
        return {"phase": "ambiguous", "grant_sha256": grant["grant_sha256"],
                "expires_at": grant["expires_at"], "observed_at": now}
    return {"phase": grant["phase"], "grant_sha256": grant["grant_sha256"],
            "expires_at": grant["expires_at"], "observed_at": now}


def operational_status(
    value: object, *, inspect: bool, catalog_path: Path = CATALOG_PATH,
    binding_key_path: Path = BINDING_KEY_PATH,
    state_root: Path = STATE_ROOT, tombstone_root: Path = TOMBSTONE_ROOT,
    config_root: Path = CLAUDE_CONFIG_ROOT, grant_path: Path = ACTIVE_GRANT,
    session_root: Path = SESSION_STATE_ROOT, now: int | None = None,
    runtime_loader: Callable[[str], dict[str, str]] = generation_runtime,
    claude_runner: Callable[..., subprocess.CompletedProcess[bytes]] | None = None,
    command_prefix: Sequence[str] | None = None,
    identity: pwd.struct_passwd | None = None,
    trusted_uid: int | None = None,
) -> dict[str, Any]:
    request = validate_status_request(value, inspect=inspect)
    stack, _ = load_stack(
        request["stack_sha256"], stack_id=request["stack_id"],
        catalog_sha256=request["catalog_sha256"], catalog_path=catalog_path)
    timestamp = int(time.time()) if now is None else now
    uid = os.geteuid() if trusted_uid is None else trusted_uid
    service = _identity() if identity is None else identity
    generation = stack["harness"]["generation_id"]
    harness: dict[str, str] | None = None
    if generation is None:
        harness_status = {
            "state": "missing", "generation_id": None, "binding_sha256": None,
            "observed_at": timestamp,
            "evidence_sha256": digest({"state": "missing",
                                        "stack_sha256": request["stack_sha256"]})}
    else:
        try:
            harness = runtime_loader(generation)
            paired = (harness["harness_id"] == stack["harness"]["harness_id"]
                      and harness["harness_adapter_id"]
                      == stack["harness"]["adapter_id"])
            harness_status = {
                "state": "admitted" if paired else "mismatch",
                "generation_id": generation,
                "binding_sha256": harness["binding_sha256"],
                "observed_at": timestamp, "evidence_sha256": digest(harness)}
        except NativeProviderControllerError:
            harness_status = {
                "state": "ambiguous", "generation_id": generation,
                "binding_sha256": None, "observed_at": timestamp,
                "evidence_sha256": digest({"state": "ambiguous",
                                            "generation_id": generation})}
            harness = None

    if stack["vendor_id"] == "anthropic" and harness is not None:
        try:
            authentication, account, _private = _claude_observation(
                stack, harness, now=timestamp, binding_key_path=binding_key_path,
                config_root=config_root, command_prefix=command_prefix,
                runner=claude_runner)
        except (NativeProviderControllerError,
                native_claude_adapter.NativeClaudeAdapterError):
            evidence = digest({"state": "ambiguous",
                               "stack_sha256": request["stack_sha256"]})
            authentication = {"state": "ambiguous", "observed_at": timestamp,
                              "evidence_sha256": evidence}
            account = {"state": "ambiguous", "account_subject_sha256": None,
                       "workspace_sha256": None, "observed_at": timestamp,
                       "evidence_sha256": evidence}
    else:
        evidence = digest({"state": "ambiguous",
                           "stack_sha256": request["stack_sha256"]})
        authentication = {"state": "ambiguous", "observed_at": timestamp,
                          "evidence_sha256": evidence}
        account = {"state": "ambiguous", "account_subject_sha256": None,
                   "workspace_sha256": None, "observed_at": timestamp,
                   "evidence_sha256": evidence}

    custody = credential_custody_observation(
        stack, stack_sha256=request["stack_sha256"], now=timestamp,
        config_root=config_root, tombstone_root=tombstone_root,
        trusted_uid=uid, identity=service)
    state = _read_state(request["stack_sha256"], state_root=state_root,
                        trusted_uid=uid)
    program = state.get("program_entitlement", _unknown())
    model = state.get("model_entitlement", _unknown())
    activation = state.get("activation", {
        "state": "inactive", "receipt_sha256": None,
        "observed_at": timestamp,
        "evidence_sha256": digest({"state": "inactive",
                                    "stack_sha256": request["stack_sha256"]})})
    return native_stack_operations.make_status(
        stack=stack, harness=harness_status, authentication=authentication,
        credential_custody=custody, account_binding=account,
        program_entitlement=program, model_entitlement=model,
        network=_network_observation(
            stack, now=timestamp, identity_gid=service.pw_gid,
            grant_path=grant_path),
        activation=activation, live_run_count=_live_runs(session_root),
        fence_reason=state.get("fence_reason"))


def dispatch(operation: str, value: object) -> dict[str, Any]:
    if operation == "native-stack-status":
        return operational_status(value, inspect=False)
    if operation == "native-stack-inspect-status":
        return operational_status(value, inspect=True)
    if operation == "native-provider-action":
        return provider_action(value)
    if operation == "native-qualification-authority":
        return qualification_authority(value)
    if operation == "native-stack-lifecycle-idle":
        return lifecycle_idle(value)
    if operation == "native-stack-lifecycle-release":
        return lifecycle_release(value)
    raise NativeProviderControllerError("native_provider_operation_invalid")


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=(
        "native-stack-status", "native-stack-inspect-status",
        "native-provider-action", "native-qualification-authority",
        "native-stack-lifecycle-idle", "native-stack-lifecycle-release"))
    args = parser.parse_args(arguments)
    try:
        raw = canonical(dispatch(args.operation, read_canonical()))
        if any(name in raw.lower() for name in FORBIDDEN_SERIALIZED_NAMES):
            raise NativeProviderControllerError(
                "native_provider_reply_secret_field_forbidden")
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.flush()
        return 0
    except (NativeProviderControllerError,
            native_lifecycle_fence.NativeLifecycleFenceError,
            OSError, ValueError) as error:
        reason = str(error)
        if re.fullmatch(r"[a-z0-9_]{1,96}", reason) is None:
            reason = "native_provider_rejected"
        sys.stderr.buffer.write(canonical({"schema": ERROR_SCHEMA,
            "status": "rejected", "error": reason}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
