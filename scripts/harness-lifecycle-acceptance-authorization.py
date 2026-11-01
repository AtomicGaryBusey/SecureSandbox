#!/usr/bin/env python3
"""Protected acceptance-only Touch ID authorization consumer."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import pwd
import re
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import time
from pathlib import Path
from typing import Any


PROTECTED_RELEASES = Path(
    "/usr/local/libexec/secure-sandbox-harness-acceptance/releases"
)
STATE_ROOT = Path("/var/db/SecureSandbox/harness-lifecycle-acceptance")
MAX_JSON = 1024 * 1024
DRIVER = "touchid-authorization-fixture"
CAMPAIGN_RELATIVE = Path(
    "Library/Application Support/SecureSandbox/harness-acceptance"
)
CONTROL_CLIENT = Path("/usr/local/libexec/secure-sandbox-host/current/control_client")
SSH_CONFIG = Path("/usr/local/libexec/secure-sandbox-host/current/ssh_config")
RESEARCH_CONTROL = "sandbox-research-control"
RECEIPT_ROOT = Path("/usr/local/var/log/secure-sandbox/authorization-receipts")
UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)


def require_protected_main_path(path: Path, effective_uid: int) -> None:
    if effective_uid != 0:
        return
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(PROTECTED_RELEASES)
    except ValueError as error:
        raise SystemExit("authorization_driver_protected_invocation_required") from error
    if (len(relative.parts) != 3 or relative.parts[1:] != ("scripts", path.name)
            or len(relative.parts[0]) != 40
            or any(character not in "0123456789abcdef" for character in relative.parts[0])):
        raise SystemExit("authorization_driver_protected_invocation_required")


if __name__ == "__main__":
    require_protected_main_path(Path(__file__), os.geteuid())


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import (  # noqa: E402
    AcceptanceError,
    CASE_BY_ID,
    canonical,
    digest,
    validate_campaign,
)
from harness_lifecycle_acceptance_interactive import (  # noqa: E402
    InteractiveAcceptanceError,
    consume,
    empty_ledger,
    make_plan,
    validate_ledger,
    validate_plan,
)
import harness_generation_store as generation_store  # noqa: E402


SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-authorization-consumer-v1"
ERROR_SCHEMA = "secure-sandbox-harness-lifecycle-acceptance-authorization-error-v1"


class AuthorizationDriverError(RuntimeError):
    """Stable failure for the protected acceptance authorization consumer."""


def load_script(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AuthorizationDriverError("authorization_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def trusted_directory(path: Path, uid: int, mode: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode):
        raise AuthorizationDriverError("authorization_state_directory_untrusted")


def trusted_json(path: Path, uid: int, mode: int) -> dict[str, Any]:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= MAX_JSON):
        raise AuthorizationDriverError("authorization_state_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor); data = bytearray()
        while len(data) <= MAX_JSON:
            chunk = os.read(descriptor, min(65536, MAX_JSON + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
            or len(data) != opened.st_size or len(data) > MAX_JSON):
        raise AuthorizationDriverError("authorization_state_file_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationDriverError("authorization_state_json_invalid") from error
    if not isinstance(value, dict) or canonical(value) != bytes(data):
        raise AuthorizationDriverError("authorization_state_json_noncanonical")
    return value


def parse_argument(raw: str, label: str) -> dict[str, Any]:
    try:
        encoded = raw.encode("ascii")
        value = json.loads(encoded)
    except (UnicodeEncodeError, json.JSONDecodeError) as error:
        raise AuthorizationDriverError(f"authorization_{label}_invalid") from error
    if (not 0 < len(encoded) <= MAX_JSON or not isinstance(value, dict)
            or json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":"), sort_keys=True).encode("ascii") != encoded):
        raise AuthorizationDriverError(f"authorization_{label}_noncanonical")
    return value


def atomic_replace(path: Path, value: dict[str, Any], uid: int, mode: int) -> None:
    payload = canonical(value)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.new-", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AuthorizationDriverError("authorization_state_write_failed")
            view = view[written:]
        os.fchown(descriptor, uid, -1); os.fchmod(descriptor, mode); os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def publish_exact(path: Path, value: dict[str, Any], uid: int, mode: int) -> None:
    def existing_exact() -> None:
        info = path.lstat()
        if info.st_nlink > 1:
            prefix = f".{path.name}.publish-"
            aliases: list[Path] = []
            with os.scandir(path.parent) as entries:
                for entry in entries:
                    if not entry.name.startswith(prefix):
                        continue
                    candidate = entry.stat(follow_symlinks=False)
                    if (candidate.st_dev, candidate.st_ino) == (info.st_dev, info.st_ino):
                        aliases.append(path.parent / entry.name)
            if len(aliases) != info.st_nlink - 1:
                raise AuthorizationDriverError("authorization_publish_alias_invalid")
            for alias in aliases:
                alias.unlink()
            fsync_directory(path.parent)
        if trusted_json(path, uid, mode) != value:
            raise AuthorizationDriverError("authorization_existing_record_mismatch")

    if os.path.lexists(path):
        existing_exact()
        return
    payload = canonical(value)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.publish-", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise AuthorizationDriverError("authorization_state_write_failed")
            view = view[written:]
        os.fchown(descriptor, uid, -1); os.fchmod(descriptor, mode); os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            existing_exact()
            return
        fsync_directory(path.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        fsync_directory(path.parent)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def recover_transaction(state: Path, campaign: dict[str, Any], uid: int) -> None:
    journal_path = state / "transaction.json"
    if not os.path.lexists(journal_path):
        return
    journal = trusted_json(journal_path, uid, 0o600)
    expected = {
        "schema", "campaign_id", "campaign_sha256", "prior_ledger_sha256",
        "next_ledger", "result", "journal_sha256",
    }
    unsigned = {name: item for name, item in journal.items() if name != "journal_sha256"}
    next_ledger = journal.get("next_ledger"); result = journal.get("result")
    if (set(journal) != expected
            or journal.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-authorization-transaction-v1"
            or journal.get("campaign_id") != campaign["campaign_id"]
            or journal.get("campaign_sha256") != campaign["campaign_sha256"]
            or not isinstance(next_ledger, dict) or not isinstance(result, dict)
            or journal.get("journal_sha256") != digest(unsigned)):
        raise AuthorizationDriverError("authorization_transaction_invalid")
    validate_ledger(next_ledger, campaign)
    result_unsigned = {name: item for name, item in result.items()
                       if name != "result_sha256"}
    authorization_sha256 = result.get("authorization_sha256")
    expected_result = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "plan_id",
        "plan_sha256", "transaction_id", "operation", "generation_id",
        "operator_uid", "authorization_sha256", "prior_ledger_sha256",
        "ledger_sha256", "candidate_authority", "production_material_used",
        "production_store_access", "lifecycle_mutation_performed", "result_sha256",
    }
    if (set(result) != expected_result
            or result.get("schema")
            != "secure-sandbox-harness-lifecycle-acceptance-interactive-result-v1"
            or result.get("status") != "authorized-for-acceptance-only"
            or result.get("campaign_id") != campaign["campaign_id"]
            or result.get("campaign_sha256") != campaign["campaign_sha256"]
            or result.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or result.get("source_commit") != campaign["source_commit"]
            or not isinstance(result.get("operator_uid"), int)
            or isinstance(result.get("operator_uid"), bool)
            or not 1 <= result["operator_uid"] < 2 ** 31
            or result.get("candidate_authority") != "none"
            or result.get("production_material_used") is not False
            or result.get("production_store_access") is not False
            or result.get("lifecycle_mutation_performed") is not False
            or not isinstance(authorization_sha256, str)
            or authorization_sha256
               not in next_ledger["consumed_authorization_sha256"]
            or result.get("ledger_sha256") != next_ledger["ledger_sha256"]
            or result.get("prior_ledger_sha256") != journal["prior_ledger_sha256"]
            or result.get("result_sha256") != digest(result_unsigned)):
        raise AuthorizationDriverError("authorization_transaction_result_invalid")
    ledger_path = state / "ledger.json"
    ledger = trusted_json(ledger_path, uid, 0o600)
    if ledger.get("ledger_sha256") == journal["prior_ledger_sha256"]:
        atomic_replace(ledger_path, next_ledger, uid, 0o600)
    elif ledger != next_ledger:
        raise AuthorizationDriverError("authorization_transaction_ledger_mismatch")
    result_path = state / f"result-{authorization_sha256}.json"
    if os.path.lexists(result_path):
        if trusted_json(result_path, uid, 0o400) != result:
            raise AuthorizationDriverError("authorization_transaction_result_mismatch")
    else:
        atomic_replace(result_path, result, uid, 0o400)
    journal_path.unlink()
    fsync_directory(state)


def state_directory(plan: dict[str, Any], root: Path, uid: int) -> Path:
    campaign_id = plan.get("campaign_id")
    case_id = plan.get("case_id")
    if not isinstance(campaign_id, str) or not isinstance(case_id, str):
        raise AuthorizationDriverError("authorization_campaign_id_invalid")
    authorization = root / campaign_id / "interactive" / "authorization"
    path = authorization / case_id
    trusted_directory(root, uid, 0o700)
    trusted_directory(root / campaign_id, uid, 0o700)
    trusted_directory(root / campaign_id / "interactive", uid, 0o700)
    trusted_directory(authorization, uid, 0o700)
    trusted_directory(path, uid, 0o700)
    return path


def create_directory(path: Path, uid: int, mode: int) -> None:
    try:
        path.mkdir(mode=mode)
    except FileExistsError:
        trusted_directory(path, uid, mode)
        return
    os.chown(path, uid, -1)
    path.chmod(mode)
    trusted_directory(path, uid, mode)
    fsync_directory(path.parent)


def isolated_store(root: Path, campaign_id: str, uid: int) -> generation_store.GenerationStore:
    interactive = root / campaign_id / "interactive"
    return generation_store.GenerationStore(
        interactive / "store-release", interactive / "store-state", uid=uid,
    )


def validate_isolated_store(value: object) -> dict[str, Any]:
    if (not isinstance(value, dict)
            or value.get("schema") != generation_store.STATUS_SCHEMA
            or value.get("status") != "verified"
            or value.get("admission") != "open"
            or value.get("recovery_pending") is not False
            or value.get("active_generation_id") is not None
            or value.get("predecessor_generation_id") is not None
            or value.get("selector_epoch") != 0
            or value.get("highest_release_sequence") != 0
            or value.get("revoked_generation_ids") != []
            or value.get("generations") != []
            or not isinstance(value.get("boundary"), dict)
            or value["boundary"].get("active_generation_id") is not None
            or value["boundary"].get("generation_count") != 0):
        raise AuthorizationDriverError("authorization_isolated_store_invalid")
    return value


def validate_research_status(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationDriverError("authorization_research_status_invalid")
    expected = {
        "schema", "status", "admission", "recovery_pending",
        "active_generation_id", "predecessor_generation_id", "selector_epoch",
        "highest_release_sequence", "revoked_generation_ids", "generations",
        "boundary",
    }
    boundary = value.get("boundary")
    if (set(value) != expected
            or value.get("schema") != generation_store.STATUS_SCHEMA
            or value.get("status") != "verified"
            or value.get("admission") not in {"open", "fenced"}
            or not isinstance(value.get("recovery_pending"), bool)
            or not isinstance(value.get("selector_epoch"), int)
            or isinstance(value.get("selector_epoch"), bool)
            or value["selector_epoch"] < 0
            or not isinstance(value.get("highest_release_sequence"), int)
            or isinstance(value.get("highest_release_sequence"), bool)
            or value["highest_release_sequence"] < 0
            or not isinstance(value.get("revoked_generation_ids"), list)
            or value["revoked_generation_ids"]
               != sorted(set(value["revoked_generation_ids"]))
            or any(not isinstance(item, str)
                   or generation_store.SHA256_RE.fullmatch(item) is None
                   for item in value["revoked_generation_ids"])
            or not isinstance(value.get("generations"), list)
            or not isinstance(boundary, dict)
            or set(boundary) != {
                "schema", "status", "active_generation_id", "generation_count",
                "catalog_sha256", "selector_sha256", "floor_sha256",
            }
            or boundary.get("schema")
               != "secure-sandbox-harness-generation-boundary-v1"
            or boundary.get("status") != "verified"
            or boundary.get("active_generation_id") != value["active_generation_id"]
            or boundary.get("generation_count") != len(value["generations"])
            or any(not isinstance(boundary.get(name), str)
                   or generation_store.SHA256_RE.fullmatch(boundary[name]) is None
                   for name in ("catalog_sha256", "selector_sha256", "floor_sha256"))):
        raise AuthorizationDriverError("authorization_research_status_invalid")
    for name in ("active_generation_id", "predecessor_generation_id"):
        item = value.get(name)
        if item is not None and (
                not isinstance(item, str)
                or generation_store.SHA256_RE.fullmatch(item) is None):
            raise AuthorizationDriverError("authorization_research_status_invalid")
    try:
        records = {
            generation_store.GenerationStore._validate_record(record)["generation_id"]: record
            for record in value["generations"]
        }
    except (generation_store.GenerationStoreError, TypeError) as error:
        raise AuthorizationDriverError("authorization_research_status_invalid") from error
    if (len(records) != len(value["generations"])
            or value["generations"] != sorted(
                value["generations"], key=lambda item: item["generation_id"],
            )
            or any(item is not None and item not in records
                   for item in (
                       value["active_generation_id"],
                       value["predecessor_generation_id"],
                   ))):
        raise AuthorizationDriverError("authorization_research_status_invalid")
    return value


def research_status() -> dict[str, Any]:
    command = [
        str(CONTROL_CLIENT), "client", "--ssh-config", str(SSH_CONFIG),
        "--timeout-seconds", "30", RESEARCH_CONTROL, "run",
        "harness-generation-status",
    ]
    try:
        completed = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=40,
            start_new_session=True,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuthorizationDriverError("authorization_research_status_failed") from error
    if (completed.returncode != 0 or not 0 < len(completed.stdout) <= MAX_JSON
            or len(completed.stderr) > MAX_JSON):
        raise AuthorizationDriverError("authorization_research_status_failed")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorizationDriverError("authorization_research_status_invalid") from error
    if canonical(value) != completed.stdout:
        raise AuthorizationDriverError("authorization_research_status_noncanonical")
    return validate_research_status(value)


def prepare_case(campaign: dict[str, Any], case_id: str, operator_uid: int, *,
                 root: Path = STATE_ROOT, uid: int = 0,
                 now: int | None = None,
                 research_before: dict[str, Any] | None = None) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    validated_campaign = validate_campaign(campaign, current_time)
    case = CASE_BY_ID.get(case_id)
    if (case is None or case.category != "authorization"
            or not 1 <= operator_uid < 2 ** 31):
        raise AuthorizationDriverError("authorization_prepare_case_invalid")
    expected_generation = digest({
        "campaign_sha256": validated_campaign["campaign_sha256"],
        "case_id": case_id, "role": "expected-generation",
    })
    lifetime = 30 if case_id == "touchid-expired-plan" else 300
    stored_plan = make_plan(
        validated_campaign, case_id, "authorize", expected_generation,
        operator_uid, current_time, lifetime=lifetime,
    )
    request_plan = stored_plan
    if case_id == "touchid-changed-plan":
        request_plan = make_plan(
            validated_campaign, case_id, "authorize", expected_generation,
            operator_uid, current_time, lifetime=lifetime,
        )
    elif case_id == "touchid-wrong-generation":
        request_plan = dict(stored_plan)
        request_plan["generation_id"] = digest({
            "campaign_sha256": validated_campaign["campaign_sha256"],
            "case_id": case_id, "role": "wrong-generation",
        })
        request_plan["plan_sha256"] = digest({
            name: item for name, item in request_plan.items()
            if name != "plan_sha256"
        })
        validate_plan(request_plan, validated_campaign, current_time)

    trusted_directory(root, uid, 0o700)
    campaign_root = root / validated_campaign["campaign_id"]
    create_directory(campaign_root, uid, 0o700)
    interactive_root = campaign_root / "interactive"
    create_directory(interactive_root, uid, 0o700)
    store = isolated_store(root, validated_campaign["campaign_id"], uid)
    try:
        store.prepare()
        store_status = validate_isolated_store(store.inspect_status())
    except generation_store.GenerationStoreError as error:
        raise AuthorizationDriverError("authorization_isolated_store_invalid") from error
    research_snapshot = validate_research_status(
        store_status if research_before is None else research_before,
    )
    authorization_root = interactive_root / "authorization"
    create_directory(authorization_root, uid, 0o700)
    state = authorization_root / case_id
    if os.path.lexists(state):
        raise AuthorizationDriverError("authorization_case_already_prepared")
    create_directory(state, uid, 0o700)
    for name, value, mode in (
        ("campaign.json", validated_campaign, 0o400),
        ("plan.json", stored_plan, 0o400),
        ("request-plan.json", request_plan, 0o400),
        ("ledger.json", empty_ledger(validated_campaign), 0o600),
        ("store-before.json", store_status, 0o400),
        ("research-before.json", research_snapshot, 0o400),
    ):
        atomic_replace(state / name, value, uid, mode)
    prepared = {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-authorization-prepared-v1",
        "status": "prepared", "campaign_id": validated_campaign["campaign_id"],
        "campaign_sha256": validated_campaign["campaign_sha256"],
        "source_commit": validated_campaign["source_commit"], "case_id": case_id,
        "procedure_sha256": stored_plan["procedure_sha256"],
        "operator_uid": operator_uid, "request_plan": request_plan,
        "stored_plan_sha256": stored_plan["plan_sha256"],
        "isolated_store_sha256": digest(store_status),
        "research_before_sha256": digest(research_snapshot),
        "candidate_authority": "none", "production_material_used": False,
        "production_store_access": False,
    }
    prepared["prepared_sha256"] = digest(prepared)
    atomic_replace(state / "prepared.json", prepared, uid, 0o400)
    return prepared


def protected_context(case_id: str, operator_uid: int, current_time: int,
                      uid: int) -> dict[str, Any]:
    if not 1 <= operator_uid < 2 ** 31:
        raise AuthorizationDriverError("authorization_operator_uid_invalid")
    try:
        home = Path(pwd.getpwuid(operator_uid).pw_dir)
    except (KeyError, OSError) as error:
        raise AuthorizationDriverError("authorization_operator_home_invalid") from error
    campaign_root = home / CAMPAIGN_RELATIVE
    trusted_directory(campaign_root, operator_uid, 0o700)
    campaign = validate_campaign(
        trusted_json(campaign_root / "campaign.json", operator_uid, 0o600),
        current_time,
    )
    observations = campaign_root / "observations"
    trusted_directory(observations, operator_uid, 0o700)
    acceptance_cli = load_script(
        "harness_lifecycle_acceptance_authorization_cli",
        ROOT / "scripts/harness-lifecycle-acceptance.py",
    )
    supervisor = load_script(
        "harness_lifecycle_acceptance_authorization_supervisor",
        ROOT / "scripts/harness-lifecycle-acceptance-supervisor.py",
    )
    try:
        manifest = acceptance_cli.verify_protected_driver(
            PROTECTED_RELEASES.parent, campaign["source_commit"], DRIVER, uid,
        )
        next_value = acceptance_cli.next_case(
            campaign, observations, observation_uid=uid,
            directory_uid=operator_uid,
        )
        machine = supervisor.current_machine_identity()
    except (AcceptanceError, supervisor.SupervisorError, OSError, ValueError) as error:
        raise AuthorizationDriverError("authorization_preflight_failed") from error
    case = next_value.get("case") if isinstance(next_value, dict) else None
    if (not isinstance(case, dict) or case.get("case_id") != case_id
            or case.get("category") != "authorization"
            or case.get("procedure", {}).get("driver") != DRIVER
            or machine != campaign["machine_identity_sha256"]
            or manifest.get("source_commit") != campaign["source_commit"]):
        raise AuthorizationDriverError("authorization_binding_mismatch")
    return campaign


def protected_prepare(case_id: str, operator_uid: int, *,
                      root: Path = STATE_ROOT, uid: int = 0,
                      now: int | None = None,
                      research_reader=research_status) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    campaign = protected_context(case_id, operator_uid, current_time, uid)
    return prepare_case(
        campaign, case_id, operator_uid, root=root, uid=uid,
        now=current_time, research_before=research_reader(),
    )


def validate_result(value: dict[str, Any], campaign: dict[str, Any],
                    plan: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema", "status", "campaign_id", "campaign_sha256",
        "machine_identity_sha256", "source_commit", "case_id", "plan_id",
        "plan_sha256", "transaction_id", "operation", "generation_id",
        "operator_uid", "authorization_sha256", "prior_ledger_sha256",
        "ledger_sha256", "candidate_authority", "production_material_used",
        "production_store_access", "lifecycle_mutation_performed", "result_sha256",
    }
    unsigned = {name: item for name, item in value.items() if name != "result_sha256"}
    if (set(value) != expected
            or value.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-interactive-result-v1"
            or value.get("status") != "authorized-for-acceptance-only"
            or value.get("campaign_id") != campaign["campaign_id"]
            or value.get("campaign_sha256") != campaign["campaign_sha256"]
            or value.get("machine_identity_sha256")
               != campaign["machine_identity_sha256"]
            or value.get("source_commit") != campaign["source_commit"]
            or value.get("case_id") != plan["case_id"]
            or value.get("plan_id") != plan["plan_id"]
            or value.get("plan_sha256") != plan["plan_sha256"]
            or value.get("transaction_id") != plan["transaction_id"]
            or value.get("operation") != plan["operation"]
            or value.get("generation_id") != plan["generation_id"]
            or value.get("operator_uid") != plan["operator_uid"]
            or value.get("authorization_sha256")
               not in ledger["consumed_authorization_sha256"]
            or value.get("ledger_sha256") != ledger["ledger_sha256"]
            or value.get("candidate_authority") != "none"
            or value.get("production_material_used") is not False
            or value.get("production_store_access") is not False
            or value.get("lifecycle_mutation_performed") is not False
            or value.get("result_sha256") != digest(unsigned)):
        raise AuthorizationDriverError("authorization_result_invalid")
    return value


def expected_error_bytes(case_id: str, request_id: str) -> bytes:
    if case_id in {"touchid-changed-plan", "touchid-wrong-generation"}:
        error = "interactive_plan_changed"
    elif case_id == "touchid-replay":
        error = "interactive_authorization_replayed"
    elif case_id == "touchid-expired-plan":
        return canonical({
            "action": "inspect_diagnostic_code_before_retry",
            "code": "harness_authorization_expired",
            "operation": "harness-acceptance-authorize",
            "outcome": "rejected", "phase": "authorization",
            "request_id": request_id, "retry": "forbidden",
            "schema": "secure-sandbox-operator-diagnostic-v1",
        })
    else:
        raise AuthorizationDriverError("authorization_rejection_case_invalid")
    return canonical({
        "schema": ERROR_SCHEMA, "status": "rejected", "error": error,
    })


def validate_broker_receipt(receipt: dict[str, Any], campaign: dict[str, Any],
                            request_plan: dict[str, Any], request_id: str,
                            result_raw: bytes | None) -> str:
    base = {
        "schema", "request_id", "request_sha256", "status", "started_at",
        "completed_at", "operation", "declared_agent", "declared_session",
        "identity_evidence", "authorization_method", "ceremony", "purpose",
        "resource", "exit_status", "stdout_sha256", "stderr_sha256",
        "host_release_id", "acceptance_campaign_sha256", "acceptance_case_id",
        "acceptance_generation_id", "acceptance_operator_uid",
        "acceptance_plan_sha256", "acceptance_source_commit",
    }
    case_id = request_plan["case_id"]
    cancellation = case_id == "touchid-cancel"
    expected_fields = base | (
        {"authorization_ui_bundle_sha256", "outcome"} if cancellation else set()
    )
    if (set(receipt) != expected_fields
            or receipt.get("schema")
               != "secure-sandbox-operator-authorization-receipt-v1"
            or receipt.get("request_id") != request_id
            or not isinstance(receipt.get("request_sha256"), str)
            or generation_store.SHA256_RE.fullmatch(receipt["request_sha256"]) is None
            or receipt.get("operation") != "harness-acceptance-authorize"
            or receipt.get("identity_evidence") != "operator-declared"
            or receipt.get("authorization_method") != "touch-id"
            or receipt.get("resource") != "Disposable harness lifecycle acceptance plan"
            or not isinstance(receipt.get("host_release_id"), str)
            or generation_store.SHA256_RE.fullmatch(receipt["host_release_id"]) is None
            or receipt.get("acceptance_campaign_sha256")
               != campaign["campaign_sha256"]
            or receipt.get("acceptance_case_id") != case_id
            or receipt.get("acceptance_generation_id")
               != request_plan["generation_id"]
            or receipt.get("acceptance_operator_uid") != request_plan["operator_uid"]
            or receipt.get("acceptance_plan_sha256") != request_plan["plan_sha256"]
            or receipt.get("acceptance_source_commit") != campaign["source_commit"]
            or not isinstance(receipt.get("started_at"), int)
            or isinstance(receipt.get("started_at"), bool)
            or not isinstance(receipt.get("completed_at"), int)
            or isinstance(receipt.get("completed_at"), bool)
            or receipt["completed_at"] < receipt["started_at"]
            or not isinstance(receipt.get("stdout_sha256"), str)
            or not isinstance(receipt.get("stderr_sha256"), str)):
        raise AuthorizationDriverError("authorization_broker_receipt_invalid")
    empty = hashlib.sha256(b"").hexdigest()
    if cancellation:
        if (receipt.get("status") != "cancelled"
                or receipt.get("ceremony") != "cancel-test"
                or receipt.get("exit_status") != 20
                or receipt.get("outcome") != "cancelled"
                or receipt.get("stdout_sha256") != empty
                or receipt.get("stderr_sha256") != empty
                or not isinstance(receipt.get("authorization_ui_bundle_sha256"), str)
                or generation_store.SHA256_RE.fullmatch(
                    receipt["authorization_ui_bundle_sha256"],
                ) is None):
            raise AuthorizationDriverError("authorization_broker_receipt_invalid")
        return "cancelled"
    if receipt.get("ceremony") != "approve":
        raise AuthorizationDriverError("authorization_broker_receipt_invalid")
    if case_id == "touchid-approve-exact-plan":
        if (receipt.get("status") != "succeeded" or receipt.get("exit_status") != 0
                or result_raw is None
                or receipt.get("stdout_sha256")
                   != hashlib.sha256(result_raw).hexdigest()
                or receipt.get("stderr_sha256") != empty):
            raise AuthorizationDriverError("authorization_broker_receipt_invalid")
        return "authorized"
    expected_error = expected_error_bytes(case_id, request_id)
    if (receipt.get("status") != "failed" or receipt.get("exit_status") != 1
            or receipt.get("stdout_sha256") != empty
            or receipt.get("stderr_sha256")
               != hashlib.sha256(expected_error).hexdigest()):
        raise AuthorizationDriverError("authorization_broker_receipt_invalid")
    return "rejected"


def finalize_case(campaign: dict[str, Any], case_id: str, request_id: str,
                  receipt: dict[str, Any], research_after: dict[str, Any], *,
                  root: Path = STATE_ROOT, uid: int = 0,
                  now: int | None = None) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    validated_campaign = validate_campaign(campaign, current_time)
    if UUID4.fullmatch(request_id) is None:
        raise AuthorizationDriverError("authorization_request_id_invalid")
    case = CASE_BY_ID.get(case_id)
    if case is None or case.category != "authorization":
        raise AuthorizationDriverError("authorization_finalize_case_invalid")
    state = (root / validated_campaign["campaign_id"] / "interactive"
             / "authorization" / case_id)
    trusted_directory(state, uid, 0o700)
    stored_campaign = trusted_json(state / "campaign.json", uid, 0o400)
    if stored_campaign != validated_campaign:
        raise AuthorizationDriverError("authorization_campaign_changed")
    stored_plan = trusted_json(state / "plan.json", uid, 0o400)
    request_plan = trusted_json(state / "request-plan.json", uid, 0o400)
    prepared = trusted_json(state / "prepared.json", uid, 0o400)
    expected_prepared = {
        "schema", "status", "campaign_id", "campaign_sha256", "source_commit",
        "case_id", "procedure_sha256", "operator_uid", "request_plan",
        "stored_plan_sha256", "isolated_store_sha256", "research_before_sha256",
        "candidate_authority", "production_material_used", "production_store_access",
        "prepared_sha256",
    }
    if (set(prepared) != expected_prepared
            or prepared.get("schema")
               != "secure-sandbox-harness-lifecycle-acceptance-authorization-prepared-v1"
            or prepared.get("status") != "prepared"
            or prepared.get("prepared_sha256") != digest({
            name: item for name, item in prepared.items()
            if name != "prepared_sha256"
            }) or prepared.get("case_id") != case_id
            or prepared.get("request_plan") != request_plan
            or prepared.get("stored_plan_sha256") != stored_plan["plan_sha256"]):
        raise AuthorizationDriverError("authorization_prepared_invalid")
    plan_time = min(current_time, request_plan["expires_at"] - 1)
    validate_plan(stored_plan, validated_campaign, plan_time)
    validate_plan(request_plan, validated_campaign, plan_time)
    ledger = validate_ledger(
        trusted_json(state / "ledger.json", uid, 0o600), validated_campaign,
    )
    expected_consumed = 1 if case_id in {
        "touchid-approve-exact-plan", "touchid-replay",
    } else 0
    if ledger["epoch"] != expected_consumed or len(
            ledger["consumed_authorization_sha256"]) != expected_consumed:
        raise AuthorizationDriverError("authorization_ledger_outcome_invalid")
    result_paths = list(state.glob("result-*.json"))
    if len(result_paths) != expected_consumed:
        raise AuthorizationDriverError("authorization_result_inventory_invalid")
    result = None; result_raw = None
    if result_paths:
        result = trusted_json(result_paths[0], uid, 0o400)
        result = validate_result(result, validated_campaign, stored_plan, ledger)
        result_raw = canonical(result)
    outcome = validate_broker_receipt(
        receipt, validated_campaign, request_plan, request_id,
        result_raw if case_id == "touchid-approve-exact-plan" else None,
    )
    research_before = validate_research_status(
        trusted_json(state / "research-before.json", uid, 0o400),
    )
    research_after_path = state / "research-after.json"
    validated_after = (
        validate_research_status(trusted_json(research_after_path, uid, 0o400))
        if os.path.lexists(research_after_path)
        else validate_research_status(research_after)
    )
    if validated_after != research_before:
        raise AuthorizationDriverError("authorization_research_selector_changed")
    store_before = trusted_json(state / "store-before.json", uid, 0o400)
    try:
        store_after = validate_isolated_store(
            isolated_store(root, validated_campaign["campaign_id"], uid).inspect_status(),
        )
    except generation_store.GenerationStoreError as error:
        raise AuthorizationDriverError("authorization_isolated_store_invalid") from error
    if store_after != store_before:
        raise AuthorizationDriverError("authorization_isolated_store_changed")
    publish_exact(state / "broker-receipt.json", receipt, uid, 0o400)
    publish_exact(research_after_path, validated_after, uid, 0o400)
    observed_at = receipt["completed_at"]
    if case_id == "touchid-approve-exact-plan":
        readback = {
            "schema":
                "secure-sandbox-harness-lifecycle-acceptance-plan-readback-v1",
            "status": "verified", "kind": "plan-readback",
            "campaign_id": validated_campaign["campaign_id"],
            "campaign_sha256": validated_campaign["campaign_sha256"],
            "machine_identity_sha256": validated_campaign["machine_identity_sha256"],
            "source_commit": validated_campaign["source_commit"],
            "case_id": case_id, "procedure_sha256": stored_plan["procedure_sha256"],
            "plan_id": stored_plan["plan_id"],
            "plan_sha256": stored_plan["plan_sha256"],
            "transaction_id": stored_plan["transaction_id"],
            "generation_id": stored_plan["generation_id"],
            "operator_uid": stored_plan["operator_uid"],
            "broker_receipt_sha256": digest(receipt),
            "result_sha256": result["result_sha256"] if result is not None else None,
            "isolated_store_sha256": digest(store_after),
            "candidate_authority": "none", "production_material_used": False,
            "production_store_access": False, "lifecycle_mutation_performed": False,
            "observed_at": observed_at,
        }
    else:
        readback = {
            "schema":
                "secure-sandbox-harness-lifecycle-acceptance-selector-readback-v1",
            "status": "rejected", "kind": "selector-readback",
            "campaign_id": validated_campaign["campaign_id"],
            "campaign_sha256": validated_campaign["campaign_sha256"],
            "machine_identity_sha256": validated_campaign["machine_identity_sha256"],
            "source_commit": validated_campaign["source_commit"],
            "case_id": case_id, "procedure_sha256": stored_plan["procedure_sha256"],
            "request_plan_sha256": request_plan["plan_sha256"],
            "expected_generation_id": stored_plan["generation_id"],
            "requested_generation_id": request_plan["generation_id"],
            "research_before": research_before,
            "research_after": validated_after, "selector_unchanged": True,
            "broker_receipt_sha256": digest(receipt),
            "isolated_store_sha256": digest(store_after),
            "candidate_authority": "none", "production_material_used": False,
            "production_store_access": False, "lifecycle_mutation_performed": False,
            "observed_at": observed_at,
        }
    readback["readback_sha256"] = digest(readback)
    publish_exact(state / "readback.json", readback, uid, 0o400)
    finalized = {
        "schema": "secure-sandbox-harness-lifecycle-acceptance-authorization-finalized-v1",
        "status": "verified", "outcome": outcome,
        "campaign_id": validated_campaign["campaign_id"],
        "campaign_sha256": validated_campaign["campaign_sha256"],
        "source_commit": validated_campaign["source_commit"], "case_id": case_id,
        "procedure_sha256": stored_plan["procedure_sha256"],
        "request_id": request_id, "request_plan_sha256": request_plan["plan_sha256"],
        "stored_plan_sha256": stored_plan["plan_sha256"],
        "broker_receipt_sha256": digest(receipt),
        "research_status_sha256": digest(validated_after),
        "isolated_store_sha256": digest(store_after),
        "readback_sha256": readback["readback_sha256"],
        "result_sha256": None if result is None else result["result_sha256"],
        "candidate_authority": "none", "production_material_used": False,
        "production_store_access": False, "lifecycle_mutation_performed": False,
        "observed_at": observed_at,
    }
    finalized["finalized_sha256"] = digest(finalized)
    publish_exact(state / "finalized.json", finalized, uid, 0o400)
    return finalized


def protected_finalize(case_id: str, request_id: str, operator_uid: int, *,
                       root: Path = STATE_ROOT, uid: int = 0,
                       now: int | None = None,
                       research_reader=research_status,
                       receipt_root: Path = RECEIPT_ROOT) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    campaign = protected_context(case_id, operator_uid, current_time, uid)
    if UUID4.fullmatch(request_id) is None:
        raise AuthorizationDriverError("authorization_request_id_invalid")
    trusted_directory(receipt_root, uid, 0o700)
    receipt = trusted_json(receipt_root / f"{request_id}.json", uid, 0o600)
    return finalize_case(
        campaign, case_id, request_id, receipt, research_reader(),
        root=root, uid=uid, now=current_time,
    )


def consume_request(plan: dict[str, Any], authorization: dict[str, Any], *,
                    root: Path = STATE_ROOT, uid: int = 0,
                    operator_uid: int | None = None,
                    now: int | None = None) -> dict[str, Any]:
    current_time = int(time.time()) if now is None else now
    expected_operator_uid = plan.get("operator_uid")
    if (not isinstance(expected_operator_uid, int)
            or isinstance(expected_operator_uid, bool)
            or not 1 <= expected_operator_uid < 2 ** 31
            or (operator_uid is not None and operator_uid != expected_operator_uid)):
        raise AuthorizationDriverError("authorization_operator_uid_mismatch")
    state = state_directory(plan, root, uid)
    lock_path = state / "consume.lock"
    descriptor = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600,
    )
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise AuthorizationDriverError("authorization_lock_untrusted")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        campaign = validate_campaign(trusted_json(state / "campaign.json", uid, 0o400), current_time)
        recover_transaction(state, campaign, uid)
        stored_plan = trusted_json(state / "plan.json", uid, 0o400)
        validate_plan(stored_plan, campaign, current_time)
        try:
            store = isolated_store(root, campaign["campaign_id"], uid)
            store_before = validate_isolated_store(store.inspect_status())
        except generation_store.GenerationStoreError as error:
            raise AuthorizationDriverError("authorization_isolated_store_invalid") from error
        if store_before != trusted_json(state / "store-before.json", uid, 0o400):
            raise AuthorizationDriverError("authorization_isolated_store_changed")
        ledger_path = state / "ledger.json"
        ledger = trusted_json(ledger_path, uid, 0o600)
        validate_ledger(ledger, campaign)
        try:
            result, next_ledger = consume(
                stored_plan, plan, authorization, ledger, campaign, current_time,
            )
        except (AcceptanceError, InteractiveAcceptanceError) as error:
            try:
                store_after = validate_isolated_store(store.inspect_status())
            except generation_store.GenerationStoreError as store_error:
                raise AuthorizationDriverError(
                    "authorization_isolated_store_invalid",
                ) from store_error
            if store_after != store_before:
                raise AuthorizationDriverError("authorization_isolated_store_changed")
            raise AuthorizationDriverError(str(error)) from error
        try:
            store_after = validate_isolated_store(store.inspect_status())
        except generation_store.GenerationStoreError as error:
            raise AuthorizationDriverError("authorization_isolated_store_invalid") from error
        if store_after != store_before:
            raise AuthorizationDriverError("authorization_isolated_store_changed")
        result_path = state / f"result-{result['authorization_sha256']}.json"
        if os.path.lexists(result_path):
            raise AuthorizationDriverError("authorization_result_exists")
        journal = {
            "schema":
                "secure-sandbox-harness-lifecycle-acceptance-authorization-transaction-v1",
            "campaign_id": campaign["campaign_id"],
            "campaign_sha256": campaign["campaign_sha256"],
            "prior_ledger_sha256": ledger["ledger_sha256"],
            "next_ledger": next_ledger, "result": result,
        }
        journal["journal_sha256"] = digest(journal)
        journal_path = state / "transaction.json"
        if os.path.lexists(journal_path):
            raise AuthorizationDriverError("authorization_transaction_exists")
        atomic_replace(journal_path, journal, uid, 0o600)
        atomic_replace(ledger_path, next_ledger, uid, 0o600)
        atomic_replace(result_path, result, uid, 0o400)
        journal_path.unlink()
        fsync_directory(state)
        if stored_plan["case_id"] == "touchid-replay":
            try:
                consume(
                    stored_plan, stored_plan, authorization, next_ledger,
                    campaign, current_time,
                )
            except InteractiveAcceptanceError as error:
                if str(error) != "interactive_authorization_replayed":
                    raise AuthorizationDriverError(
                        "authorization_replay_check_failed",
                    ) from error
                raise AuthorizationDriverError(
                    "interactive_authorization_replayed",
                ) from error
            raise AuthorizationDriverError("authorization_replay_check_failed")
        return result
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Prepare or consume an acceptance-only Touch ID receipt",
    )
    commands = value.add_subparsers(dest="command", required=True)
    prepare_command = commands.add_parser("prepare")
    prepare_command.add_argument("--case", required=True)
    prepare_command.add_argument("--operator-uid", type=int, required=True)
    finalize_command = commands.add_parser("finalize")
    finalize_command.add_argument("--case", required=True)
    finalize_command.add_argument("--request-id", required=True)
    finalize_command.add_argument("--operator-uid", type=int, required=True)
    consume_command = commands.add_parser("consume")
    consume_command.add_argument("--plan-json", required=True)
    consume_command.add_argument("--authorization-json", required=True)
    consume_command.add_argument("--operator-uid", type=int, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if os.geteuid() != 0 or args.operator_uid <= 0:
        raise AuthorizationDriverError("authorization_root_context_required")
    if args.command == "prepare":
        result = protected_prepare(args.case, args.operator_uid)
    elif args.command == "finalize":
        result = protected_finalize(
            args.case, args.request_id, args.operator_uid,
        )
    else:
        result = consume_request(
            parse_argument(args.plan_json, "plan"),
            parse_argument(args.authorization_json, "receipt"),
            operator_uid=args.operator_uid,
        )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, AuthorizationDriverError, OSError, ValueError) as error:
        reason = str(error) if isinstance(error, AuthorizationDriverError) \
            else "authorization_consumer_failed"
        print(json.dumps({"schema": ERROR_SCHEMA, "status": "rejected", "error": reason},
                         ensure_ascii=True, separators=(",", ":"), sort_keys=True),
              file=sys.stderr)
        raise SystemExit(1)
