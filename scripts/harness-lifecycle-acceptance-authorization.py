#!/usr/bin/env python3
"""Protected acceptance-only Touch ID authorization consumer."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import stat
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


def prepare_case(campaign: dict[str, Any], case_id: str, operator_uid: int, *,
                 root: Path = STATE_ROOT, uid: int = 0,
                 now: int | None = None) -> dict[str, Any]:
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
        "candidate_authority": "none", "production_material_used": False,
        "production_store_access": False,
    }
    prepared["prepared_sha256"] = digest(prepared)
    atomic_replace(state / "prepared.json", prepared, uid, 0o400)
    return prepared


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
    value = argparse.ArgumentParser(description="Consume an acceptance-only Touch ID receipt")
    commands = value.add_subparsers(dest="command", required=True)
    consume_command = commands.add_parser("consume")
    consume_command.add_argument("--plan-json", required=True)
    consume_command.add_argument("--authorization-json", required=True)
    consume_command.add_argument("--operator-uid", type=int, required=True)
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if os.geteuid() != 0 or args.operator_uid <= 0:
        raise AuthorizationDriverError("authorization_root_context_required")
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
