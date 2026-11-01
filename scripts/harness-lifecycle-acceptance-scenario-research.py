#!/usr/bin/env python3
"""Research-side executor for isolated runtime and management acceptance cases."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
sys.dont_write_bytecode = True
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import canonical, validate_campaign  # noqa: E402
from harness_lifecycle_acceptance_scenarios import (  # noqa: E402
    MANAGEMENT_CASES,
    RUNTIME_CASES,
    SCENARIO_CASES,
    TOUCH_ID_CASES,
    ScenarioError,
    execute_case,
    initial_state,
    validate_result,
)


STATE_ROOT = Path("/var/lib/secure-sandbox/harness-lifecycle-acceptance")
MAX_JSON = 1024 * 1024


class ResearchScenarioError(RuntimeError):
    """Stable failure for the protected Research scenario runner."""


def trusted_directory(path: Path, uid: int, mode: int) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or stat.S_IMODE(info.st_mode) != mode):
        raise ResearchScenarioError("scenario_research_directory_untrusted")


def trusted_json(path: Path, uid: int, mode: int) -> dict[str, Any]:
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_uid != uid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= MAX_JSON):
        raise ResearchScenarioError("scenario_research_file_untrusted")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor); raw = bytearray()
        while len(raw) <= MAX_JSON:
            chunk = os.read(descriptor, min(65536, MAX_JSON + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (opened.st_size, opened.st_mtime_ns)
               != (after.st_size, after.st_mtime_ns)
            or len(raw) != opened.st_size or len(raw) > MAX_JSON):
        raise ResearchScenarioError("scenario_research_file_changed")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResearchScenarioError("scenario_research_json_invalid") from error
    if not isinstance(value, dict) or canonical(value) != bytes(raw):
        raise ResearchScenarioError("scenario_research_json_noncanonical")
    return value


def parse_argument(raw: str | None, label: str) -> dict[str, Any] | None:
    if raw is None:
        return None
    try:
        encoded = raw.encode("ascii"); value = json.loads(encoded)
    except (UnicodeEncodeError, json.JSONDecodeError) as error:
        raise ResearchScenarioError(f"scenario_research_{label}_invalid") from error
    if (not isinstance(value, dict) or not 0 < len(encoded) <= MAX_JSON
            or canonical(value) != encoded):
        raise ResearchScenarioError(f"scenario_research_{label}_noncanonical")
    return value


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
                raise ResearchScenarioError("scenario_research_publish_alias_invalid")
            for alias in aliases:
                alias.unlink()
            fsync_directory(path.parent)
        if trusted_json(path, uid, mode) != value:
            raise ResearchScenarioError("scenario_research_existing_record_mismatch")

    if os.path.lexists(path):
        existing_exact()
        return
    payload = canonical(value)
    descriptor, name = tempfile.mkstemp(
        prefix=f".{path.name}.publish-", dir=path.parent,
    )
    temporary = Path(name)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ResearchScenarioError("scenario_research_write_failed")
            view = view[written:]
        os.fchown(descriptor, uid, -1); os.fchmod(descriptor, mode); os.fsync(descriptor)
        os.close(descriptor); descriptor = -1
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


def _create_directory(path: Path, uid: int, mode: int) -> None:
    try:
        path.mkdir(mode=mode)
        os.chown(path, uid, -1); os.chmod(path, mode); fsync_directory(path.parent)
    except FileExistsError:
        trusted_directory(path, uid, mode)


def execute(campaign_path: Path, case_id: str, *, category: str,
            plan: dict[str, Any] | None = None,
            authorization: dict[str, Any] | None = None,
            state_root: Path = STATE_ROOT, uid: int | None = None,
            now: int | None = None) -> dict[str, Any]:
    owner = os.geteuid() if uid is None else uid
    current_time = int(time.time()) if now is None else now
    if category not in {"runtime", "management"}:
        raise ResearchScenarioError("scenario_research_category_invalid")
    allowed = RUNTIME_CASES if category == "runtime" else MANAGEMENT_CASES
    if case_id not in allowed:
        raise ResearchScenarioError("scenario_research_case_invalid")
    trusted_directory(state_root, owner, 0o700)
    campaign_root = state_root / campaign_path.parent.name
    if campaign_path != campaign_root / "campaign.json":
        raise ResearchScenarioError("scenario_research_campaign_path_invalid")
    trusted_directory(campaign_root, owner, 0o700)
    campaign = validate_campaign(
        trusted_json(campaign_path, owner, 0o600), current_time,
    )
    if campaign_root.name != campaign["campaign_id"]:
        raise ResearchScenarioError("scenario_research_campaign_binding_invalid")
    scenarios_root = campaign_root / "scenarios"
    _create_directory(scenarios_root, owner, 0o700)
    case_root = scenarios_root / case_id
    _create_directory(case_root, owner, 0o700)
    result_path = case_root / "result.json"
    if os.path.lexists(result_path):
        return validate_result(
            trusted_json(result_path, owner, 0o400), campaign, case_id,
        )
    before = initial_state(campaign, case_id, now=current_time)
    if case_id in TOUCH_ID_CASES and (plan is None or authorization is None):
        raise ResearchScenarioError("scenario_research_authorization_required")
    if case_id not in TOUCH_ID_CASES and (plan is not None or authorization is not None):
        raise ResearchScenarioError("scenario_research_authorization_forbidden")
    result = execute_case(
        campaign, case_id, before, plan=plan, authorization=authorization,
        now=current_time,
    )
    publish_exact(case_root / "state-before.json", before, owner, 0o400)
    publish_exact(case_root / "state-after.json", result["after_state"], owner, 0o400)
    publish_exact(result_path, result, owner, 0o400)
    return result


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Execute one isolated Research lifecycle acceptance scenario",
    )
    value.add_argument("--campaign", type=Path, required=True)
    value.add_argument("--case", required=True)
    value.add_argument("--category", choices=("runtime", "management"), required=True)
    value.add_argument("--plan-json")
    value.add_argument("--authorization-json")
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if os.geteuid() != 0:
        raise ResearchScenarioError("scenario_research_root_required")
    result = execute(
        args.campaign, args.case, category=args.category,
        plan=parse_argument(args.plan_json, "plan"),
        authorization=parse_argument(args.authorization_json, "authorization"),
    )
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ScenarioError, ResearchScenarioError, ValueError) as error:
        reason = str(error) if isinstance(error, ResearchScenarioError) \
            else "scenario_research_rejected"
        sys.stderr.buffer.write(canonical({
            "schema": "secure-sandbox-harness-lifecycle-acceptance-scenario-error-v1",
            "status": "rejected", "error": reason,
        }))
        raise SystemExit(1)
