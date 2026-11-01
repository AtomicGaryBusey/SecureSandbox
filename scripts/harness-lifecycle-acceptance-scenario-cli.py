#!/usr/bin/env python3
"""Closed CLI shared by protected runtime and management acceptance drivers."""

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_lifecycle_acceptance import canonical  # noqa: E402
from harness_lifecycle_acceptance_scenarios import (  # noqa: E402
    TOUCH_ID_CASES,
    ScenarioError,
)


class ScenarioCLIError(RuntimeError):
    """Stable protected scenario CLI rejection."""


def load_script(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ScenarioCLIError("scenario_cli_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_script(
    "harness_lifecycle_acceptance_scenario_cli_supervisor",
    ROOT / "scripts/harness-lifecycle-acceptance-scenario-supervisor.py",
)


def parser(category: str) -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=f"Protected {category} lifecycle acceptance driver",
    )
    commands = value.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--case", required=True)
    prepare.add_argument("--operator-uid", type=int, required=True)
    consume = commands.add_parser("consume")
    consume.add_argument("--plan-json", required=True)
    consume.add_argument("--authorization-json", required=True)
    consume.add_argument("--operator-uid", type=int, required=True)
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--case", required=True)
    finalize.add_argument("--request-id")
    finalize.add_argument("--operator-uid", type=int, required=True)
    run = commands.add_parser("run")
    run.add_argument("--case", required=True)
    run.add_argument("--operator-uid", type=int, required=True)
    return value


def main(category: str, wrapper: Path,
         arguments: list[str] | None = None) -> int:
    args = parser(category).parse_args(arguments)
    if os.geteuid() != 0 or not 1 <= args.operator_uid < 2 ** 31:
        raise ScenarioCLIError("scenario_cli_root_required")
    SUPERVISOR.AUTH.require_protected_main_path(wrapper, os.geteuid())
    if args.command == "prepare":
        result = SUPERVISOR.prepare(category, args.case, args.operator_uid)
    elif args.command == "consume":
        plan = SUPERVISOR.AUTH.parse_argument(args.plan_json, "plan")
        authorization = SUPERVISOR.AUTH.parse_argument(
            args.authorization_json, "authorization",
        )
        result = SUPERVISOR.execute(
            category, plan.get("case_id"), args.operator_uid,
            plan=plan, authorization=authorization,
        )
    elif args.command == "finalize":
        result = SUPERVISOR.finalize(
            category, args.case, args.operator_uid, request_id=args.request_id,
        )
    else:
        if args.case in TOUCH_ID_CASES:
            raise ScenarioCLIError("scenario_cli_touchid_prepare_required")
        SUPERVISOR.prepare(category, args.case, args.operator_uid)
        SUPERVISOR.execute(category, args.case, args.operator_uid)
        result = SUPERVISOR.finalize(category, args.case, args.operator_uid)
    sys.stdout.buffer.write(canonical(result))
    return 0
