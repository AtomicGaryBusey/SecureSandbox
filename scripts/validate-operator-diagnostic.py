#!/usr/bin/env python3
"""Validate one terminal, content-free SecureSandbox operator diagnosis."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SCHEMA = "secure-sandbox-operator-diagnostic-v1"
UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
FIELDS = {
    "action", "code", "operation", "outcome", "phase", "request_id", "retry", "schema",
}


class DiagnosticError(RuntimeError):
    pass


def validate(path: Path, code: str, operation: str, outcome: str,
             retry: str, action: str) -> dict[str, object]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise DiagnosticError("operator_diagnostic_unreadable") from error
    if len(raw) > 65_536:
        raise DiagnosticError("operator_diagnostic_too_large")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise DiagnosticError("operator_diagnostic_invalid") from error
    records = []
    for line in lines:
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise DiagnosticError("operator_diagnostic_invalid") from error
        if isinstance(value, dict) and value.get("schema") == SCHEMA:
            records.append(value)
    try:
        terminal = json.loads(lines[-1]) if lines else None
    except json.JSONDecodeError as error:
        raise DiagnosticError("operator_diagnostic_not_single_terminal_record") from error
    if len(records) != 1 or terminal != records[0]:
        raise DiagnosticError("operator_diagnostic_not_single_terminal_record")
    value = records[0]
    if (set(value) != FIELDS or value.get("code") != code
            or value.get("operation") != operation or value.get("outcome") != outcome
            or value.get("retry") != retry or value.get("action") != action
            or value.get("schema") != SCHEMA
            or value.get("phase") not in {"ceremony", "authorization", "validation", "operation", "result"}
            or not isinstance(value.get("request_id"), str)
            or UUID4.fullmatch(value["request_id"]) is None):
        raise DiagnosticError("operator_diagnostic_invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--code", required=True)
    parser.add_argument("--operation", required=True)
    parser.add_argument("--outcome", required=True)
    parser.add_argument("--retry", required=True)
    parser.add_argument("--action", required=True)
    args = parser.parse_args()
    validate(args.path, args.code, args.operation, args.outcome, args.retry, args.action)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DiagnosticError as error:
        print(str(error), file=__import__("sys").stderr)
        raise SystemExit(1)
