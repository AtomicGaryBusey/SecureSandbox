#!/usr/bin/env python3
"""Run the non-admitting synthetic harness qualification fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "shared"))

from harness_qualification import (  # noqa: E402
    CASE_IDS,
    PLAN_SCHEMA,
    SUITE_ID,
    QualificationError,
    QualificationRunner,
    sha256_value,
)
from harness_qualification_fixture import SyntheticDisposableSupervisor  # noqa: E402


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_plan(now: int) -> dict[str, object]:
    runner = ROOT / "shared/harness_qualification.py"
    fixture = ROOT / "fixtures/harness-qualification/malicious_harness.py"
    adapter = ROOT / "shared/claude_core_adapter.py"
    suite_sha256 = sha256_value({"suite_id": SUITE_ID, "cases": list(CASE_IDS)})
    corpus_sha256 = file_sha256(fixture)
    return {
        "schema": PLAN_SCHEMA,
        "qualification_id": str(uuid.uuid4()),
        "suite_id": SUITE_ID,
        "generation_id": file_sha256(fixture),
        "artifact_sha256": file_sha256(fixture),
        "manifest_sha256": sha256_value({
            "fixture": "synthetic-malicious-harness-v1",
            "artifact_sha256": file_sha256(fixture),
        }),
        "adapter_id": "claude-core-v1",
        "adapter_sha256": file_sha256(adapter),
        "suite_sha256": suite_sha256,
        "fixture_corpus_sha256": corpus_sha256,
        "policy_sha256": sha256_value({
            "authority": "none",
            "automatic_admission": False,
            "vendor_candidate_execution": False,
            "synthetic_fixture_execution": True,
            "observer": "secure-sandbox-disposable-supervisor-v1",
        }),
        "runner_sha256": file_sha256(runner),
        "created_at": now,
        "expires_at": now + 300,
        "cases": list(CASE_IDS),
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description="Run the built-in malicious fixture; this cannot qualify or admit vendor bytes",
    )
    value.add_argument("command", choices=("self-test",))
    return value


def main(arguments: list[str] | None = None) -> int:
    args = parser().parse_args(arguments)
    if args.command != "self-test":  # pragma: no cover - argparse owns this
        raise QualificationError("command_invalid")
    now = int(time.time())
    fixture = ROOT / "fixtures/harness-qualification/malicious_harness.py"
    report = QualificationRunner(now).run(
        fixture_plan(now),
        SyntheticDisposableSupervisor(fixture_path=fixture, fixture_sha256=file_sha256(fixture)),
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "fixture_qualified" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (QualificationError, OSError) as error:
        reason = str(error) if isinstance(error, QualificationError) else "qualification_io_failed"
        print(json.dumps({
            "error": reason,
            "schema": "secure-sandbox-harness-qualification-error-v1",
            "status": "rejected",
        }, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(1)
