#!/usr/bin/env python3
"""Deterministic malicious-harness fixture and outer observation backend."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness_qualification import (
    DENIAL_CASES,
    EXPECTED_EVENTS,
    OBSERVATION_SCHEMA,
    OBSERVER_ID,
    sha256_value,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "fixtures/harness-qualification/malicious_harness.py"
RUNNER_PATH = ROOT / "shared/harness_qualification.py"
ADAPTER_PATH = ROOT / "shared/claude_core_adapter.py"
SYNTHETIC_POLICY = {
    "authority": "none",
    "automatic_admission": False,
    "vendor_candidate_execution": False,
    "synthetic_fixture_execution": True,
    "observer": OBSERVER_ID,
}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic_bindings(fixture_path: Path = DEFAULT_FIXTURE) -> dict[str, str]:
    fixture_sha256 = file_sha256(fixture_path)
    return {
        "generation_id": fixture_sha256,
        "artifact_sha256": fixture_sha256,
        "fixture_corpus_sha256": fixture_sha256,
        "manifest_sha256": sha256_value({
            "fixture": "synthetic-malicious-harness-v1",
            "artifact_sha256": fixture_sha256,
        }),
        "adapter_sha256": file_sha256(ADAPTER_PATH),
        "runner_sha256": file_sha256(RUNNER_PATH),
        "policy_sha256": sha256_value(SYNTHETIC_POLICY),
    }


@dataclass
class SyntheticDisposableSupervisor:
    """Test-only parent that runs one fixed fixture and owns all observed facts."""

    fixture_path: Path = DEFAULT_FIXTURE
    fixture_sha256: str | None = None
    faults: dict[str, dict[str, Any]] = field(default_factory=dict)

    def observe(self, plan: dict[str, Any], case_id: str, sequence: int) -> dict[str, Any]:
        actual_sha256 = file_sha256(self.fixture_path)
        expected_sha256 = self.fixture_sha256 or actual_sha256
        expected_bindings = synthetic_bindings(self.fixture_path)
        if (actual_sha256 != expected_sha256 or any(
                plan.get(name) != value for name, value in expected_bindings.items())):
            raise RuntimeError("fixture_digest_mismatch")
        child_environment = {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}
        with tempfile.TemporaryDirectory(prefix="secure-sandbox-harness-fixture.") as directory:
            working_directory = Path(directory)
            process = subprocess.run(
                [sys.executable, "-I", str(self.fixture_path), case_id],
                cwd=directory,
                env=child_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
            )
            file_changes = sorted(
                path.relative_to(working_directory).as_posix()
                for path in working_directory.rglob("*")
            )
        if process.returncode != 0 or len(process.stdout) > 4096 or len(process.stderr) > 4096:
            raise RuntimeError("fixture_process_failed")
        try:
            request = json.loads(process.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise RuntimeError("fixture_protocol_invalid") from error
        if (not isinstance(request, dict)
                or set(request) != {"action", "claimed_status", "requested_effect"}
                or request["action"] != case_id
                or request["claimed_status"] != "passed"
                or not isinstance(request["requested_effect"], str)):
            raise RuntimeError("fixture_protocol_invalid")
        denial = case_id in DENIAL_CASES
        catalog = sha256_value({"tools": ["source-integrity", "corpus", "execution-broker"]})
        facts: dict[str, Any] = {
            "blocked": denial,
            "events": ["policy_denial"] if denial else EXPECTED_EVENTS.get(case_id, []),
            "attempts": [request["requested_effect"]] if denial else [],
            "network_connections": [],
            "child_processes": [],
            "file_changes": file_changes,
            "environment_keys": sorted(child_environment),
            "secret_markers": [],
            "tool_catalog_before_sha256": catalog if case_id == "tool-catalog-stability" else None,
            "tool_catalog_after_sha256": catalog if case_id == "tool-catalog-stability" else None,
            "semantic_loss": False,
            "unknown_events": [],
            "stdout_bytes": len(process.stdout),
            "stderr_bytes": len(process.stderr),
            "timed_out": False,
        }
        facts.update(self.faults.get(case_id, {}))
        return {
            "schema": OBSERVATION_SCHEMA,
            "observer": OBSERVER_ID,
            "plan_sha256": sha256_value(plan),
            "case_id": case_id,
            "sequence": sequence,
            "outcome": "completed",
            "facts": facts,
        }
