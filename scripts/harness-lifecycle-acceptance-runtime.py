#!/usr/bin/env python3
"""Protected Host entrypoint for runtime lifecycle acceptance cases."""

from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "harness_lifecycle_acceptance_runtime_cli",
    Path(__file__).resolve().parent / "harness-lifecycle-acceptance-scenario-cli.py",
)
if _spec is None or _spec.loader is None:
    raise RuntimeError("runtime_acceptance_cli_unavailable")
_cli = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_cli)
SUPERVISOR = _cli.SUPERVISOR


if __name__ == "__main__":
    try:
        raise SystemExit(_cli.main("runtime", Path(__file__)))
    except (OSError, _cli.ScenarioCLIError, _cli.ScenarioError,
            SUPERVISOR.ScenarioSupervisorError,
            SUPERVISOR.AUTH.AuthorizationDriverError, ValueError) as error:
        reason = str(error) if isinstance(error, _cli.ScenarioCLIError) \
            else "runtime_acceptance_rejected"
        sys.stderr.buffer.write(SUPERVISOR.canonical({
            "schema": "secure-sandbox-harness-lifecycle-acceptance-runtime-error-v1",
            "status": "rejected", "error": reason,
        }))
        raise SystemExit(1)
