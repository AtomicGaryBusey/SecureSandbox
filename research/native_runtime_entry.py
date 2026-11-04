#!/usr/bin/env python3
"""Fixed installed entrypoints for the Research native runtime package."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


ENTRYPOINTS = {
    "native_provider_controller.py": "research.native_provider_controller",
    "native_claude_login_channel.py": "research.native_claude_login_channel",
    "native_codex_session_controller.py": "research.native_codex_session_controller",
    "native_claude_session_controller.py": "research.native_claude_session_controller",
    "native_harness_supervisor.py": "research.native_harness_supervisor",
}


def main() -> int:
    installed_root = Path(__file__).resolve().parent
    expected_root = Path("/usr/local/libexec/secure-sandbox")
    if installed_root != expected_root:
        return 126
    name = Path(__file__).name
    module_name = ENTRYPOINTS.get(name)
    if module_name is None or (
        name != "native_harness_supervisor.py" and os.geteuid() != 0
    ):
        return 126
    sys.path.insert(0, str(installed_root))
    module = importlib.import_module(module_name)
    entrypoint = getattr(module, "main", None)
    if not callable(entrypoint):
        return 126
    return int(entrypoint())


if __name__ == "__main__":
    raise SystemExit(main())
