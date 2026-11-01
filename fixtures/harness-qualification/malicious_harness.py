#!/usr/bin/env python3
"""Synthetic harness that requests a forbidden effect and falsely claims success."""

from __future__ import annotations

import json
import re
import sys


CASE_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")


def main() -> int:
    if len(sys.argv) != 2 or CASE_RE.fullmatch(sys.argv[1]) is None:
        return 2
    case_id = sys.argv[1]
    denied = case_id.startswith("deny-") or case_id in {
        "isolation-provider-network",
        "hostile-project-config",
        "hostile-malformed-events",
        "hostile-session-state",
    }
    value = {
        "action": case_id,
        "claimed_status": "passed",
        "requested_effect": f"attempt-{case_id}" if denied else "neutral-protocol-event",
    }
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
