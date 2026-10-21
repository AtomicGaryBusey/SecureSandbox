#!/usr/bin/env python3
"""Permit the Research agent SSH principal to invoke only research-claude."""

import os
import re
import shlex
import sys

LAUNCHER = "/usr/local/bin/research-claude"
UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def command(original: str) -> list[str]:
    if len(original.encode("utf-8")) > 256:
        raise ValueError("SSH command exceeds limit")
    values = shlex.split(original, posix=True)
    if values == [LAUNCHER]:
        return values
    if len(values) == 3 and values[:2] == [LAUNCHER, "--resume"] and UUID4_RE.fullmatch(values[2]):
        return values
    raise ValueError("Research SSH permits only the approved Claude launcher")


def main() -> None:
    if os.geteuid() == 0 or os.environ.get("USER") != "agent":
        raise SystemExit("Research SSH entry requires the agent identity")
    try:
        arguments = command(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError as error:
        raise SystemExit(str(error)) from error
    os.execve(LAUNCHER, arguments, {"HOME":"/home/agent", "USER":"agent",
                                    "LOGNAME":"agent", "PATH":"/usr/local/bin:/usr/bin:/bin",
                                    "TERM":os.environ.get("TERM", "xterm-256color")})


if __name__ == "__main__":
    main()
