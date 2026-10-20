#!/usr/bin/env python3
"""Fixed systemd sandbox wrapper exposed to labadmin through sudo."""

import os
import re
import subprocess
import sys
import uuid

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("root required")
    if len(sys.argv) == 2 and sys.argv[1] == "stage":
        child = ["/usr/local/libexec/secure-sandbox/source_importer.py", "stage"]
    elif len(sys.argv) == 3 and sys.argv[1] == "publish" and UUID_RE.fullmatch(sys.argv[2]):
        child = ["/usr/local/libexec/secure-sandbox/source_importer.py", "publish", sys.argv[2]]
    else:
        raise SystemExit("invalid invocation")
    unit = "source-import-" + str(uuid.uuid4())
    command = [
        "/usr/bin/systemd-run", "--pipe", "--wait", "--collect", "--quiet", f"--unit={unit}",
        "--property=NoNewPrivileges=yes", "--property=PrivateDevices=yes",
        "--property=PrivateTmp=yes", "--property=PrivateNetwork=yes",
        "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
        "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
        "--property=ProtectControlGroups=yes", "--property=ProtectClock=yes",
        "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
        "--property=RestrictSUIDSGID=yes", "--property=LockPersonality=yes",
        "--property=MemoryDenyWriteExecute=yes", "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=ReadOnlyPaths=/etc/secure-sandbox/conversation-recipient.txt",
        "--property=ReadWritePaths=/var/lib/secure-sandbox/source-acquisition /var/lib/secure-sandbox/conversation-outbox /home/agent/research-workspace/repos /home/agent/research-workspace/baselines /home/agent/research-workspace/source-manifests",
        "--property=MemoryMax=1536M", "--property=TasksMax=32", *child,
    ]
    result = subprocess.run(command, stdin=sys.stdin.buffer, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, check=False, env={"PATH": "/usr/sbin:/usr/bin"})
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
