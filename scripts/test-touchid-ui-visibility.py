#!/usr/bin/env python3
"""Side-effect-free foreground-window probe for the signed authorization app."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
DEFAULT_APP = REPO / "artifacts/host/SecureSandboxAuthorizationUI.app"
EXECUTABLE = Path("Contents/MacOS/SecureSandboxAuthorizationUI")
LSREGISTER = Path(
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/"
    "LaunchServices.framework/Support/lsregister"
)


def canonical(value: dict[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def window_state(pid: int) -> dict[str, object]:
    source = r'''
import AppKit
import CoreGraphics
import Foundation
let pid = Int32(ProcessInfo.processInfo.environment["SECURE_SANDBOX_PROBE_PID"]!)!
let windows = (CGWindowListCopyWindowInfo(
    [.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID
) as? [[String: Any]]) ?? []
let owned = windows.filter { ($0[kCGWindowOwnerPID as String] as? Int32) == pid }
let result: [String: Any] = [
    "frontmost": NSWorkspace.shared.frontmostApplication?.processIdentifier == pid,
    "onscreen_windows": owned.count,
]
let data = try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
print(String(data: data, encoding: .utf8)!)
'''
    environment = os.environ.copy()
    environment["SECURE_SANDBOX_PROBE_PID"] = str(pid)
    result = subprocess.run(
        ["/usr/bin/swift", "-e", source], check=True, capture_output=True,
        text=True, timeout=30, env=environment,
    )
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, default=DEFAULT_APP)
    parser.add_argument("--settle-seconds", type=float, default=2)
    args = parser.parse_args()
    app = args.app.resolve(strict=True)
    executable = app / EXECUTABLE
    if app.name != "SecureSandboxAuthorizationUI.app" or not executable.is_file():
        raise SystemExit("authorization_ui_bundle_invalid")
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--deep", str(app)],
        check=True, timeout=30,
    )
    subprocess.run([str(LSREGISTER), "-f", str(app)], check=True, timeout=30)

    with tempfile.TemporaryDirectory(prefix="secure-sandbox-ui-probe.") as temporary:
        root = Path(temporary)
        request_id = str(uuid.uuid4())
        created_at = int(time.time())
        request = {
            "created_at": created_at,
            "declared_agent": "Codex",
            "declared_session": "authorization-ui-visibility-probe",
            "expires_at": created_at + 60,
            "identity_evidence": "operator-declared",
            "invoking_uid": os.getuid(),
            "operation": "authorization-probe",
            "parameters": {"challenge": str(uuid.uuid4())},
            "purpose": "Side-effect-free authorization window visibility probe",
            "request_id": request_id,
            "resource": "/usr/local/libexec/secure-sandbox-host",
            "schema": "secure-sandbox-operator-authorization-v1",
        }
        encoded = canonical(request)
        digest = hashlib.sha256(encoded).hexdigest()
        request_path = root / "request.json"
        descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, encoded)
        finally:
            os.close(descriptor)
        socket_path = root / "broker.sock"
        result_path = root / "result.json"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(socket_path))
        server.listen(1)
        server.settimeout(10)
        process = subprocess.Popen(
            ["/usr/bin/open", "-n", "-W", str(app), "--args",
             "--request-path", str(request_path), "--request-sha256", digest,
             "--socket-path", str(socket_path), "--result-path", str(result_path)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        application_pid: int | None = None
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                begin = b""
                while not begin.endswith(b"\n"):
                    begin += connection.recv(4096)
                    if len(begin) > 65_536:
                        raise RuntimeError("touchid_probe_begin_too_large")
                parsed = json.loads(begin)
                if (parsed.get("schema") != "secure-sandbox-touchid-approval-v2"
                        or parsed.get("phase") != "begin"
                        or parsed.get("request_id") != request_id
                        or parsed.get("request_sha256") != digest):
                    raise RuntimeError("touchid_probe_begin_invalid")
                challenge = {
                    "host_release_id": "0" * 64,
                    "mode": "legacy-touch-id",
                    "request_id": request_id,
                    "request_sha256": digest,
                    "schema": "secure-sandbox-touchid-challenge-v2",
                }
                connection.sendall(canonical(challenge))
                time.sleep(args.settle_seconds)
                listing = subprocess.run(
                    ["/bin/ps", "-axo", "pid=,command="], check=True,
                    capture_output=True, text=True, timeout=5,
                ).stdout.splitlines()
                matches = [
                    line.strip().split(None, 1)[0] for line in listing
                    if "SecureSandboxAuthorizationUI.app/Contents/MacOS/"
                    "SecureSandboxAuthorizationUI" in line
                ]
                if len(matches) != 1:
                    raise RuntimeError("authorization_ui_process_ambiguous:" + repr(matches))
                application_pid = int(matches[0])
                status = process.poll()
                if status is not None:
                    stdout, stderr = process.communicate()
                    raise RuntimeError(
                        "authorization_ui_exited_before_window:"
                        + json.dumps({
                            "status": status,
                            "stdout": stdout.decode("utf-8", "replace")[-1000:],
                            "stderr": stderr.decode("utf-8", "replace")[-1000:],
                        }, sort_keys=True)
                    )
                observed = window_state(application_pid)
                if observed != {"frontmost": True, "onscreen_windows": 1}:
                    raise RuntimeError("authorization_window_not_foreground:" + json.dumps(observed))
                print(json.dumps({
                    "app": str(app),
                    "frontmost": True,
                    "onscreen_windows": 1,
                    "schema": "secure-sandbox-touchid-ui-visibility-v1",
                    "status": "verified",
                }, sort_keys=True))
        finally:
            server.close()
            if application_pid is not None:
                try:
                    os.kill(application_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
