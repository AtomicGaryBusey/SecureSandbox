#!/usr/bin/env python3
"""Content-free live adversarial checks for deployed local broker transports."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time


FRAMING_BOUND_SECONDS = 4.5
REQUEST_ID = "00000000-0000-4000-8000-000000000001"


class GateFailed(RuntimeError):
    pass


def child_hold(host: str, port: int, mode: str) -> int:
    connection = socket.create_connection((host, port), timeout=2)
    try:
        if mode == "http":
            connection.sendall(b"GET /healthz HTTP/1.1\r\nHost:")
        elif mode != "tls":
            raise GateFailed("hold_mode")
        print("ready", flush=True)
        time.sleep(FRAMING_BOUND_SECONDS)
    finally:
        connection.close()
    return 0


def run_as(user: str, arguments: list[str], timeout: float = 8.0) -> None:
    result = subprocess.run(
        ["/usr/sbin/runuser", "-u", user, "--", *arguments],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if result.returncode != 0:
        raise GateFailed("valid_peer")


def http_fairness(user: str, host: str, port: int, mode: str,
                  valid_arguments: list[str]) -> None:
    child = subprocess.Popen(
        ["/usr/sbin/runuser", "-u", user, "--", sys.executable,
         os.path.realpath(__file__), "--hold", host, str(port), mode],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True)
    try:
        if child.stdout is None or child.stdout.readline().strip() != "ready":
            raise GateFailed("slow_peer_start")
        time.sleep(0.1)
        started = time.monotonic()
        run_as(user, valid_arguments)
        if time.monotonic() - started >= FRAMING_BOUND_SECONDS:
            raise GateFailed("framing_bound")
    finally:
        try:
            child.wait(timeout=FRAMING_BOUND_SECONDS + 1)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)


def unix_fairness(path: str, *, newline: bool) -> None:
    slow = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    valid = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        slow.settimeout(2)
        slow.connect(path)
        slow.sendall(b"{")
        time.sleep(0.05)
        valid.settimeout(2)
        started = time.monotonic()
        valid.connect(path)
        valid.sendall(b"{}\n" if newline else b"{}")
        if not newline:
            valid.shutdown(socket.SHUT_WR)
        response = valid.recv(4096)
        if not response or time.monotonic() - started >= 2.0:
            raise GateFailed("unix_fairness")
    finally:
        slow.close()
        valid.close()


def curl(*arguments: str) -> list[str]:
    return ["/usr/bin/curl", "-fsS", "--max-time", "7", *arguments]


def verify() -> None:
    for path, newline in (
        ("/run/secure-sandbox-corpus/corpus.sock", False),
        ("/run/secure-sandbox-findings/findings.sock", False),
        ("/run/secure-sandbox-memory/memory-proposal.sock", False),
        ("/run/secure-sandbox-codegraph/query.sock", True),
    ):
        unix_fairness(path, newline=newline)

    http_fairness(
        "claude-relay", "127.0.0.1", 18080, "http",
        curl("http://127.0.0.1:18080/healthz"))
    http_fairness(
        "claude-relay", "172.30.10.1", 8443, "tls",
        curl("--cacert", "/etc/secure-sandbox/relay/ca.crt",
             "--cert", "/etc/secure-sandbox/relay/client.crt",
             "--key", "/etc/secure-sandbox/relay/client.key",
             "-H", f"X-Sandbox-Request-Id: {REQUEST_ID}",
             "-H", "X-Sandbox-Run-Id: boundary-test",
             "https://172.30.10.1:8443/healthz"))
    http_fairness(
        "telemetry-exporter", "172.30.10.1", 9443, "tls",
        curl("--cacert", "/etc/secure-sandbox/telemetry/ca.crt",
             "--cert", "/etc/secure-sandbox/telemetry/client.crt",
             "--key", "/etc/secure-sandbox/telemetry/client.key",
             "https://172.30.10.1:9443/healthz"))
    http_fairness(
        "conversation-shipper", "172.30.10.1", 9553, "tls",
        curl("--cacert", "/etc/secure-sandbox/conversation-transport/ca.crt",
             "--cert", "/etc/secure-sandbox/conversation-transport/client.crt",
             "--key", "/etc/secure-sandbox/conversation-transport/client.key",
             "https://172.30.10.1:9553/healthz"))
    http_fairness(
        "execution-broker", "172.30.20.2", 8080, "http",
        curl("http://172.30.20.2:8080/healthz"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hold", nargs=3, metavar=("HOST", "PORT", "MODE"))
    args = parser.parse_args()
    if args.hold:
        host, port, mode = args.hold
        return child_hold(host, int(port), mode)
    try:
        verify()
    except (GateFailed, OSError, subprocess.SubprocessError, ValueError):
        print(json.dumps({
            "schema": "secure-sandbox-local-broker-protocol-live-verification-v1",
            "status": "rejected",
        }, separators=(",", ":"), sort_keys=True))
        return 1
    print(json.dumps({
        "schema": "secure-sandbox-local-broker-protocol-live-verification-v1",
        "status": "verified",
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
