#!/usr/bin/env python3
"""Ship bounded, metadata-only telemetry to Azure Monitor over pinned TLS."""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import socket
import ssl
import stat
import time
import urllib.parse
import uuid

SPOOL = "/var/lib/secure-sandbox/telemetry/current.jsonl"
STATE = "/var/lib/secure-sandbox/azure-shipper/state.json"
SECRET = "/run/credentials/azure-shipper.service/client_secret"
MAX_BATCH_EVENTS = 100
MAX_BATCH_BYTES = 900 * 1024
MAX_LINE_BYTES = 16 * 1024


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Validate a logical TLS host while connecting only to a pinned IPv4."""

    def __init__(self, host: str, address: str, timeout: int = 20):
        self.pinned_address = address
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().__init__(host, 443, timeout=timeout, context=context)

    def connect(self) -> None:
        raw = socket.create_connection((self.pinned_address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def validate_config(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("config must be an object")
    required_strings = ("tenant_id", "client_id", "ingestion_endpoint", "dcr_immutable_id", "stream_name")
    for name in required_strings:
        if not isinstance(value.get(name), str) or not value[name]:
            raise ValueError(f"invalid {name}")
    uuid.UUID(value["tenant_id"])
    uuid.UUID(value["client_id"])
    endpoint = urllib.parse.urlsplit(value["ingestion_endpoint"])
    if endpoint.scheme != "https" or endpoint.port not in (None, 443) or endpoint.path not in ("", "/"):
        raise ValueError("ingestion endpoint must be an HTTPS origin")
    if not endpoint.hostname or not endpoint.hostname.endswith(".ingest.monitor.azure.com"):
        raise ValueError("unexpected ingestion hostname")
    if not value["dcr_immutable_id"].startswith("dcr-"):
        raise ValueError("invalid DCR immutable ID")
    if not value["stream_name"].startswith("Custom-"):
        raise ValueError("invalid stream name")
    for name in ("token_ipv4", "ingestion_ipv4"):
        addresses = value.get(name)
        if not isinstance(addresses, list) or not addresses:
            raise ValueError(f"{name} must not be empty")
        for address in addresses:
            parsed = ipaddress.ip_address(address)
            if parsed.version != 4 or not parsed.is_global:
                raise ValueError(f"{name} must contain global IPv4 addresses")
    value = dict(value)
    value["ingestion_host"] = endpoint.hostname
    return value


def request_pinned(host: str, addresses: list[str], method: str, path: str,
                   body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    last_error: BaseException | None = None
    for address in addresses:
        connection = PinnedHTTPSConnection(host, address)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(128 * 1024)
            return response.status, payload
        except (OSError, ssl.SSLError, http.client.HTTPException) as error:
            last_error = error
        finally:
            connection.close()
    raise OSError("all pinned endpoints failed") from last_error


def get_token(config: dict, secret: str) -> tuple[str, float]:
    body = urllib.parse.urlencode({
        "client_id": config["client_id"],
        "client_secret": secret,
        "scope": config.get("token_scope", "https://monitor.azure.com//.default"),
        "grant_type": "client_credentials",
    }).encode()
    path = f"/{config['tenant_id']}/oauth2/v2.0/token"
    status, payload = request_pinned(
        "login.microsoftonline.com", config["token_ipv4"], "POST", path, body,
        {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(len(body))},
    )
    if status != 200:
        raise RuntimeError(f"token endpoint status {status}")
    result = json.loads(payload)
    token = result.get("access_token")
    expires = result.get("expires_in", 0)
    if not isinstance(token, str) or not token or not isinstance(expires, int):
        raise RuntimeError("invalid token response")
    return token, time.monotonic() + max(0, expires - 300)


def load_state() -> dict[str, int]:
    try:
        with open(STATE, encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, int) and v >= 0 for k, v in value.items()):
            raise ValueError
        return value
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def save_state(value: dict[str, int]) -> None:
    directory = os.path.dirname(STATE)
    temporary = f"{STATE}.new"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, (json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, STATE)
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def spool_paths() -> list[str]:
    paths = [f"{SPOOL}.{index}" for index in range(5, 0, -1)]
    paths.append(SPOOL)
    return [path for path in paths if os.path.exists(path)]


def next_batch(offsets: dict[str, int]) -> tuple[list[dict], str, int, set[str]]:
    seen: set[str] = set()
    for path in spool_paths():
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("spool entry is not a regular file")
            identity = f"{info.st_dev}:{info.st_ino}"
            seen.add(identity)
            position = min(offsets.get(identity, 0), info.st_size)
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                handle.seek(position)
                events: list[dict] = []
                total = 2
                final_position = position
                while len(events) < MAX_BATCH_EVENTS:
                    line = handle.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE_BYTES or not line.endswith(b"\n"):
                        raise RuntimeError("invalid or partial telemetry line")
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise RuntimeError("invalid telemetry record")
                    encoded = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
                    if events and total + len(encoded) + 1 > MAX_BATCH_BYTES:
                        break
                    events.append(event)
                    total += len(encoded) + 1
                    final_position = handle.tell()
                if events:
                    return events, identity, final_position, seen
        finally:
            os.close(descriptor)
    return [], "", 0, seen


def upload(config: dict, token: str, events: list[dict]) -> str:
    request_id = str(uuid.uuid4())
    body = json.dumps(events, separators=(",", ":"), sort_keys=True).encode()
    rule = urllib.parse.quote(config["dcr_immutable_id"], safe="-")
    stream = urllib.parse.quote(config["stream_name"], safe="-")
    path = f"/dataCollectionRules/{rule}/streams/{stream}?api-version=2023-01-01"
    status, _ = request_pinned(
        config["ingestion_host"], config["ingestion_ipv4"], "POST", path, body,
        {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "x-ms-client-request-id": request_id,
        },
    )
    if status != 204:
        raise RuntimeError(f"ingestion endpoint status {status}")
    return request_id


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as handle:
        config = validate_config(json.load(handle))
    if args.validate:
        print("valid")
        return
    with open(SECRET, encoding="utf-8") as handle:
        secret = handle.read().strip()
    if not secret:
        raise RuntimeError("client secret is empty")

    offsets = load_state()
    token = ""
    token_expiry = 0.0
    while True:
        try:
            events, identity, position, seen = next_batch(offsets)
            if not events:
                offsets = {key: value for key, value in offsets.items() if key in seen}
                save_state(offsets)
                time.sleep(5)
                continue
            if time.monotonic() >= token_expiry:
                token, token_expiry = get_token(config, secret)
            request_id = upload(config, token, events)
            offsets[identity] = position
            save_state(offsets)
            print(json.dumps({"event": "azure_upload_complete", "count": len(events), "request_id": request_id}, separators=(",", ":")), flush=True)
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
            print(json.dumps({"event": "azure_upload_failed", "error": type(error).__name__}, separators=(",", ":")), flush=True)
            time.sleep(10)


if __name__ == "__main__":
    main()
