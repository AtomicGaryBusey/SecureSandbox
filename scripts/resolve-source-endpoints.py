#!/usr/bin/env python3
"""Resolve and validate the fixed public GitHub acquisition endpoints."""

import ipaddress
import json
import socket

hosts = ("api.github.com", "codeload.github.com", "registry.npmjs.org")
endpoints = {}
for host in hosts:
    values = []
    for result in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM):
        address = result[4][0]
        parsed = ipaddress.ip_address(address)
        if parsed.version != 4 or not parsed.is_global:
            raise SystemExit(f"non-global address for {host}")
        if address not in values:
            values.append(address)
    if not values:
        raise SystemExit(f"no global IPv4 address for {host}")
    endpoints[host] = sorted(values)
print(json.dumps({
    "endpoint_ipv4": endpoints,
    "max_api_bytes": 2097152,
    "max_archive_bytes": 268435456,
    "policy_version": "source-acquisition-v1",
    "request_timeout_seconds": 300,
    "schema": "secure-sandbox-source-policy-v1",
}, separators=(",", ":"), sort_keys=True))
