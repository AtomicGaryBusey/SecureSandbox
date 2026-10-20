#!/usr/bin/env python3
"""Render the complete Gateway nftables policy from validated service configs."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pwd
import re
import stat


def global_ipv4(values: object, name: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise ValueError(f"{name} is empty")
    result = []
    for value in values:
        address = ipaddress.ip_address(value)
        if address.version != 4 or not address.is_global:
            raise ValueError(f"{name} contains a non-global IPv4 address")
        if str(address) not in result:
            result.append(str(address))
    return result


def optional_json(path: str) -> dict | None:
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("service config must be an object")
    return value


def ipv4_file(path: str) -> str:
    with open(path, encoding="ascii") as handle:
        value = handle.read(64).strip()
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise ValueError("admin source must be an IPv4 address")
    return str(address)


def legacy_admin_source(policy: str) -> str:
    matches = re.findall(
        r'^\s*iifname "uplink0" ip saddr ([0-9.]+) tcp dport 22 accept\s*$',
        policy,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise ValueError("legacy firewall does not contain one admin source")
    address = ipaddress.ip_address(matches[0])
    if address.version != 4:
        raise ValueError("admin source must be an IPv4 address")
    return str(address)


def load_admin_source(path: str, legacy_policy: str = "/etc/nftables.conf") -> str:
    try:
        return ipv4_file(path)
    except FileNotFoundError:
        info = os.stat(legacy_policy, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("unsafe legacy firewall policy")
        with open(legacy_policy, encoding="utf-8") as handle:
            address = legacy_admin_source(handle.read(1024 * 1024 + 1))
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        temporary = f"{path}.tmp.{os.getpid()}"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, (address + "\n").encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        return address


def render(
    broker: dict | None,
    azure: dict | None,
    archive: dict | None = None,
    source: dict | None = None,
    *,
    admin_source_ipv4: str,
) -> str:
    admin_source = ipaddress.ip_address(admin_source_ipv4)
    if admin_source.version != 4:
        raise ValueError("admin source must be an IPv4 address")
    sets: list[str] = []
    rules: list[str] = []
    if broker and broker.get("mode") == "production":
        addresses = global_ipv4(broker.get("upstream_ipv4"), "upstream_ipv4")
        uid = pwd.getpwnam("model-broker").pw_uid
        sets.append("  set provider_ipv4 {\n    type ipv4_addr\n    flags constant\n    elements = { " + ", ".join(addresses) + " }\n  }")
        rules.append(f'    oifname "uplink0" meta skuid {uid} ip daddr @provider_ipv4 tcp dport 443 accept')
    if azure:
        addresses = global_ipv4(
            list(azure.get("token_ipv4", [])) + list(azure.get("ingestion_ipv4", [])),
            "Azure IPv4 allowlist",
        )
        uid = pwd.getpwnam("azure-shipper").pw_uid
        sets.append("  set azure_ipv4 {\n    type ipv4_addr\n    flags constant\n    elements = { " + ", ".join(addresses) + " }\n  }")
        rules.append(f'    oifname "uplink0" meta skuid {uid} ip daddr @azure_ipv4 tcp dport 443 accept')
    if archive:
        addresses = global_ipv4(
            list(archive.get("token_ipv4", [])) + list(archive.get("storage_ipv4", [])),
            "archive Azure IPv4 allowlist",
        )
        uid = pwd.getpwnam("conversation-azure").pw_uid
        sets.append("  set archive_ipv4 {\n    type ipv4_addr\n    flags constant\n    elements = { " + ", ".join(addresses) + " }\n  }")
        rules.append(f'    oifname "uplink0" meta skuid {uid} ip daddr @archive_ipv4 tcp dport 443 accept')
    if source:
        endpoint_values = source.get("endpoint_ipv4", {})
        addresses = global_ipv4(
            list(endpoint_values.get("api.github.com", []))
            + list(endpoint_values.get("codeload.github.com", []))
            + list(endpoint_values.get("registry.npmjs.org", [])),
            "source endpoint IPv4 allowlist",
        )
        uid = pwd.getpwnam("source-fetcher").pw_uid
        sets.append("  set source_ipv4 {\n    type ipv4_addr\n    flags constant\n    elements = { " + ", ".join(addresses) + " }\n  }")
        rules.append(f'    oifname "uplink0" meta skuid {uid} ip daddr @source_ipv4 tcp dport 443 accept')
    optional_sets = ("\n".join(sets) + "\n") if sets else ""
    optional_rules = ("\n".join(rules) + "\n") if rules else ""
    return f'''#!/usr/sbin/nft -f
flush ruleset
table inet filter {{
{optional_sets}  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "uplink0" ip saddr {admin_source} tcp dport 22 accept
    iifname "uplink0" udp sport 67 udp dport 68 accept
    iifname "ctl0" ip saddr 172.30.10.2 icmp type echo-request accept
    iifname "ctl0" ip saddr 172.30.10.2 tcp dport {{ 8443, 9443, 9553 }} accept
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-in-deny " flags all counter
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-fwd-deny " flags all counter
  }}
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    oifname "uplink0" udp sport 68 udp dport 67 accept
{optional_rules}    oifname "ctl0" ip daddr 172.30.10.2 tcp dport 22 accept
    limit rate 5/second burst 10 packets log prefix "sandbox-gw-out-deny " flags all counter
  }}
}}
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker-config", default="")
    parser.add_argument("--azure-config", default="")
    parser.add_argument("--archive-config", default="")
    parser.add_argument("--source-config", default="/etc/secure-sandbox/source-acquisition.json")
    parser.add_argument(
        "--admin-source-ipv4-file",
        default="/etc/secure-sandbox/gateway-admin-source-ipv4",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    policy = render(
        optional_json(args.broker_config),
        optional_json(args.azure_config),
        optional_json(args.archive_config),
        optional_json(args.source_config),
        admin_source_ipv4=load_admin_source(args.admin_source_ipv4_file),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(args.output, flags, 0o600)
    try:
        os.write(descriptor, policy.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()
