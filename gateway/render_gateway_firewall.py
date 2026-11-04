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
import time
from pathlib import Path

from shared import native_egress


DEFAULT_NATIVE_GRANT = Path("/var/lib/secure-sandbox/native-egress/active.json")
DEFAULT_NATIVE_INSTALL_STATE = Path(
    "/etc/secure-sandbox/native-egress-installed"
)


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


def load_native_cli_state(
    install_state_path: Path,
    grant_path: Path,
    *,
    now: int,
    expected_uid: int = 0,
    expected_install_gid: int = 0,
) -> tuple[dict | None, bool]:
    installed = native_egress.load_install_state(
        install_state_path,
        expected_uid=expected_uid,
        expected_gid=expected_install_gid,
    )
    try:
        identity = pwd.getpwnam("native-tunnel")
    except KeyError:
        identity = None
    if installed != (identity is not None):
        raise ValueError("native egress install state is ambiguous")
    try:
        grant_path.lstat()
    except FileNotFoundError:
        return None, installed
    except OSError as error:
        raise ValueError("native grant state is unavailable") from error
    if not installed or identity is None:
        raise ValueError("native grant exists without installed native identity")
    grant = native_egress.load_grant(
        grant_path,
        now=now,
        expected_uid=expected_uid,
        expected_gid=identity.pw_gid,
        expected_mode=0o640,
    )
    return grant, True


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
    native: dict | None = None,
    *,
    admin_source_ipv4: str,
    now: int | None = None,
    native_feature: bool = False,
) -> str:
    admin_source = ipaddress.ip_address(admin_source_ipv4)
    if admin_source.version != 4:
        raise ValueError("admin source must be an IPv4 address")
    sets: list[str] = []
    rules: list[str] = []
    native_input_rules: list[str] = []
    native_output_rules: list[str] = []
    if broker and broker.get("mode") == "production":
        addresses = global_ipv4(
            list(broker.get("upstream_ipv4", [])) + list(broker.get("oauth_ipv4", [])),
            "provider IPv4 allowlist",
        )
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
    if native is not None and not native_feature:
        raise ValueError("native grant requires the native firewall feature")
    if native_feature:
        uid = pwd.getpwnam("native-tunnel").pw_uid
        if native:
            timestamp = int(time.time()) if now is None else now
            grant = native_egress.validate_grant(
                native, now=timestamp
            )
            timeout = grant["expires_at"] - timestamp
            addresses = native_egress.flattened_ipv4(grant)
            provider_mark = native_egress.conntrack_mark(grant, "provider")
            research_mark = native_egress.conntrack_mark(grant, "research")
            sets.append(
                "  set native_provider_ipv4 {\n"
                "    type ipv4_addr\n"
                "    flags timeout\n"
                f"    timeout {timeout}s\n"
                "    elements = { "
                + ", ".join(
                    f"{address} timeout {timeout}s" for address in addresses
                )
                + " }\n  }"
            )
            native_input_rules.extend(
                (
                    f'    iifname "uplink0" ip saddr @native_provider_ipv4 tcp sport 443 ct mark {provider_mark} accept',
                    f'    iifname "ctl0" ip saddr 172.30.10.2 tcp dport 8643 ct state new ct mark 0 ct mark set {research_mark} accept',
                    f'    iifname "ctl0" ip saddr 172.30.10.2 tcp dport 8643 ct mark {research_mark} accept',
                )
            )
            native_output_rules.extend(
                (
                    f'    oifname "uplink0" meta skuid {uid} ip daddr @native_provider_ipv4 tcp dport 443 ct state new ct mark 0 ct mark set {provider_mark} accept',
                    f'    oifname "uplink0" meta skuid {uid} ip daddr @native_provider_ipv4 tcp dport 443 ct mark {provider_mark} accept',
                    f'    oifname "ctl0" ip daddr 172.30.10.2 tcp sport 8643 ct mark {research_mark} accept',
                )
            )
        # These guards remain when the active grant disappears. They precede
        # the generic established rule, so a policy reload revokes both halves
        # of already-established marked flows without trusting tunnel polling.
        native_input_rules.extend(
            (
                "    ct mark != 0 drop",
                '    iifname "ctl0" tcp dport 8643 drop',
            )
        )
        native_output_rules.extend(
            (
                f'    meta skuid {uid} drop',
                "    ct mark != 0 drop",
            )
        )
    optional_sets = ("\n".join(sets) + "\n") if sets else ""
    optional_rules = ("\n".join(rules) + "\n") if rules else ""
    native_input = ("\n".join(native_input_rules) + "\n") if native_input_rules else ""
    native_output = ("\n".join(native_output_rules) + "\n") if native_output_rules else ""
    return f'''#!/usr/sbin/nft -f
flush ruleset
table inet filter {{
{optional_sets}  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
{native_input}    ct state established,related accept
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
    ct state invalid drop
{native_output}    oifname "lo" accept
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
    parser.add_argument("--native-grant", type=Path, default=DEFAULT_NATIVE_GRANT)
    parser.add_argument(
        "--native-feature-state",
        type=Path,
        default=DEFAULT_NATIVE_INSTALL_STATE,
    )
    parser.add_argument(
        "--admin-source-ipv4-file",
        default="/etc/secure-sandbox/gateway-admin-source-ipv4",
    )
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        native, native_installed = load_native_cli_state(
            args.native_feature_state,
            args.native_grant,
            now=int(time.time()),
        )
    except (ValueError, native_egress.NativeEgressError) as error:
        parser.error(str(error))
    policy = render(
        optional_json(args.broker_config),
        optional_json(args.azure_config),
        optional_json(args.archive_config),
        optional_json(args.source_config),
        native,
        admin_source_ipv4=load_admin_source(args.admin_source_ipv4_file),
        native_feature=native_installed,
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
