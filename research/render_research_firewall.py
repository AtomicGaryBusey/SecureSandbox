#!/usr/bin/env python3
"""Render Research nftables rules with per-service UID egress controls."""

import argparse
import os
import pwd
import time
from pathlib import Path

from shared import native_egress


DEFAULT_NATIVE_GRANT = Path("/var/lib/secure-sandbox/native-egress/active.json")
DEFAULT_NATIVE_INSTALL_STATE = Path(
    "/etc/secure-sandbox/native-egress-installed"
)


def uid(name: str) -> int:
    return pwd.getpwnam(name).pw_uid


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
        identity = pwd.getpwnam("native-harness")
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


def render(
    native: dict | None = None,
    *,
    now: int | None = None,
    native_feature: bool = False,
) -> str:
    if native is not None and not native_feature:
        raise ValueError("native grant requires the native firewall feature")
    native_input = ""
    native_output = ""
    native_sets = ""
    if native_feature:
        supervisor_uid = uid("native-harness")
        provider_uids = (uid("native-claude"), uid("native-codex"))
        input_rules: list[str] = []
        output_rules: list[str] = []
        if native:
            timestamp = int(time.time()) if now is None else now
            grant = native_egress.validate_grant(
                native, now=timestamp
            )
            timeout = grant["expires_at"] - timestamp
            research_mark = native_egress.conntrack_mark(grant, "research")
            native_sets = (
                "  set native_gateway_ipv4 {\n"
                "    type ipv4_addr\n"
                "    flags timeout\n"
                f"    timeout {timeout}s\n"
                f"    elements = {{ 172.30.10.1 timeout {timeout}s }}\n"
                "  }\n"
            )
            input_rules.append(
                f'    iifname "ctl0" ip saddr @native_gateway_ipv4 tcp sport 8643 ct mark {research_mark} accept'
            )
            for provider_uid in provider_uids:
                output_rules.extend((
                    f'    oifname "ctl0" meta skuid {provider_uid} ip daddr @native_gateway_ipv4 tcp dport 8643 ct state new ct mark 0 ct mark set {research_mark} accept',
                    f'    oifname "ctl0" meta skuid {provider_uid} ip daddr @native_gateway_ipv4 tcp dport 8643 ct mark {research_mark} accept',
                ))
        input_rules.append("    ct mark != 0 drop")
        output_rules.extend(
            (
                f'    meta skuid {supervisor_uid} drop',
                *(f'    meta skuid {provider_uid} drop'
                  for provider_uid in provider_uids),
                "    ct mark != 0 drop",
            )
        )
        native_input = "\n".join(input_rules) + "\n"
        native_output = "\n".join(output_rules) + "\n"
    return f'''#!/usr/sbin/nft -f
flush ruleset
table inet filter {{
{native_sets}  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
{native_input}    ct state established,related accept
    iifname "ctl0" ip saddr 172.30.10.1 tcp dport 22 accept
    limit rate 5/second burst 10 packets log prefix "sandbox-r-in-deny " flags all counter
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    limit rate 5/second burst 10 packets log prefix "sandbox-r-fwd-deny " flags all counter
  }}
  chain output {{
    type filter hook output priority 0; policy drop;
    ct state invalid drop
{native_output}    oifname "lo" accept
    ct state established,related accept
    oifname "ctl0" ip daddr 172.30.10.1 icmp type echo-request accept
    oifname "ctl0" meta skuid {uid("claude-relay")} ip daddr 172.30.10.1 tcp dport 8443 accept
    oifname "ctl0" meta skuid {uid("telemetry-exporter")} ip daddr 172.30.10.1 tcp dport 9443 accept
    oifname "ctl0" meta skuid {uid("conversation-shipper")} ip daddr 172.30.10.1 tcp dport 9553 accept
    oifname "lab0" ip daddr 172.30.20.2 icmp type echo-request accept
    oifname "lab0" meta skuid {uid("labadmin")} ip daddr 172.30.20.2 tcp dport 22 accept
    oifname "lab0" meta skuid {uid("execution-broker")} ip daddr 172.30.20.2 tcp dport 8080 accept
    limit rate 5/second burst 10 packets log prefix "sandbox-r-out-deny " flags all counter
  }}
}}
'''


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-grant", type=Path, default=DEFAULT_NATIVE_GRANT)
    parser.add_argument(
        "--native-feature-state",
        type=Path,
        default=DEFAULT_NATIVE_INSTALL_STATE,
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
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(args.output, flags, 0o600)
    try:
        os.write(
            descriptor,
            render(
                native,
                native_feature=native_installed,
            ).encode(),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()
