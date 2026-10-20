#!/usr/bin/env python3
"""Render Research nftables rules with per-service UID egress controls."""

import argparse
import os
import pwd


def uid(name: str) -> int:
    return pwd.getpwnam(name).pw_uid


def render() -> str:
    return f'''#!/usr/sbin/nft -f
flush ruleset
table inet filter {{
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    iifname "ctl0" ip saddr 172.30.10.1 tcp dport 22 accept
    limit rate 5/second burst 10 packets log prefix "sandbox-r-in-deny " flags all counter
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    limit rate 5/second burst 10 packets log prefix "sandbox-r-fwd-deny " flags all counter
  }}
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state invalid drop
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
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    descriptor = os.open(args.output, flags, 0o600)
    try:
        os.write(descriptor, render().encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    main()
