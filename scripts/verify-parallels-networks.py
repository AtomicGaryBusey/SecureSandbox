#!/usr/bin/env python3
"""Assert the persisted Parallels custom-network isolation controls."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

PATH = "/Library/Preferences/Parallels/network.desktop.xml"
EXPECTED = {
    "control-net": {
        "host address": "172.30.10.30",
        "DHCP address": "172.30.10.1",
        "range start": "172.30.10.1",
        "range end": "172.30.10.29",
        "host adapter": "1",
    },
    "lab-net": {
        "host address": "172.30.20.2",
        "DHCP address": "172.30.20.1",
        "range start": "172.30.20.1",
        "range end": "172.30.20.30",
        "host adapter": "0",
    },
}

class NetworkVerificationError(RuntimeError):
    pass


def verify(path: Path | str = PATH) -> dict[str, dict[str, str]]:
    root = ET.parse(path).getroot()
    found: dict[str, dict[str, str]] = {}
    for network in root.iter("VirtualNetwork"):
        network_id = network.findtext("NetworkID")
        if network_id not in EXPECTED:
            continue
        if network_id in found:
            raise NetworkVerificationError(
                f"{network_id}: duplicate VirtualNetwork"
            )
        host = network.find("HostOnlyNetwork")
        if host is None:
            raise NetworkVerificationError(
                f"{network_id}: missing HostOnlyNetwork"
            )
        checks = {
            "host address": host.findtext("HostIPAddress") or "",
            "DHCP address": host.findtext("DhcpIPAddress") or "",
            "range start": host.findtext("DHCPServer/IPScopeStart") or "",
            "range end": host.findtext("DHCPServer/IPScopeEnd") or "",
            "host adapter": host.findtext("ParallelsAdapter/Enabled") or "",
        }
        failures = [
            name for name, expected in EXPECTED[network_id].items()
            if checks.get(name) != expected
        ]
        disabled = {
            "DHCPv4": host.findtext("DHCPServer/Enabled"),
            "DHCPv6": host.findtext("DHCPv6Server/Enabled"),
            "NAT": host.findtext("NATServer/Enabled"),
            "host IPv6 assignment": host.findtext("HostAssignIPv6"),
        }
        failures.extend(name for name, value in disabled.items() if value != "0")
        if failures:
            raise NetworkVerificationError(
                f"{network_id}: invalid: {', '.join(failures)}"
            )
        found[network_id] = checks
    expected_names = set(EXPECTED)
    found_names = set(found)
    if found_names != expected_names:
        missing = expected_names - found_names
        unexpected = found_names - expected_names
        raise NetworkVerificationError(
            "network inventory mismatch: "
            f"missing={','.join(sorted(missing)) or 'none'};"
            f"unexpected={','.join(sorted(unexpected)) or 'none'}"
        )
    return found


def main() -> int:
    try:
        verify()
    except (ET.ParseError, OSError, NetworkVerificationError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
