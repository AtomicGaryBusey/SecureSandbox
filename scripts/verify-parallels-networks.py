#!/usr/bin/env python3
"""Assert the persisted Parallels custom-network isolation controls."""

import xml.etree.ElementTree as ET

PATH = "/Library/Preferences/Parallels/network.desktop.xml"
EXPECTED = {"control-net", "lab-net"}

root = ET.parse(PATH).getroot()
found = set()
for network in root.iter("VirtualNetwork"):
    network_id = network.findtext("NetworkID")
    if network_id not in EXPECTED:
        continue
    found.add(network_id)
    host = network.find("HostOnlyNetwork")
    if host is None:
        raise SystemExit(f"{network_id}: missing HostOnlyNetwork")
    checks = {
        "host adapter": host.findtext("ParallelsAdapter/Enabled"),
        "DHCPv4": host.findtext("DHCPServer/Enabled"),
        "DHCPv6": host.findtext("DHCPv6Server/Enabled"),
        "NAT": host.findtext("NATServer/Enabled"),
        "host IPv6 assignment": host.findtext("HostAssignIPv6"),
    }
    failures = [name for name, value in checks.items() if value != "0"]
    if failures:
        raise SystemExit(f"{network_id}: enabled: {', '.join(failures)}")
if found != EXPECTED:
    raise SystemExit(f"missing networks: {', '.join(sorted(EXPECTED - found))}")
