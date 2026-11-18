#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


PATH = Path(__file__).with_name("verify-parallels-networks.py")
SPEC = importlib.util.spec_from_file_location("verify_parallels_networks", PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)


def network(name, values):
    item = ET.Element("VirtualNetwork")
    ET.SubElement(item, "NetworkID").text = name
    host = ET.SubElement(item, "HostOnlyNetwork")
    ET.SubElement(host, "HostIPAddress").text = values["host address"]
    ET.SubElement(host, "DhcpIPAddress").text = values["DHCP address"]
    dhcp = ET.SubElement(host, "DHCPServer")
    ET.SubElement(dhcp, "Enabled").text = "0"
    ET.SubElement(dhcp, "IPScopeStart").text = values["range start"]
    ET.SubElement(dhcp, "IPScopeEnd").text = values["range end"]
    dhcp6 = ET.SubElement(host, "DHCPv6Server")
    ET.SubElement(dhcp6, "Enabled").text = "0"
    nat = ET.SubElement(host, "NATServer")
    ET.SubElement(nat, "Enabled").text = "0"
    adapter = ET.SubElement(host, "ParallelsAdapter")
    ET.SubElement(adapter, "Enabled").text = values["host adapter"]
    ET.SubElement(host, "HostAssignIPv6").text = "0"
    return item


class VerifyParallelsNetworksTests(unittest.TestCase):
    def write(self, items):
        root = ET.Element("ParallelsNetworkConfig")
        for item in items:
            root.append(item)
        temporary = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        temporary.close()
        path = Path(temporary.name)
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def valid(self):
        return [network(name, values) for name, values in VERIFY.EXPECTED.items()]

    def test_accepts_exact_isolated_control_and_detached_lab_planes(self):
        observed = VERIFY.verify(self.write(self.valid()))
        self.assertEqual(set(observed), {"control-net", "lab-net"})
        self.assertEqual(observed["control-net"]["host adapter"], "1")
        self.assertEqual(observed["lab-net"]["host adapter"], "0")

    def test_rejects_missing_duplicate_and_drifted_networks(self):
        cases = {
            "missing": self.valid()[:1],
            "duplicate": [*self.valid(), network(
                "control-net", VERIFY.EXPECTED["control-net"]
            )],
        }
        drifted = self.valid()
        drifted[0].find("HostOnlyNetwork/ParallelsAdapter/Enabled").text = "0"
        cases["drifted"] = drifted
        for label, items in cases.items():
            with self.subTest(label=label), self.assertRaises(
                VERIFY.NetworkVerificationError
            ):
                VERIFY.verify(self.write(items))


if __name__ == "__main__":
    unittest.main()
