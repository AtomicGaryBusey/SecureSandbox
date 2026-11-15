#!/usr/bin/env python3

from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("vm-maintenance.py")
SPEC = importlib.util.spec_from_file_location("vm_maintenance", SCRIPT)
VM = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VM)


class VmMaintenanceTests(unittest.TestCase):
    NETWORKS = {
        "control-net": {"uuid": "{11111111-1111-4111-8111-111111111111}",
                        "host_ip": "172.30.10.2", "dhcp_ip": "172.30.10.1",
                        "netmask": "255.255.255.224", "range_start": "172.30.10.1",
                        "range_end": "172.30.10.30", "adapter_enabled": "0",
                        "dhcp4_enabled": "0", "dhcp6_enabled": "0",
                        "nat_enabled": "0", "host_assign_ipv6": "0"},
        "lab-net": {"uuid": "{22222222-2222-4222-8222-222222222222}",
                    "host_ip": "172.30.20.2", "dhcp_ip": "172.30.20.1",
                    "netmask": "255.255.255.224", "range_start": "172.30.20.1",
                    "range_end": "172.30.20.30", "adapter_enabled": "0",
                    "dhcp4_enabled": "0", "dhcp6_enabled": "0",
                    "nat_enabled": "0", "host_assign_ipv6": "0"},
    }

    @staticmethod
    def shared_network_xml(**changes):
        values = {
            "network_id": "Shared", "enabled": "1", "network_type": "1",
            "host_ip": "10.211.55.2", "dhcp_ip": "10.211.55.1",
            "netmask": "255.255.255.0", "ipv6": "0", "dhcp": "1",
            "start": "10.211.55.1", "end": "10.211.55.254", "nat": "1",
        }
        values.update(changes)
        return ET.fromstring("""<Root><VirtualNetwork>
<NetworkID>{network_id}</NetworkID><Enabled>{enabled}</Enabled>
<NetworkType>{network_type}</NetworkType><HostOnlyNetwork>
<HostIPAddress>{host_ip}</HostIPAddress><DhcpIPAddress>{dhcp_ip}</DhcpIPAddress>
<IPNetMask>{netmask}</IPNetMask><HostAssignIPv6>{ipv6}</HostAssignIPv6>
<DHCPServer><Enabled>{dhcp}</Enabled><IPScopeStart>{start}</IPScopeStart>
<IPScopeEnd>{end}</IPScopeEnd></DHCPServer>
<NATServer><Enabled>{nat}</Enabled></NATServer>
</HostOnlyNetwork></VirtualNetwork></Root>""".format(**values))

    @staticmethod
    def gateway_value(home, **changes):
        value = {
            "ID": "11111111-1111-4111-8111-111111111111",
            "Name": VM.NAMES[0], "State": "running", "Home": str(home) + "/",
            "Network": {
                "Conditioned": "off",
                "ipAddresses": [
                    {"type": "ipv4", "ip": "10.211.55.5"},
                    {"type": "ipv6", "ip": "fe80::21c:42ff:febc:794f"},
                ],
            },
            "Hardware": {
                "net0": {"enabled": True, "type": "shared", "mac": "001C42BC794F"},
                "net1": {"enabled": True, "type": "host", "iface": "control-net",
                         "mac": "001C4292EA7F"},
                "cdrom0": {"enabled": False},
                "cdrom1": {"enabled": False},
            },
        }
        value.update(changes)
        return value

    def test_parallels_json_uuid_is_normalized_to_transaction_form(self):
        bare = "-".join(("1" * 8, "2" * 4, "4" + "3" * 3, "8" + "4" * 3, "5" * 12))
        canonical = "{" + bare.lower() + "}"
        self.assertEqual(
            VM.normalize_vm_uuid(bare),
            canonical,
        )
        self.assertEqual(
            VM.normalize_vm_uuid("{" + bare + "}"),
            canonical,
        )
        for invalid in (None, "", "3967a31d-cea2-4cbf-8d7e", "../Gateway"):
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_uuid_invalid"):
                VM.normalize_vm_uuid(invalid)

    def test_vm_identity_accepts_actual_parallels_bare_json_uuid(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "SecureSandbox-Gateway.pvm"
            home.mkdir()
            bare = "-".join(("1" * 8, "2" * 4, "4" + "3" * 3, "8" + "4" * 3, "5" * 12))
            response = json.dumps([{
                "ID": bare,
                "Name": VM.NAMES[0], "State": "stopped", "Home": str(home) + "/",
            }])
            with mock.patch.object(VM, "run", return_value=response):
                identity = VM.vm_identity(VM.NAMES[0], home)
            self.assertEqual(identity["uuid"], "{" + bare + "}")

    def test_trusted_directory_validates_link_count_and_binds_stable_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            identity = VM.trusted_directory(path, os.geteuid())
            self.assertEqual(identity, (path.lstat().st_dev, path.lstat().st_ino))
            self.assertGreaterEqual(path.lstat().st_nlink, 1)

    def test_plan_digest_binds_all_security_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            with (mock.patch.object(VM, "trusted_repo", return_value=repo),
                  mock.patch.object(VM, "installer_path", return_value=Path("/protected/installer.iso")),
                  mock.patch.object(VM, "seed_hashes", return_value={role: role[0] * 64 for role in VM.ROLES}),
                  mock.patch.object(VM, "vm_inventory", return_value=[]),
                  mock.patch.object(VM, "private_network_config", return_value=self.NETWORKS),
                  mock.patch.object(VM, "host_memory_bytes", return_value=24 * 1024**3),
                  mock.patch.object(VM, "prlctl_hash", return_value="a" * 64)):
                first = VM.build_plan(str(repo), "create", 501)
                second = VM.build_plan(str(repo), "create", 501)
            self.assertEqual(first, second)
            unsigned = dict(first)
            claimed = unsigned.pop("plan_sha256")
            self.assertEqual(claimed, hashlib.sha256(VM.canonical(unsigned)).hexdigest())
            unsigned["prlctl_sha256"] = "b" * 64
            self.assertNotEqual(claimed, hashlib.sha256(VM.canonical(unsigned)).hexdigest())
            self.assertEqual(first["layout_profile"], "standard")
            self.assertEqual(first["layout"]["research"]["memory_mib"], 6144)
            self.assertEqual(first["network_config"], self.NETWORKS)

    def test_neo_layout_is_explicit_and_host_bound(self):
        with mock.patch.object(VM, "host_memory_bytes", return_value=8 * 1024**3):
            layout, memory = VM.checked_layout("neo-8gb")
            self.assertEqual(memory, 8 * 1024**3)
            self.assertEqual(sum(role["memory_mib"] for role in layout.values()), 5632)
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_layout_host_memory_mismatch"):
                VM.checked_layout("standard")
        with mock.patch.object(VM, "host_memory_bytes", return_value=24 * 1024**3):
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_layout_host_memory_mismatch"):
                VM.checked_layout("neo-8gb")

    def test_private_networks_require_exact_closed_topology(self):
        def network(name, uuid, prefix):
            return f"""<VirtualNetwork><Uuid>{uuid}</Uuid><NetworkID>{name}</NetworkID>
<Enabled>1</Enabled><NetworkType>1</NetworkType><HostOnlyNetwork>
<HostIPAddress>172.30.{prefix}.2</HostIPAddress><DhcpIPAddress>172.30.{prefix}.1</DhcpIPAddress>
<IPNetMask>255.255.255.224</IPNetMask><HostAssignIPv6>0</HostAssignIPv6>
<ParallelsAdapter><Enabled>0</Enabled></ParallelsAdapter>
<DHCPServer><Enabled>0</Enabled><IPScopeStart>172.30.{prefix}.1</IPScopeStart>
<IPScopeEnd>172.30.{prefix}.30</IPScopeEnd></DHCPServer>
<DHCPv6Server><Enabled>0</Enabled></DHCPv6Server>
<NATServer><Enabled>0</Enabled></NATServer></HostOnlyNetwork></VirtualNetwork>"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "network.desktop.xml"
            path.write_text("<Root>" +
                network("control-net", "{11111111-1111-4111-8111-111111111111}", "10") +
                network("lab-net", "{22222222-2222-4222-8222-222222222222}", "20") +
                "</Root>", encoding="utf-8")
            with mock.patch.object(
                    VM, "reject_extended_acl", wraps=VM.reject_extended_acl) as acl_check:
                self.assertEqual(
                    VM.private_network_config(path, os.getuid()), self.NETWORKS,
                )
            self.assertEqual(acl_check.call_count, 2)
            path.write_text(path.read_text().replace(
                "<DHCPServer><Enabled>0</Enabled>",
                "<DHCPServer><Enabled>1</Enabled>", 1), encoding="utf-8")
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_network_config_invalid:control-net"):
                VM.private_network_config(path, os.getuid())
            path.write_text("<Root>" +
                network("control-net", "{11111111-1111-4111-8111-111111111111}", "10") +
                network("lab-net", "{22222222-2222-4222-8222-222222222222}", "20") +
                "</Root>", encoding="utf-8")
            path.write_text(path.read_text().replace(
                "<IPScopeEnd>172.30.10.30</IPScopeEnd>",
                "<IPScopeEnd>172.30.10.31</IPScopeEnd>", 1), encoding="utf-8")
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_network_config_invalid:control-net"):
                VM.private_network_config(path, os.getuid())

    def test_private_networks_reject_overlapping_or_duplicate_other_planes(self):
        def network(name, uuid, prefix):
            return f"""<VirtualNetwork><Uuid>{uuid}</Uuid><NetworkID>{name}</NetworkID>
<Enabled>1</Enabled><NetworkType>1</NetworkType><HostOnlyNetwork>
<HostIPAddress>172.30.{prefix}.2</HostIPAddress><DhcpIPAddress>172.30.{prefix}.1</DhcpIPAddress>
<IPNetMask>255.255.255.224</IPNetMask><HostAssignIPv6>0</HostAssignIPv6>
<ParallelsAdapter><Enabled>0</Enabled></ParallelsAdapter>
<DHCPServer><Enabled>0</Enabled><IPScopeStart>172.30.{prefix}.1</IPScopeStart>
<IPScopeEnd>172.30.{prefix}.30</IPScopeEnd></DHCPServer>
<DHCPv6Server><Enabled>0</Enabled></DHCPv6Server><NATServer><Enabled>0</Enabled></NATServer>
</HostOnlyNetwork></VirtualNetwork>"""
        control = network("control-net", "{11111111-1111-4111-8111-111111111111}", "10")
        lab = network("lab-net", "{22222222-2222-4222-8222-222222222222}", "20")
        overlap = network("other-net", "{33333333-3333-4333-8333-333333333333}", "10")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "network.desktop.xml"
            path.write_text(f"<Root>{control}{lab}{overlap}</Root>", encoding="utf-8")
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_network_overlap:other-net"):
                VM.private_network_config(path, os.getuid())
            duplicate = overlap.replace(
                "{33333333-3333-4333-8333-333333333333}",
                "{11111111-1111-4111-8111-111111111111}",
            ).replace("172.30.10", "172.30.30")
            path.write_text(f"<Root>{control}{lab}{duplicate}</Root>", encoding="utf-8")
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_network_config_invalid"):
                VM.private_network_config(path, os.getuid())

    def test_shared_network_scope_requires_one_enabled_nat_dhcp_plane(self):
        subnet, start, end, excluded = VM.shared_network_scope(self.shared_network_xml())
        self.assertEqual(str(subnet), "10.211.55.0/24")
        self.assertEqual((str(start), str(end)), ("10.211.55.1", "10.211.55.254"))
        self.assertEqual({str(value) for value in excluded}, {
            "10.211.55.0", "10.211.55.1", "10.211.55.2", "10.211.55.255",
        })
        invalid_roots = [
            self.shared_network_xml(enabled="0"),
            self.shared_network_xml(network_type="0"),
            self.shared_network_xml(dhcp="0"),
            self.shared_network_xml(nat="0"),
            self.shared_network_xml(ipv6="1"),
            self.shared_network_xml(start="10.211.56.1"),
            self.shared_network_xml(start="10.211.55.255"),
            self.shared_network_xml(start="10.211.55.200", end="10.211.55.100"),
        ]
        duplicate = self.shared_network_xml()
        duplicate.append(list(self.shared_network_xml())[0])
        invalid_roots.append(duplicate)
        for root in invalid_roots:
            with self.subTest(root=ET.tostring(root)):
                with self.assertRaisesRegex(VM.MaintenanceError, "vm_shared_network_invalid"):
                    VM.shared_network_scope(root)

    def test_gateway_proxy_resolves_only_exact_running_vm_in_shared_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "SecureSandbox"
            home = repo / "vms" / f"{VM.NAMES[0]}.pvm"
            home.mkdir(parents=True)
            value = self.gateway_value(home)
            with (mock.patch.object(VM.os, "getuid", return_value=os.geteuid()),
                  mock.patch.object(VM, "trusted_repo", return_value=repo),
                  mock.patch.object(VM, "trusted_root_executable"),
                  mock.patch.object(VM, "trusted_network_root",
                                    return_value=self.shared_network_xml()),
                  mock.patch.object(VM, "run", return_value=json.dumps([value])) as run):
                self.assertEqual(
                    VM.gateway_proxy_endpoint(os.geteuid(), repo=repo), "10.211.55.5",
                )
            run.assert_called_once_with([
                str(VM.PRLCTL), "list", "-a", "-i", "-j", VM.NAMES[0],
            ], capture=True)

    def test_gateway_proxy_rejects_vm_identity_topology_media_and_address_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "SecureSandbox"
            home = repo / "vms" / f"{VM.NAMES[0]}.pvm"
            home.mkdir(parents=True)
            canonical = self.gateway_value(home)
            cases = {
                "stopped": {**canonical, "State": "stopped"},
                "wrong-name": {**canonical, "Name": "Other"},
                "wrong-home": {**canonical, "Home": str(repo / "vms/Other.pvm")},
                "wrong-mac": {**canonical, "Hardware": {
                    **canonical["Hardware"],
                    "net0": {"enabled": True, "type": "shared", "mac": "001C42FFFFFF"},
                }},
                "extra-nic": {**canonical, "Hardware": {
                    **canonical["Hardware"],
                    "net2": {"enabled": True, "type": "shared", "mac": "001C42000000"},
                }},
                "media": {**canonical, "Hardware": {
                    **canonical["Hardware"], "cdrom1": {"enabled": True},
                }},
                "malformed-media": {**canonical, "Hardware": {
                    **canonical["Hardware"], "cdrom1": "unexpected",
                }},
                "malformed-enabled": {**canonical, "Hardware": {
                    **canonical["Hardware"],
                    "net0": {"enabled": "false", "type": "shared",
                             "mac": "001C42BC794F"},
                }},
                "outside-scope": {**canonical, "Network": {
                    "Conditioned": "off",
                    "ipAddresses": [{"type": "ipv4", "ip": "192.0.2.5"}],
                }},
                "excluded": {**canonical, "Network": {
                    "Conditioned": "off",
                    "ipAddresses": [{"type": "ipv4", "ip": "10.211.55.2"}],
                }},
                "multiple-ipv4": {**canonical, "Network": {
                    "Conditioned": "off", "ipAddresses": [
                        {"type": "ipv4", "ip": "10.211.55.5"},
                        {"type": "ipv4", "ip": "10.211.55.6"},
                    ],
                }},
                "missing-ip": {**canonical, "Network": {
                    "Conditioned": "off", "ipAddresses": [],
                }},
                "conditioned": {**canonical, "Network": {
                    "Conditioned": "on",
                    "ipAddresses": [{"type": "ipv4", "ip": "10.211.55.5"}],
                }},
                "type-mismatch": {**canonical, "Network": {
                    "Conditioned": "off",
                    "ipAddresses": [{"type": "ipv6", "ip": "10.211.55.5"}],
                }},
            }
            for name, value in cases.items():
                with self.subTest(name=name), \
                     mock.patch.object(VM.os, "getuid", return_value=os.geteuid()), \
                     mock.patch.object(VM, "trusted_repo", return_value=repo), \
                     mock.patch.object(VM, "trusted_root_executable"), \
                     mock.patch.object(VM, "trusted_network_root",
                                       return_value=self.shared_network_xml()), \
                     mock.patch.object(VM, "run", return_value=json.dumps([value])):
                    with self.assertRaisesRegex(
                            VM.MaintenanceError,
                            "gateway_proxy_(vm|address)_invalid"):
                        VM.gateway_proxy_endpoint(os.geteuid(), repo=repo)

    def test_gateway_proxy_exec_is_port_22_only_and_content_free_on_rejection(self):
        with self.assertRaisesRegex(VM.MaintenanceError, "gateway_proxy_port_invalid"):
            VM.exec_gateway_proxy(2222)
        with (mock.patch.object(VM, "gateway_proxy_endpoint", return_value="10.211.55.5"),
              mock.patch.object(VM.os, "execve", side_effect=RuntimeError("exec intercepted")) as execute):
            with self.assertRaisesRegex(RuntimeError, "exec intercepted"):
                VM.exec_gateway_proxy(22)
        execute.assert_called_once_with(
            str(VM.NC), [str(VM.NC), "-w", "10", "10.211.55.5", "22"],
            {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        with (mock.patch.object(VM.sys, "argv", [
                  "vm-maintenance.py", "proxy-gateway", "--port", "2222",
              ]), redirect_stderr(io.StringIO()) as error):
            self.assertEqual(VM.main(), 1)
        self.assertEqual(json.loads(error.getvalue()), {
            "status": "rejected", "error": "gateway_proxy_rejected",
        })
        with (mock.patch.object(VM.os, "geteuid", return_value=0),
              mock.patch.object(VM.os, "getuid", return_value=501)):
            with self.assertRaisesRegex(
                    VM.MaintenanceError, "gateway_proxy_unprivileged_user_required"):
                VM.gateway_proxy_endpoint(501)

    def test_resource_readback_rejects_missing_or_conflicting_values(self):
        for detail in (
                "Hardware:\n  cpu cpus=2 VT-x\n  memory 2560Mb\n",
                "Hardware:\n"
                "  cpu cpus=2 auto=off VT-x accl=high mode=64 type=arm\n"
                "  memory size=2560Mb auto=off\n"):
            with mock.patch.object(VM, "run", return_value=detail):
                self.assertEqual(VM.vm_cpu_memory("vm-id"), (2, 2560))
        for detail in ("Hardware:\n  cpu cpus=2\n",
                       "Hardware:\n  cpu cpus=2\n  memory 2560Mb\n  memory 4096Mb\n"):
            with mock.patch.object(VM, "run", return_value=detail):
                with self.assertRaisesRegex(VM.MaintenanceError, "vm_resource_readback_invalid"):
                    VM.vm_cpu_memory("vm-id")

    def test_disk_readback_requires_one_expanding_disk_of_declared_size(self):
        home = Path("/repo/vms/SecureSandbox-Gateway.pvm")
        disk = {"enabled": True, "type": "expanded", "size": "12288Mb",
                "image": str(home / "harddisk1.hdd")}
        with mock.patch.object(VM, "run", return_value=json.dumps([{"Hardware": {"hdd0": disk}}])):
            self.assertEqual(VM.vm_disk_size("vm-id", home), 12288)
        for invalid in (
                {"hdd0": {**disk, "size": "12287Mb"}, "hdd1": disk},
                {"hdd0": {**disk, "size": "12GiB"}},
                {"hdd0": {**disk, "type": "plain"}},
                {"hdd0": {**disk, "image": "/elsewhere/harddisk1.hdd"}},
                {"hdd0": {**disk, "enabled": False}},
                {}):
            with mock.patch.object(VM, "run", return_value=json.dumps([{"Hardware": invalid}])):
                with self.assertRaisesRegex(VM.MaintenanceError, "vm_disk_readback_invalid"):
                    VM.vm_disk_size("vm-id", home)

    def test_post_create_resource_mismatch_rejects_before_configuration_success(self):
        identity = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/repo/vms/SecureSandbox-Gateway.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        with mock.patch.object(VM, "vm_cpu_memory", return_value=(4, 4096)):
            with self.assertRaisesRegex(VM.MaintenanceError, "effective_resources_invalid"):
                VM.verify_created(Path("/repo"), Path("/installer"),
                                  {VM.NAMES[0]: identity}, VM.LAYOUTS["neo-8gb"])
        with (mock.patch.object(VM, "vm_cpu_memory", return_value=(1, 1536)),
              mock.patch.object(VM, "vm_disk_size", return_value=12287)):
            with self.assertRaisesRegex(VM.MaintenanceError, "effective_resources_invalid"):
                VM.verify_created(Path("/repo"), Path("/installer"),
                                  {VM.NAMES[0]: identity}, VM.LAYOUTS["neo-8gb"])

    def test_execution_requires_root_broker_before_privilege_drop(self):
        with mock.patch.object(VM.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(VM.MaintenanceError, "root_broker_required"):
                VM.drop_privileges(501)

    def test_each_operator_displayed_component_is_revalidated(self):
        plan = {
            "plan_sha256": "a" * 64, "prlctl_sha256": "b" * 64,
            "installer_sha256": "c" * 64,
            "seed_sha256": {role: str(index) * 64 for index, role in enumerate(VM.ROLES, start=1)},
        }
        expected = {key: plan[key] for key in ("prlctl_sha256", "installer_sha256", "seed_sha256")}
        VM.validate_plan_bindings(plan, plan["plan_sha256"], expected)
        for key in ("prlctl_sha256", "installer_sha256", "seed_sha256"):
            forged = dict(expected)
            forged[key] = ({role: "f" * 64 for role in VM.ROLES}
                           if key == "seed_sha256" else "f" * 64)
            with self.assertRaisesRegex(VM.MaintenanceError, "maintenance_component_binding_changed"):
                VM.validate_plan_bindings(plan, plan["plan_sha256"], forged)

    def test_same_name_substitution_is_never_deleted(self):
        original = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/original.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        substituted = {**original, "uuid": "{22222222-2222-4222-8222-222222222222}"}
        def fail_after_recording(*args):
            created = args[-2]
            created.append(original)
            raise VM.MaintenanceError("configure_failed")

        with (tempfile.TemporaryDirectory() as temporary,
              mock.patch.object(VM, "create_one", side_effect=fail_after_recording),
              mock.patch.object(VM, "vm_identity", return_value=substituted),
              mock.patch.object(VM.subprocess, "run") as cleanup):
            original["expected_home"] = str(Path(temporary) / f"vms/{VM.NAMES[0]}.pvm")
            substituted["expected_home"] = original["expected_home"]
            with self.assertRaisesRegex(VM.MaintenanceError, "configure_failed"):
                VM.create_all(Path(temporary), Path("/installer"))
        cleanup.assert_not_called()

    def test_network_drift_before_attachment_aborts_creation(self):
        changed = json.loads(json.dumps(self.NETWORKS))
        changed["control-net"]["nat_enabled"] = "1"
        with (tempfile.TemporaryDirectory() as temporary,
              mock.patch.object(VM, "private_network_config",
                                side_effect=[self.NETWORKS, changed]),
              mock.patch.object(VM, "create_one", return_value="gateway-id"),
              mock.patch.object(VM.subprocess, "run") as cleanup):
            with self.assertRaisesRegex(VM.MaintenanceError, "vm_network_config_changed"):
                VM.create_all(
                    Path(temporary), Path("/installer"),
                    expected_networks=self.NETWORKS,
                )
        cleanup.assert_not_called()

    def test_vm_network_macs_are_exact_and_device_bound(self):
        with mock.patch.object(VM, "set_vm") as set_vm:
            VM.set_vm_network_macs("gateway-id", VM.NAMES[0])
            VM.set_vm_network_macs("research-id", VM.NAMES[1])
            VM.set_vm_network_macs("target-id", VM.NAMES[2])
        self.assertEqual(
            set_vm.call_args_list,
            [
                mock.call("gateway-id", "--device-set", "net0", "--mac", "001C42BC794F"),
                mock.call("gateway-id", "--device-set", "net1", "--mac", "001C4292EA7F"),
                mock.call("research-id", "--device-set", "net1", "--mac", "001C429945C7"),
                mock.call("research-id", "--device-set", "net2", "--mac", "001C420B2402"),
                mock.call("target-id", "--device-set", "net1", "--mac", "001C4249D2AA"),
            ],
        )

    def test_vm_network_macs_match_tracked_seed_netplans(self):
        repo = SCRIPT.parent.parent
        expected = {
            "gateway": {
                "net0": "001C42BC794F", "net1": "001C4292EA7F",
            },
            "research": {
                "net1": "001C429945C7", "net2": "001C420B2402",
            },
            "target": {"net1": "001C4249D2AA"},
        }
        for role, name in zip(VM.ROLES, VM.NAMES):
            self.assertEqual(VM.NETWORK_MACS[name], expected[role])
            netplan = (
                repo / f"config/netplan-{role}.example.yaml"
            ).read_text(encoding="utf-8")
            for mac in expected[role].values():
                colon_mac = ":".join(
                    mac[index:index + 2] for index in range(0, len(mac), 2)
                ).lower()
                self.assertIn(f"macaddress: {colon_mac}", netplan)

    def test_post_create_readback_rejects_seed_mac_mismatch(self):
        identity = {
            "name": VM.NAMES[0],
            "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/repo/vms/SecureSandbox-Gateway.pvm",
            "state": "stopped", "bundle_device": 1, "bundle_inode": 2,
        }
        hardware = {
            "cdrom0": {"image": "/installer"},
            "cdrom1": {"image": "/release/seed_gateway"},
            "net0": {"enabled": True, "type": "shared", "mac": "001C42FFFFFF"},
            "net1": {"enabled": True, "type": "host", "iface": "control-net",
                     "mac": VM.NETWORK_MACS[VM.NAMES[0]]["net1"]},
        }
        value = {
            "State": "stopped", "Hardware": hardware,
            "USB and Bluetooth": {
                "Automatic sharing cameras": "off",
                "Automatic sharing bluetooth": "off",
                "Automatic sharing smart cards": "off",
                "Automatic sharing gamepads": "off",
                "Support USB 3.0": "off",
            },
        }
        with (mock.patch.object(VM, "vm_cpu_memory", return_value=(1, 1536)),
              mock.patch.object(VM, "vm_disk_size", return_value=12288),
              mock.patch.object(VM, "vm_identity", return_value=identity),
              mock.patch.object(VM, "protected_seed_paths",
                                return_value={"gateway": Path("/release/seed_gateway")}),
              mock.patch.object(VM, "run", return_value=json.dumps([value]))):
            with self.assertRaisesRegex(VM.MaintenanceError, "effective_configuration_invalid"):
                VM.verify_created(
                    Path("/repo"), Path("/installer"),
                    {VM.NAMES[0]: identity}, VM.LAYOUTS["neo-8gb"],
                )

    def test_privilege_drop_must_be_irreversible(self):
        account = mock.Mock(pw_name="operator", pw_gid=20, pw_dir="/Users/operator")
        with (mock.patch.object(VM.os, "geteuid", side_effect=[0, 501]),
              mock.patch.object(VM.os, "getuid", return_value=501),
              mock.patch.object(VM.pwd, "getpwuid", return_value=account),
              mock.patch.object(VM.os, "initgroups"), mock.patch.object(VM.os, "setgid"),
              mock.patch.object(VM.os, "setuid", side_effect=[None, OSError("denied")])):
            VM.drop_privileges(501)

    def test_partial_creation_deletes_only_vms_created_by_this_attempt(self):
        calls = []
        identity = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "", "state": "stopped", "bundle_device": 1, "bundle_inode": 2,
        }

        def fake_run(command, **_kwargs):
            calls.append(command)
            if len(command) > 1 and command[1] == "set":
                raise VM.MaintenanceError("simulated_failure")
            return ""

        with (tempfile.TemporaryDirectory() as temporary,
              mock.patch.object(VM, "run", side_effect=fake_run),
              mock.patch.object(VM.subprocess, "run") as cleanup):
            identity["expected_home"] = str(Path(temporary) / f"vms/{VM.NAMES[0]}.pvm")
            with mock.patch.object(VM, "vm_identity", return_value=identity):
                with self.assertRaisesRegex(VM.MaintenanceError, "simulated_failure"):
                    VM.create_all(Path(temporary), Path("/protected/installer.iso"))
        cleanup_commands = [call.args[0] for call in cleanup.call_args_list]
        self.assertTrue(any(command[1:3] == ["delete", identity["uuid"]] for command in cleanup_commands))
        self.assertFalse(any(len(command) > 2 and command[1] == "delete" and command[2] != identity["uuid"]
                             for command in cleanup_commands))

    def test_new_vm_is_journaled_before_every_configuration_step(self):
        identity = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/new.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        events = []

        def fake_run(command, **_kwargs):
            events.append(("run", command[1]))
            if command[1] == "list":
                return json.dumps([{"Hardware": {
                    "usb": {}, "sound0": {}, "serial0": {},
                }}])
            return ""

        def record(created):
            events.append(("journal", created["uuid"]))

        with (mock.patch.object(VM, "run", side_effect=fake_run),
              mock.patch.object(VM, "vm_identity", return_value=identity)):
            VM.create_one(Path("/repo"), VM.NAMES[0], 1, 2048, 12288,
                          Path("/seed"), Path("/installer"), [], record)
        self.assertEqual(events[0], ("run", "create"))
        self.assertEqual(events[1], ("journal", identity["uuid"]))
        self.assertTrue(all(event[0] == "run" for event in events[2:]))

    def test_absent_optional_default_device_is_already_hardened(self):
        commands = []

        def fake_run(command, **_kwargs):
            commands.append(command)
            if command[1] == "list":
                return json.dumps([{"Hardware": {"usb": {}, "sound0": {}}}])
            return ""

        with mock.patch.object(VM, "run", side_effect=fake_run):
            VM.remove_present_devices("vm-id", "usb", "sound0", "serial0")
        removed = [command[-1] for command in commands if command[1] == "set"]
        self.assertEqual(removed, ["usb", "sound0"])
        self.assertNotIn("serial0", removed)

    def test_optional_device_inventory_is_fail_closed(self):
        for invalid in ("", "{}", "[]", '[{"Hardware": []}]'):
            with mock.patch.object(VM, "run", return_value=invalid):
                with self.assertRaises((VM.MaintenanceError, json.JSONDecodeError)):
                    VM.remove_present_devices("vm-id", "serial0")

    def test_crash_after_each_configuration_step_has_persisted_created_identity(self):
        identity = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/new.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        # There are currently 31 fixed configuration calls. Every simulated
        # abrupt stop after creation must observe the same already-persisted
        # identity before the failing call.
        for fail_at in range(1, 32):
            journal = []
            set_calls = 0

            def fake_run(command, **_kwargs):
                nonlocal set_calls
                if command[1] == "set":
                    set_calls += 1
                    if set_calls == fail_at:
                        raise KeyboardInterrupt("simulated abrupt stop")
                if command[1] == "list":
                    return json.dumps([{"Hardware": {
                        "usb": {}, "sound0": {}, "serial0": {},
                    }}])
                return ""

            with (mock.patch.object(VM, "run", side_effect=fake_run),
                  mock.patch.object(VM, "vm_identity", return_value=identity)):
                with self.assertRaises(KeyboardInterrupt):
                    VM.create_one(Path("/repo"), VM.NAMES[0], 1, 2048, 12288,
                                  Path("/seed"), Path("/installer"), [], journal.append)
            self.assertEqual(journal, [identity], f"configuration step {fail_at}")

    def test_bundle_is_revalidated_after_unregister_before_quarantine_move(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / ".private").mkdir(mode=0o700)
            source = repo / f"vms/{VM.NAMES[0]}.pvm"
            source.mkdir(parents=True)
            info = source.lstat()
            expected = [{
                "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
                "expected_home": str(source), "state": "stopped",
                "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
            }]

            def substitute_after_unregister(command, **_kwargs):
                if command[1] == "unregister":
                    source.rename(source.with_name("original-away.pvm"))
                    source.mkdir()
                return ""

            with (mock.patch.object(VM, "run", side_effect=substitute_after_unregister),
                  mock.patch.object(VM, "vm_identity", return_value=expected[0]),
                  mock.patch.object(VM, "recover_transaction", return_value=repo / "quarantine"),
                  mock.patch.object(VM, "create_all") as create_all):
                with self.assertRaisesRegex(VM.MaintenanceError, "vm_bundle_identity_changed"):
                    VM.reprovision(repo, Path("/installer"), expected, "a" * 64, os.geteuid())
            create_all.assert_not_called()
            self.assertTrue(source.is_dir())

    def test_reprovision_rollback_never_deletes_unowned_same_named_vms(self):
        source_by_name = {}
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            for name in VM.NAMES:
                source = repo / f"vms/{name}.pvm"
                source.mkdir(parents=True)
                source_by_name[name] = source
            commands = []
            expected = []
            for index, name in enumerate(VM.NAMES, start=1):
                info = source_by_name[name].lstat()
                expected.append({
                    "name": name, "uuid": f"{{00000000-0000-4000-8000-{index:012d}}}",
                    "expected_home": str(source_by_name[name]), "state": "stopped",
                    "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
                })

            def fake_run(command, **_kwargs):
                commands.append(command)
                return ""

            identity_by_uuid = {item["uuid"]: item for item in expected}
            identity_by_uuid.update({item["name"]: item for item in expected})
            with (mock.patch.object(VM, "run", side_effect=fake_run),
                  mock.patch.object(VM, "vm_identity", side_effect=lambda selector, _home: identity_by_uuid[selector]),
                  mock.patch.object(VM, "create_all", side_effect=VM.MaintenanceError("fail")),
                  mock.patch.object(VM.subprocess, "run") as fallback):
                with self.assertRaisesRegex(VM.MaintenanceError, "fail"):
                    VM.reprovision(repo, Path("/protected/installer.iso"), expected, "a" * 64, os.geteuid())
            self.assertFalse(any(len(command) > 1 and command[1] == "delete" for command in commands))
            fallback.assert_not_called()
            for source in source_by_name.values():
                self.assertTrue(source.is_dir())

    def test_crash_left_transaction_restores_and_reregisters_original_identities(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "vms").mkdir()
            (repo / ".private").mkdir(mode=0o700)
            directories = VM.maintenance_directories(repo, os.geteuid())
            quarantine = directories["quarantine"][0] / "20261021T000000Z-11111111-1111-4111-8111-111111111111"
            quarantine.mkdir(mode=0o700)
            directories["quarantine"] = (
                directories["quarantine"][0],
                VM.trusted_directory(directories["quarantine"][0], os.geteuid()),
            )
            originals = []
            for index, name in enumerate(VM.NAMES, start=1):
                bundle = quarantine / f"{name}.pvm"
                bundle.mkdir()
                info = bundle.lstat()
                originals.append({
                    "name": name, "uuid": f"{{00000000-0000-4000-8000-{index:012d}}}",
                    "expected_home": str(repo / f"vms/{name}.pvm"), "state": "stopped",
                    "bundle_device": info.st_dev, "bundle_inode": info.st_ino,
                })
            transaction = {
                "schema": VM.TRANSACTION_SCHEMA, "repo": str(repo), "plan_sha256": "a" * 64,
                "quarantine": str(quarantine), "originals": originals,
                "unregistered": [item["uuid"] for item in originals],
                "displaced": list(VM.NAMES), "created": [],
            }
            VM.atomic_json(VM.transaction_path(repo), transaction)
            registered = set()
            commands = []

            def fake_run(command, capture=False):
                commands.append(command)
                if command[1] == "register":
                    name = Path(command[2]).stem
                    registered.add(next(item["uuid"] for item in originals if item["name"] == name))
                if command[1:5] == ["list", "--all", "--no-header", "--output"]:
                    return ""
                return ""

            def fake_identity(selector, _home):
                if selector not in registered:
                    raise VM.MaintenanceError("command_failed:prlctl:not found")
                return next(item for item in originals if item["uuid"] == selector)

            with (mock.patch.object(VM, "run", side_effect=fake_run),
                  mock.patch.object(VM, "vm_identity", side_effect=fake_identity)):
                VM.recover_transaction(repo, transaction, os.geteuid(), directories)
            self.assertFalse(VM.transaction_path(repo).exists())
            self.assertEqual(len([command for command in commands if command[1] == "register"]), 3)
            for name in VM.NAMES:
                self.assertTrue((repo / f"vms/{name}.pvm").is_dir())

    def test_recovery_preserves_substituted_created_identity(self):
        created = {
            "name": VM.NAMES[0], "uuid": "{11111111-1111-4111-8111-111111111111}",
            "expected_home": "/tmp/created.pvm", "state": "stopped",
            "bundle_device": 1, "bundle_inode": 2,
        }
        substituted = {**created, "uuid": "{22222222-2222-4222-8222-222222222222}"}
        with mock.patch.object(VM, "vm_identity", return_value=substituted), \
             mock.patch.object(VM, "run") as run:
            with self.assertRaisesRegex(VM.MaintenanceError, "recovery_created_identity_changed"):
                # The path checks precede original restoration, so only a minimal valid directory set is needed.
                with tempfile.TemporaryDirectory() as temporary:
                    repo = Path(temporary)
                    (repo / ".private").mkdir(mode=0o700)
                    directories = VM.maintenance_directories(repo, os.geteuid())
                    quarantine = directories["quarantine"][0] / "q"
                    quarantine.mkdir(mode=0o700)
                    directories["quarantine"] = (
                        directories["quarantine"][0],
                        VM.trusted_directory(directories["quarantine"][0], os.geteuid()),
                    )
                    transaction = {"quarantine": str(quarantine), "created": [created], "originals": []}
                    VM.recover_transaction(repo, transaction, os.geteuid(), directories)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
