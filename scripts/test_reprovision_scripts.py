import unittest
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ReprovisionScriptTests(unittest.TestCase):
    def test_conversation_archive_activation_installs_shared_azure_transport_first(self):
        text = (ROOT / "scripts/activate-conversation-archive.sh").read_text(encoding="utf-8")
        installer = text.index("/tmp/install-azure-shipper.sh")
        credential = text.index("systemd-creds encrypt")
        self.assertLess(installer, credential)
        self.assertIn("/usr/local/libexec/secure-sandbox/azure_shipper.py", text)
        self.assertIn("< /tmp/azure-client-secret", text)
        self.assertIn("systemctl restart conversation-azure-shipper.service", text)

    def test_installer_acquisition_is_canonical_verified_and_cleanup_is_last(self):
        text = (ROOT / "scripts/acquire-ubuntu-installer.sh").read_text(encoding="utf-8")
        self.assertIn("https://cdimage.ubuntu.com/ubuntu/releases/26.04/release/", text)
        self.assertIn("--proto '=https'", text)
        self.assertIn("--continue-at -", text)
        self.assertIn("installer-operation.py\" promote", text)
        self.assertNotIn("/usr/bin/sudo", text)
        self.assertLess(text.index("--use-promoted --path-only"), text.index('rm -f "$artifact"'))
        self.assertLess(text.index("build-autoinstall-installer.sh"), text.index('rm -f "$artifact"'))

    def test_autoinstall_remaster_is_reproducible_and_content_bound(self):
        text = (ROOT / "scripts/build-autoinstall-installer.sh").read_text(encoding="utf-8")
        for required in (
            "-iso_nowtime", "gpt_disk_guid=", "-alter_date_r", "set_to_mtime",
            "promote-autoinstall", "--use-promoted-autoinstall",
        ):
            self.assertIn(required, text)
        self.assertIn("c9978c366c630932758b4fefb251e01725da46929565870e506254653ef95804", text)
        self.assertLess(text.index("expected_iso_sha256"), text.index("promote-autoinstall"))
        self.assertNotIn("/usr/bin/sudo", text)

    def test_creation_verifies_and_attaches_each_role_seed_before_creation(self):
        wrapper = (ROOT / "scripts/create-vms.sh").read_text(encoding="utf-8")
        text = (ROOT / "scripts/vm-maintenance.py").read_text(encoding="utf-8")
        self.assertIn("vm-operation.py\" create", wrapper)
        self.assertNotIn("create --apply", wrapper)
        self.assertLess(text.index("def seed_hashes"), text.index("def create_one"))
        for role in ("gateway", "research", "target"):
            self.assertIn('f"seed_{role}"', text)
        self.assertIn('"--device-add", "cdrom"', text)
        self.assertIn('"--device-bootorder", "cdrom0 cdrom1 hdd0"', text)
        self.assertIn('set_vm(research, "--device-del", "net0")', text)
        self.assertIn('set_vm(target, "--device-del", "net0")', text)
        self.assertIn('for identity in reversed(created)', text)
        self.assertIn('drop_privileges(uid)', text)

    def test_replacement_is_dry_by_default_and_preserves_original_bundles(self):
        wrapper = (ROOT / "scripts/reprovision-vms.sh").read_text(encoding="utf-8")
        client = (ROOT / "scripts/vm-operation.py").read_text(encoding="utf-8")
        text = (ROOT / "scripts/vm-maintenance.py").read_text(encoding="utf-8")
        self.assertIn('vm-operation.py\" reprovision', wrapper)
        self.assertIn('if not args.apply:', client)
        self.assertIn('Dry run only.', client)
        self.assertIn('source.rename(quarantine / source.name)', text)
        self.assertNotIn('--destroy', text)
        self.assertIn('"register", str(destination), "--preserve-uuid"', text)
        self.assertIn('recover_transaction(repo, transaction', text)
        self.assertIn('atomic_json(transaction_path(repo), transaction)', text)

    def test_dependency_provisioning_normalizes_stopped_guests_before_lifecycle_probe(self):
        text = (ROOT / "scripts/provision-fresh-vm-dependencies.sh").read_text(encoding="utf-8")
        gateway = text.index("all_names=(SecureSandbox-Gateway")
        start = text.index('for index in {1..2}; do')
        lifecycle = text.index('run lifecycle-idle')
        self.assertLess(gateway, start)
        self.assertIn('if [[ "$gateway_state" == stopped ]]; then', text[gateway:start])
        self.assertIn('wait_control sandbox-gateway-control', text[gateway:start])
        self.assertLess(start, lifecycle)
        self.assertIn('if [[ "$state" == stopped ]]; then', text[start:lifecycle])
        self.assertIn('wait_control "${hosts[$index]}"', text[start:lifecycle])
        self.assertEqual(text.count("for attempt in {1..60}; do"), 4)
        self.assertIn('contained_dependency_postcondition_timeout:$name', text)
        self.assertIn('vm_uuid_mismatch:$name', text)
        self.assertIn('expected_vm_uuid_duplicate', text)
        self.assertIn('vm_home_invalid:$name', text)
        self.assertIn('unexpected_device_sharing:$name', text)
        self.assertIn('"$control_client" client --ssh-config "$ssh_config" --timeout-seconds 20', text)
        self.assertNotIn('"$deadline" 20 "$control_client"', text)
        self.assertEqual(text.count('"$deadline" 20 ssh'), 2)
        self.assertIn('"$prlctl" start "$gateway_uuid"', text)
        self.assertIn('"$prlctl" set "$vm_id" --device-add net', text)
        self.assertNotIn('"$prlctl" set "$name"', text)

    def test_deadline_helper_terminates_a_hung_process_group(self):
        helper = ROOT / "scripts/run-with-deadline.py"
        started = time.monotonic()
        result = subprocess.run(
            [str(helper), "1", sys.executable, "-c", "import time; time.sleep(30)"],
            check=False, capture_output=True, text=True, timeout=6,
        )
        self.assertEqual(result.returncode, 124)
        self.assertIn("deadline_exceeded", result.stderr)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(
            subprocess.run([str(helper), "2", "/usr/bin/true"], check=False).returncode,
            0,
        )

    def test_deadline_helper_kills_term_ignoring_descendants_after_leader_exits(self):
        helper = ROOT / "scripts/run-with-deadline.py"
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary, "descendant-survived")
            child = (
                "import pathlib,signal,time;"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                "time.sleep(4);"
                f"pathlib.Path({str(marker)!r}).write_text('unsafe')"
            )
            leader = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
                "time.sleep(30)"
            )
            result = subprocess.run(
                [str(helper), "1", sys.executable, "-c", leader],
                check=False, capture_output=True, text=True, timeout=7,
            )
            self.assertEqual(result.returncode, 124)
            time.sleep(2)
            self.assertFalse(marker.exists())

    def test_dependency_provisioning_rejects_apply_time_topology_drift_before_start(self):
        uuids = {
            "SecureSandbox-Gateway": "11111111-1111-4111-8111-111111111111",
            "SecureSandbox-Research": "22222222-2222-4222-8222-222222222222",
            "SecureSandbox-Target": "33333333-3333-4333-8333-333333333333",
        }
        adapters = {
            "SecureSandbox-Gateway": {
                "net0": {"enabled": True, "type": "shared", "iface": None, "card": "virtio"},
                "net1": {"enabled": True, "type": "host", "iface": "control-net", "card": "virtio"},
            },
            "SecureSandbox-Research": {
                "net1": {"enabled": True, "type": "host", "iface": "control-net", "card": "virtio"},
                "net2": {"enabled": True, "type": "host", "iface": "lab-net", "card": "virtio"},
            },
            "SecureSandbox-Target": {
                "net1": {"enabled": True, "type": "host", "iface": "lab-net", "card": "virtio"},
            },
        }
        sharing = {
            "Automatic sharing cameras": "off",
            "Automatic sharing bluetooth": "off",
            "Automatic sharing smart cards": "off",
            "Automatic sharing gamepads": "off",
            "Support USB 3.0": "off",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            inventories = {}
            for name, vm_uuid in uuids.items():
                home = root / "vms" / f"{name}.pvm"
                home.mkdir(parents=True)
                inventories[name] = [{
                    "Name": name,
                    "ID": "{" + vm_uuid + "}",
                    "Home": str(home),
                    "State": "running",
                    "Hardware": adapters[name],
                    "USB and Bluetooth": sharing,
                }]
            drifted = [dict(inventories["SecureSandbox-Research"][0])]
            drifted[0]["Hardware"] = dict(drifted[0]["Hardware"])
            drifted[0]["Hardware"]["net0"] = {
                "enabled": True, "type": "shared", "iface": None, "card": "virtio",
            }
            by_handle = {**inventories, **{uuids[name]: value for name, value in inventories.items()}}
            by_handle[uuids["SecureSandbox-Research"]] = drifted
            starts = root / "starts"
            fake_prlctl = root / "fake-prlctl"
            fake_prlctl.write_text(
                f"#!{sys.executable}\n"
                "import json, pathlib, sys\n"
                f"inventory = {by_handle!r}\n"
                f"starts = pathlib.Path({str(starts)!r})\n"
                "if sys.argv[1] == 'list':\n"
                "    print(json.dumps(inventory[sys.argv[-1]]))\n"
                "    raise SystemExit(0)\n"
                "if sys.argv[1] == 'start':\n"
                "    starts.write_text(starts.read_text() + sys.argv[2] + '\\n' if starts.exists() else sys.argv[2] + '\\n')\n"
                "    raise SystemExit(0)\n"
                "raise SystemExit(90)\n",
                encoding="utf-8",
            )
            fake_prlctl.chmod(0o755)
            control_client = root / "control-client"
            control_client.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            control_client.chmod(0o755)
            deadline = scripts / "run-with-deadline.py"
            deadline.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            deadline.chmod(0o755)
            ssh_config = root / "ssh-config"
            ssh_config.write_text("test\n", encoding="utf-8")
            source = (ROOT / "scripts/provision-fresh-vm-dependencies.sh").read_text(encoding="utf-8")
            source = source.replace(
                'prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"',
                f'prlctl={str(fake_prlctl)!r}',
            ).replace(
                'ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config',
                f'ssh_config={str(ssh_config)!r}',
            ).replace(
                'control_client=/usr/local/libexec/secure-sandbox-host/current/control_client',
                f'control_client={str(control_client)!r}',
            )
            candidate = scripts / "provision-fresh-vm-dependencies.sh"
            candidate.write_text(source, encoding="utf-8")
            candidate.chmod(0o755)
            result = subprocess.run(
                [str(candidate), "--apply",
                 "--gateway-uuid", uuids["SecureSandbox-Gateway"],
                 "--research-uuid", uuids["SecureSandbox-Research"],
                 "--target-uuid", uuids["SecureSandbox-Target"]],
                check=False, capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unexpected_adapter_inventory:SecureSandbox-Research", result.stderr)
            self.assertFalse(starts.exists())

    def test_dependency_recovery_accepts_exact_raw_baseline_with_adapter_metadata(self):
        uuids = {
            "SecureSandbox-Gateway": "11111111-1111-4111-8111-111111111111",
            "SecureSandbox-Research": "22222222-2222-4222-8222-222222222222",
            "SecureSandbox-Target": "33333333-3333-4333-8333-333333333333",
        }
        role_adapters = {
            "SecureSandbox-Gateway": [
                ("net0", "shared", None, "001C42000001"),
                ("net1", "host", "control-net", "001C42000002"),
            ],
            "SecureSandbox-Research": [
                ("net1", "host", "control-net", "001C42000003"),
                ("net2", "host", "lab-net", "001C42000004"),
            ],
            "SecureSandbox-Target": [
                ("net1", "host", "lab-net", "001C42000005"),
            ],
        }
        sharing = {
            "Automatic sharing cameras": "off", "Automatic sharing bluetooth": "off",
            "Automatic sharing smart cards": "off", "Automatic sharing gamepads": "off",
            "Support USB 3.0": "off",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            inventories = {}
            for name, vm_uuid in uuids.items():
                home = root / "vms" / f"{name}.pvm"
                home.mkdir(parents=True)
                hardware = {
                    key: {"enabled": True, "type": kind, "iface": iface, "card": "virtio", "mac": mac}
                    for key, kind, iface, mac in role_adapters[name]
                }
                inventories[name] = [{
                    "Name": name, "ID": "{" + vm_uuid + "}", "Home": str(home),
                    "State": "running", "Hardware": hardware, "USB and Bluetooth": sharing,
                }]
            by_handle = {**inventories, **{uuids[name]: value for name, value in inventories.items()}}
            fake_prlctl = root / "fake-prlctl"
            fake_prlctl.write_text(
                f"#!{sys.executable}\nimport json,sys\ninventory={by_handle!r}\n"
                "assert sys.argv[1] == 'list'\nprint(json.dumps(inventory[sys.argv[-1]]))\n",
                encoding="utf-8",
            )
            fake_prlctl.chmod(0o755)
            control_client = root / "control-client"
            control_client.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            control_client.chmod(0o755)
            deadline = scripts / "run-with-deadline.py"
            deadline.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            deadline.chmod(0o755)
            ssh_config = root / "ssh-config"
            ssh_config.write_text("test\n", encoding="utf-8")
            source = (ROOT / "scripts/provision-fresh-vm-dependencies.sh").read_text(encoding="utf-8")
            source = source.replace(
                'prlctl="/Applications/Parallels Desktop.app/Contents/MacOS/prlctl"', f'prlctl={str(fake_prlctl)!r}',
            ).replace(
                'ssh_config=/usr/local/libexec/secure-sandbox-host/current/ssh_config', f'ssh_config={str(ssh_config)!r}',
            ).replace(
                'control_client=/usr/local/libexec/secure-sandbox-host/current/control_client', f'control_client={str(control_client)!r}',
            )
            candidate = scripts / "provision-fresh-vm-dependencies.sh"
            candidate.write_text(source, encoding="utf-8")
            candidate.chmod(0o755)
            state_dir = root / ".private" / "restoration"
            state_dir.mkdir(parents=True, mode=0o700)
            research = inventories["SecureSandbox-Research"][0]
            transaction = {
                "schema": "secure-sandbox-temporary-adapter-transaction-v2", "stage": "adding",
                "name": "SecureSandbox-Research", "vm_id": uuids["SecureSandbox-Research"],
                "original_state": "running",
                "before_adapters": [{"key": key, "value": value} for key, value in research["Hardware"].items()],
                "net_key": "", "mac": "",
            }
            state_file = state_dir / "temporary-package-provisioning.json"
            state_file.write_text(json.dumps(transaction), encoding="utf-8")
            state_file.chmod(0o600)
            result = subprocess.run([str(candidate)], check=False, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(state_file.exists())

    def test_dependency_provisioning_journals_and_recovers_temporary_adapters(self):
        text = (ROOT / "scripts/provision-fresh-vm-dependencies.sh").read_text(encoding="utf-8")
        self.assertIn('secure-sandbox-temporary-adapter-transaction-v2', text)
        self.assertIn('before_adapters', text)
        self.assertLess(text.index('write_adapter_transaction adding'), text.index('--device-add net --type shared'))
        self.assertIn('temporary_adapter_recovery_ambiguous', text)
        self.assertIn('temporary_adapter_recovery_mac_mismatch', text)
        self.assertIn('if ! recover_adapter_transaction; then', text)
        self.assertLess(
            text.index('recover_adapter_transaction\n\ntypeset -a all_names'),
            text.index('for index in {1..3}; do'),
        )
        self.assertIn('temporary_adapter_recovery_incomplete', text)
        self.assertIn('request_poweroff', text)
        self.assertIn('[[ "$state" == stopped ]] && return 0', text)
        self.assertIn('for poll in {1..30}; do', text)
        self.assertEqual(
            text.count('verify_adapter_removed "$name" "$vm_id" "$before_adapters"'),
            3,
        )
        self.assertNotIn('verify_adapter_removed "$name" "$vm_id" "$before_keys"', text)
        self.assertIn('temporary_adapter_recovery_baseline_changed', text)
        self.assertIn('temporary_adapter_recovery_unexpected_type', text)
        cleanup_start = text.index('"$prlctl" set "$vm_id" --device-del "$net_key"', text.index('provision_one()'))
        self.assertLess(text.index('verify_adapter_removed', cleanup_start),
                        text.index('clear_adapter_transaction', cleanup_start))

    def test_rootless_docker_starts_a_lingering_user_manager_before_setup(self):
        text = (ROOT / "scripts/install-rootless-docker.sh").read_text(encoding="utf-8")
        self.assertLess(text.index('loginctl enable-linger labadmin'), text.index('dockerd-rootless-setuptool.sh'))
        self.assertLess(text.index('systemctl start "user@$uid.service"'), text.index('dockerd-rootless-setuptool.sh'))
        self.assertIn('[[ -S "$run_dir/bus" ]]', text)
        self.assertNotIn('install -d -m 700 -o labadmin -g labadmin "$run_dir"', text)
        self.assertIn('9DC858229FC7DD38854AE2D88D81803C0EBFCD88', text)
        self.assertIn('1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570', text)
        self.assertIn('--homedir "$gpg_home"', text)
        self.assertIn('Package digest mismatch for $package=$version.', text)
        self.assertIn('chown _apt:nogroup "$package_staging"', text)
        self.assertIn('verified_staging="$(mktemp -d', text)
        self.assertIn('install -o root -g root -m 0600 "$deb" "$sealed"', text)
        self.assertIn('sudo -u _apt curl', text)
        self.assertIn('--no-download', text)
        self.assertIn('Unbound or destructive package action refused', text)
        self.assertIn('require_clean_dpkg_state', text)
        self.assertIn('/var/lib/dpkg/triggers/Unincorp', text)
        self.assertIn('/^(Inst|Conf|Remv|Purg) /', text)
        self.assertIn('systemctl disable --now docker.service docker.socket containerd.service', text)
        self.assertNotIn('systemctl disable --now docker.service docker.socket containerd.service || true', text)
        self.assertIn('systemctl mask docker.service docker.socket containerd.service', text)

    def test_installer_media_removal_is_single_vm_and_content_bound(self):
        text = (ROOT / "scripts/remove-installer-media.sh").read_text(encoding="utf-8")
        self.assertIn('[[ $# -eq 1 ]]', text)
        self.assertIn('Unknown managed VM: $vm', text)
        self.assertIn('.Hardware.cdrom0.image == $installer', text)
        self.assertIn('.Hardware.cdrom1.image == $seed', text)
        self.assertIn('.[0].Hardware.cdrom0 == null', text)
        self.assertIn('.[0].Hardware.cdrom1 == null', text)
        self.assertEqual(text.count('info="$("$prlctl" list -a -i -j "$vm")"'), 2)
        self.assertGreaterEqual(text.count('"Automatic sharing gamepads"] == "off"'), 1)
        self.assertIn('"Support USB 3.0"] == "off"', text)
        self.assertNotIn('vms=(SecureSandbox-Gateway SecureSandbox-Research SecureSandbox-Target)', text)

    def test_boundary_evidence_requires_fresh_attributed_canaries(self):
        text = (ROOT / "scripts/verify-boundaries.sh").read_text(encoding="utf-8")
        self.assertIn('sync-lab-time.sh" --check', text)
        self.assertIn('pki_canary_since="$(freshness_cutoff)"', text)
        self.assertIn("systemctl start pki-expiry-check.service", text)
        self.assertIn("--evidence-id '$pki_canary_id'", text)
        self.assertIn('.EventType == \\"pki_expiry_status\\"', text)
        self.assertIn('endswith(\\":\\" + \\$evidence)', text)
        self.assertIn('.TimeGenerated >= \\$since', text)
        self.assertIn('network_canary_since="$(freshness_cutoff)"', text)
        self.assertIn('.RunId == \\"boundary-test\\"', text)
        self.assertIn("secrets.randbits(39)", text)
        self.assertIn('.Destination == \\$destination', text)
        self.assertIn('.DestinationPort == \\$port', text)
        self.assertEqual(text.count('for _ in {1..20}; do'), 2)
        self.assertIn('client --timeout-seconds 75 --ssh-config', text)
        self.assertNotIn('network_evidence_ready=', text)
        self.assertIn('timedelta(seconds=6)', text)
        self.assertIn('log_format[[:space:]]*=', text)
        self.assertEqual(text.count("control receipt ledger retains acceptance headroom"), 3)
        self.assertNotIn('check "Unrouted egress attempts reached the metadata spool"', text)
        match = re.search(r'<<< "\$\((python3 -c .*?)\)"', text[text.index("network_canary_since="):])
        self.assertIsNotNone(match)
        generated = subprocess.run(
            ["zsh", "-c", match.group(1)], check=False, capture_output=True, text=True,
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)
        destination, port = generated.stdout.strip().split()
        self.assertRegex(destination, r"^198\.1[89]\.[0-9]{1,3}\.[0-9]{1,3}$")
        self.assertTrue(16384 <= int(port) <= 49151)

    def test_execution_approval_ddd_synchronizes_clocks_before_boundary_freshness(self):
        text = (ROOT / "scripts/deploy-execution-approval-ddd.sh").read_text(
            encoding="utf-8"
        )
        archival = text.index("run control-receipts-archive")
        synchronization = text.index("scripts/sync-lab-time.sh --apply")
        verification = text.index("scripts/verify-boundaries.sh")
        self.assertLess(archival, verification)
        self.assertLess(synchronization, verification)

    def test_auditd_configuration_uses_transactional_runtime_validation(self):
        text = (ROOT / "scripts/install-research-auditd.sh").read_text(encoding="utf-8")
        self.assertNotIn('/sbin/auditd -t', text)
        self.assertIn('auditd rejected the ENRICHED configuration; restoring the prior file', text)
        self.assertIn('Failed to restore the prior auditd configuration; backup retained at $audit_config_backup.', text)
        self.assertLess(text.index('audit_config_backup='), text.index('/usr/sbin/service auditd restart'))
        self.assertIn("dpkg-query -W -f='${db:Status-Status}' age", text)
        self.assertIn('dpkg -V age', text)
        self.assertIn('51b8f2008cb57eddd57ce8038dbdd9409ea9b6ee08459d35c3752e8c87dca7cd', text)
        self.assertIn('297513b0e4f8eed57731f253537e2b918337ee11fc05fc83d627725656b4e284', text)
        self.assertIn('chown _apt:nogroup "$package_staging"', text)
        self.assertIn('install -o root -g root -m 0600 "$deb" "$sealed"', text)
        self.assertIn('--no-download', text)
        self.assertIn('require_clean_dpkg_state', text)
        self.assertIn('/^(Inst|Conf|Remv|Purg) /', text)

    def test_boundary_acceptance_proves_adapter_and_rootful_daemon_absence(self):
        text = (ROOT / "scripts/verify-boundaries.sh").read_text(encoding="utf-8")
        self.assertIn('has exactly its permitted adapter topology', text)
        self.assertIn('Target rootful Docker and containerd are masked, inactive, and socketless', text)
        self.assertIn('Research restoration packages match the source-bound identities', text)
        self.assertIn('Target Docker repository key bytes match the source-bound identity', text)
        self.assertIn('Target restoration packages match the source-bound identities', text)

    def test_disposable_execution_cleanup_preserves_the_configured_full_image_id(self):
        text = (ROOT / "scripts/install-disposable-execution-target.sh").read_text(encoding="utf-8")
        self.assertIn('image ls -q --no-trunc', text)
        self.assertIn('resolved_old=', text)
        self.assertIn('[[ "$resolved_old" == "$image_id" ]] && continue', text)
        self.assertIn('Configured runtime image disappeared during cleanup.', text)

    def test_bootstrap_pki_is_resumable_without_replacing_private_keys(self):
        foundation = (ROOT / "scripts/deploy-foundation.sh").read_text(encoding="utf-8")
        installer = (ROOT / "scripts/install-bootstrap-pki.sh").read_text(encoding="utf-8")
        gateway = (ROOT / "scripts/init-gateway-broker-pki.sh").read_text(encoding="utf-8")
        self.assertNotIn("bootstrap_pki_partial_state", foundation)
        self.assertEqual(foundation.count("install-bootstrap-pki.sh gateway-init"), 1)
        self.assertEqual(foundation.count("install-bootstrap-pki.sh research-create"), 1)
        self.assertIn("research-validate", foundation)
        self.assertIn("publish_csr", installer)
        self.assertIn("same_public_key", installer)
        self.assertIn('$exchange/installed-ca.crt', installer)
        self.assertIn('pki-exchange/bootstrap/installed-ca.crt', foundation)
        self.assertNotIn('sandbox-research-admin:/etc/secure-sandbox/relay/ca.crt', foundation)
        self.assertEqual(foundation.count('install_control_plane sandbox-'), 3)
        self.assertLess(
            foundation.index('install_control_plane sandbox-research-control research'),
            foundation.index('install-bootstrap-pki.sh gateway-init'),
        )
        self.assertIn("if [[ ! -e \"$pki_dir/ca.key\" ]]", gateway)
        self.assertIn("Gateway CA certificate does not match its existing key", gateway)

    def test_review_bundle_install_and_rollback_represent_absent_workspace(self):
        install = (ROOT / "scripts/install-review-bundle-verifier.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "research/rollback_review_bundle_verifier.sh").read_text(encoding="utf-8")
        marker = "review-bundles.workspace.absent"
        self.assertIn(marker, install)
        self.assertIn(marker, rollback)
        self.assertIn('elif [[ ! -f "$backup/mount.was-active" ]]', rollback)
        self.assertIn('/usr/bin/nsenter --mount=/proc/1/ns/mnt --', install)
        self.assertIn('/usr/bin/nsenter --mount=/proc/1/ns/mnt --', rollback)
        self.assertIn('host_mount_namespace /usr/bin/mountpoint -q "$view"', install)
        self.assertIn('host_mount_namespace /usr/bin/findmnt -n -o OPTIONS', install)
        self.assertIn('remove_unmounted_view_if_present', rollback)
        self.assertIn('if host_mount_namespace /usr/bin/test -e "$view"; then', rollback)

    def test_findings_service_group_is_created_before_early_service_start(self):
        receipts = (ROOT / "scripts/install-evidence-receipts.sh").read_text(encoding="utf-8")
        findings = (ROOT / "scripts/install-findings-adjudication.sh").read_text(encoding="utf-8")
        unit = (ROOT / "research/findings-broker.service").read_text(encoding="utf-8")
        self.assertLess(
            receipts.index("groupadd --system findings-broker"),
            receipts.index("systemctl restart corpus-broker.service"),
        )
        self.assertIn("--gid findings-broker findings-broker", receipts)
        self.assertIn("usermod -a -G findings-broker findings-broker", receipts)
        self.assertIn("Service group is untrusted: findings-broker", receipts)
        self.assertIn('"$findings_members" == findings-broker', receipts)
        self.assertIn('"$findings_primary_gid" == "$findings_gid"', receipts)
        self.assertIn("groupadd --system findings-broker", findings)
        self.assertIn("usermod -a -G findings-broker findings-broker", findings)
        self.assertIn("Service account is untrusted: findings-broker", findings)
        self.assertIn('"$findings_members" == findings-broker', findings)
        self.assertIn("SupplementaryGroups=evidence-receipts findings-broker", unit)

    def test_findings_install_is_transactional_and_evidence_rollback_restores_service_state(self):
        findings = (ROOT / "scripts/install-findings-adjudication.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "research/rollback_evidence_receipts.sh").read_text(encoding="utf-8")
        privileged_install = 'install -o root -g root -m 755 "$update_policy_hash"'
        self.assertLess(findings.index('[[ "$(id -u)" -eq 0 ]]'), findings.index(privileged_install))
        self.assertLess(findings.index('for source in "$broker"'), findings.index(privileged_install))
        self.assertLess(findings.index('trap rollback_on_error ERR'), findings.index(privileged_install))
        self.assertIn('/usr/local/libexec/secure-sandbox/update-policy-hash.sh', findings)
        self.assertIn('restore update-policy-hash.sh', (ROOT / "research/rollback_findings_adjudication.sh").read_text(encoding="utf-8"))
        self.assertIn('service-state-recorded', (ROOT / "scripts/install-evidence-receipts.sh").read_text(encoding="utf-8"))
        self.assertIn('restore_service_state()', rollback)
        self.assertIn('if [[ ! -f "$unit" ]]; then', rollback)
        self.assertIn('if [[ -f "$backup/$service.was-active" ]]', rollback)


if __name__ == "__main__":
    unittest.main()
