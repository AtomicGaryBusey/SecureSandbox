#!/bin/zsh
set -u

root_dir="${0:A:h:h}"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
failures=0
approved_broker_credential_dropin_hash="$(shasum -a 256 "$root_dir/gateway/model-broker-production.conf" | awk '{print $1}')"
approved_lease_manager_hash="$(shasum -a 256 "$root_dir/gateway/run_lease.py" | awk '{print $1}')"
approved_lease_profiles_hash="$(shasum -a 256 "$root_dir/gateway/run-lease-profiles.json" | awk '{print $1}')"
approved_watchdog_hash="$(shasum -a 256 "$root_dir/research/run_lease_watchdog.py" | awk '{print $1}')"
approved_run_supervisor_hash="$(shasum -a 256 "$root_dir/research/run_lease_process.py" | awk '{print $1}')"
approved_run_supervisor_sudoers_hash="$(shasum -a 256 "$root_dir/research/run-lease-supervisor.sudoers" | awk '{print $1}')"
approved_watchdog_unit_hash="$(shasum -a 256 "$root_dir/research/run-lease-watchdog.service" | awk '{print $1}')"
approved_research_install_recovery_hash="$(shasum -a 256 "$root_dir/research/run-leases-install-recovery.sh" | awk '{print $1}')"
approved_research_install_recovery_unit_hash="$(shasum -a 256 "$root_dir/research/run-leases-install-recovery.service" | awk '{print $1}')"
approved_gateway_install_recovery_hash="$(shasum -a 256 "$root_dir/gateway/run-leases-install-recovery.sh" | awk '{print $1}')"
approved_gateway_install_recovery_unit_hash="$(shasum -a 256 "$root_dir/gateway/run-leases-install-recovery.service" | awk '{print $1}')"
approved_agent_ssh_entry_hash="$(shasum -a 256 "$root_dir/research/research_agent_ssh_entry.py" | awk '{print $1}')"
approved_agent_sshd_policy_hash="$(shasum -a 256 "$root_dir/research/sshd-agent-fixed-command.conf" | awk '{print $1}')"
approved_persona_hash="$(shasum -a 256 "$root_dir/research/glm-persona.md" | awk '{print $1}')"
approved_memory_broker_hash="$(shasum -a 256 "$root_dir/research/memory_proposal.py" | awk '{print $1}')"
approved_memory_mcp_hash="$(shasum -a 256 "$root_dir/research/memory_proposal_mcp.py" | awk '{print $1}')"
approved_memory_unit_hash="$(shasum -a 256 "$root_dir/research/memory-proposal.service" | awk '{print $1}')"
approved_findings_broker_hash="$(shasum -a 256 "$root_dir/research/findings_broker.py" | awk '{print $1}')"
approved_findings_mcp_hash="$(shasum -a 256 "$root_dir/research/findings_mcp.py" | awk '{print $1}')"
approved_finding_admin_hash="$(shasum -a 256 "$root_dir/research/finding_admin.py" | awk '{print $1}')"
approved_findings_unit_hash="$(shasum -a 256 "$root_dir/research/findings-broker.service" | awk '{print $1}')"
approved_receipts_hash="$(shasum -a 256 "$root_dir/research/evidence_receipts.py" | awk '{print $1}')"
approved_bounded_server_hash="$(shasum -a 256 "$root_dir/research/bounded_unix_server.py" | awk '{print $1}')"
approved_bounded_http_hash="$(shasum -a 256 "$root_dir/shared/bounded_http.py" | awk '{print $1}')"
approved_privileged_workflow_hash="$(shasum -a 256 "$root_dir/shared/privileged_workflow.py" | awk '{print $1}')"
approved_shared_init_hash="$(shasum -a 256 "$root_dir/shared/__init__.py" | awk '{print $1}')"
approved_corpus_broker_hash="$(shasum -a 256 "$root_dir/research/corpus_broker.py" | awk '{print $1}')"
approved_corpus_broker_unit_hash="$(shasum -a 256 "$root_dir/research/corpus-broker.service" | awk '{print $1}')"
approved_corpus_mcp_hash="$(shasum -a 256 "$root_dir/research/corpus_intelligence_mcp.py" | awk '{print $1}')"
approved_execution_broker_hash="$(shasum -a 256 "$root_dir/research/execution_broker.py" | awk '{print $1}')"
approved_execution_unit_hash="$(shasum -a 256 "$root_dir/research/execution-broker.service" | awk '{print $1}')"
approved_pki_lifecycle_hash="$(shasum -a 256 "$root_dir/scripts/pki_lifecycle.py" | awk '{print $1}')"
approved_pki_helpers_hash="$(shasum -a 256 "$root_dir/scripts/pki_guest_helpers.py" | awk '{print $1}')"
approved_gateway_pki_hash="$(shasum -a 256 "$root_dir/gateway/pki_generation.py" | awk '{print $1}')"
approved_research_pki_hash="$(shasum -a 256 "$root_dir/research/pki_generation.py" | awk '{print $1}')"
approved_pki_expiry_service_hash="$(shasum -a 256 "$root_dir/scripts/pki-expiry-check.service" | awk '{print $1}')"
approved_pki_expiry_timer_hash="$(shasum -a 256 "$root_dir/scripts/pki-expiry-check.timer" | awk '{print $1}')"
approved_control_dispatcher_hash="$(shasum -a 256 "$root_dir/scripts/privileged_control.py" | awk '{print $1}')"
approved_control_entry_hash="$(shasum -a 256 "$root_dir/scripts/privileged_control_entry.py" | awk '{print $1}')"
approved_control_sshd_hash="$(shasum -a 256 "$root_dir/config/sshd-control.conf" | awk '{print $1}')"
approved_control_sudoers_hash="$(shasum -a 256 "$root_dir/config/privileged-control.sudoers" | awk '{print $1}')"
approved_control_key_hash="$(printf '%s\n' "$(cat "$root_dir/runs/control_key.pub")" | shasum -a 256 | awk '{print $1}')"

pass() { print "PASS  $1"; }
fail() { print "FAIL  $1"; failures=$((failures + 1)); }
gate() { print "GATE  $1"; }
freshness_cutoff() {
  # Guest clocks are independently required to stay within five seconds of
  # the host. One additional second covers whole-second timestamp truncation.
  python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(seconds=6)).strftime("%Y-%m-%dT%H:%M:%SZ"))'
}
check() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}
check "Host Claude controller is an immutable release matching approved source" \
  python3 "$root_dir/scripts/secure_enclave_ddd_support.py" \
    verify-postactivation-host-release --repo "$root_dir" \
    --install-root /usr/local/libexec/secure-sandbox-host \
    --launcher /usr/local/bin/secure-sandbox-claude
check "Host execution-approval authority has a protected signing identity" \
  /usr/local/libexec/secure-sandbox-host/current/authorization_broker execution-approval-public-key
check "Gateway, Research, and Target clocks are within 5 seconds of the host" \
  "$root_dir/scripts/sync-lab-time.sh" --check
remote() { ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 "$@"; }
control_client() {
  "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" "$@"
}
invalid_deployment_request() {
  python3 - <<'PY'
import hashlib, io, json, struct, sys, tarfile, uuid
data = b"#!/bin/bash\nexit 99\n"
archive_bytes = io.BytesIO()
with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
    member = tarfile.TarInfo("files/install-integrity-probe.sh")
    member.size = len(data)
    member.mode = 0o700
    archive.addfile(member, io.BytesIO(data))
payload = archive_bytes.getvalue()
request = {
    "schema": "secure-sandbox-privileged-control-request-v1",
    "request_id": str(uuid.uuid4()),
    "kind": "deploy",
    "installer": "install-integrity-probe.sh",
    "args": [],
    "files": [{"path": "install-integrity-probe.sh", "size": len(data), "sha256": "0" * 64, "mode": 0o700}],
    "payload_length": len(payload),
}
header = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii")
sys.stdout.buffer.write(struct.pack(">I", len(header)) + header + payload)
PY
}

verify_control_plane() {
  local admin_host="$1"
  local control_host="$2"
  local role="$3"
  local wrong_operation="$4"
  local error_file status_output
  local inventory_command="test \"\$(sha256sum /usr/local/libexec/secure-sandbox/privileged_control.py | awk '{print \$1}')\" = '$approved_control_dispatcher_hash' \
    && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/privileged_control_entry.py | awk '{print \$1}')\" = '$approved_control_entry_hash' \
    && test \"\$(sha256sum /etc/ssh/sshd_config.d/15-secure-sandbox-control.conf | awk '{print \$1}')\" = '$approved_control_sshd_hash' \
    && test \"\$(sha256sum /etc/sudoers.d/secure-sandbox-control | awk '{print \$1}')\" = '$approved_control_sudoers_hash' \
    && test \"\$(sha256sum /etc/ssh/authorized_keys/securectl | awk '{print \$1}')\" = '$approved_control_key_hash' \
    && test \"\$(cat /etc/secure-sandbox/control-role)\" = '$role' \
    && test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/privileged_control.py)\" = 'root:root:755' \
    && test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/privileged_control_entry.py)\" = 'root:root:755' \
    && test \"\$(stat -c '%U:%G:%a' /etc/ssh/sshd_config.d/15-secure-sandbox-control.conf)\" = 'root:root:644' \
    && test \"\$(stat -c '%U:%G:%a' /etc/sudoers.d/secure-sandbox-control)\" = 'root:root:444' \
    && test \"\$(stat -c '%U:%G:%a' /etc/ssh/authorized_keys/securectl)\" = 'root:root:644' \
    && test \"\$(stat -c '%U:%G:%a' /etc/secure-sandbox/control-role)\" = 'root:root:644' \
    && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/control)\" = 'root:root:700' \
    && test \"\$(stat -c '%U:%G:%a' /var/empty/securectl)\" = 'root:root:755'"
  check "$role control files independently match approved bytes and ownership" \
    remote "$admin_host" "$inventory_command"
  check "$role effective sshd policy forces the control entry and disables forwarding" \
    zsh -c '"$1" client --ssh-config "$2" "$3" run control-self-check 2>/dev/null | jq -e '\''
      .status == "verified"
      and .sshd.forcecommand == "/usr/local/libexec/secure-sandbox/privileged_control_entry.py"
      and .sshd.authenticationmethods == "publickey"
      and .sshd.passwordauthentication == "no"
      and .sshd.kbdinteractiveauthentication == "no"
      and .sshd.disableforwarding == "yes"
      and .sshd.permittty == "no"
      and .sshd.permituserrc == "no"
    '\'' >/dev/null' _ /usr/local/libexec/secure-sandbox-host/current/control_client "$ssh_config" "$control_host"
  check "$role labadmin has no local dispatcher sudo transition" \
    remote "$admin_host" "! sudo -n -- /usr/local/libexec/secure-sandbox/privileged_control.py dispatch </dev/null"
  error_file="$(mktemp "${TMPDIR:-/tmp}/secure-sandbox-control-negative.XXXXXX")" || return
  if remote "$control_host" not-request </dev/null 2>"$error_file"; then
    fail "$role forced command rejects alternate SSH commands"
  elif grep -q 'control_request_required' "$error_file"; then
    pass "$role forced command rejects alternate SSH commands"
  else
    fail "$role forced command rejects alternate SSH commands with the expected error"
  fi
  if remote "$control_host" request </dev/null 2>"$error_file"; then
    fail "$role malformed protocol is rejected"
  elif grep -q 'request_truncated' "$error_file"; then
    pass "$role malformed protocol is rejected"
  else
    fail "$role malformed protocol returns the expected error"
  fi
  if invalid_deployment_request | remote "$control_host" request 2>"$error_file"; then
    fail "$role deployment accepts a digest-mismatched payload"
  elif grep -q 'bundle_digest_mismatch' "$error_file"; then
    pass "$role deployment rejects a digest-mismatched payload before execution"
  else
    fail "$role deployment integrity rejection returns the expected error"
  fi
  rm -f -- "$error_file"
  status_output="$(control_client "$control_host" run control-status 2>/dev/null)"
  if print -r -- "$status_output" | jq -e --arg role "$role" '.schema == "secure-sandbox-privileged-control-status-v1" and .role == $role' >/dev/null; then
    pass "$role control identity reports the pinned role"
  else
    fail "$role control identity reports the pinned role"
  fi
  if control_client "$control_host" run "$wrong_operation" >/dev/null 2>&1; then
    fail "$role rejects a valid operation from another role"
  else
    pass "$role rejects a valid operation from another role"
  fi
  if control_client "$control_host" run control-audit-tail 2>/dev/null | grep -q 'request_truncated'; then
    pass "$role root-only audit records malformed requests"
  else
    fail "$role root-only audit records malformed requests"
  fi
}
sudo_remote() {
  local item="$1"
  local host="$2"
  local command="$3"
  local control_host installer
  case "$host" in
    sandbox-gateway) control_host=sandbox-gateway-control ;;
    sandbox-research-admin) control_host=sandbox-research-control ;;
    sandbox-target-admin) control_host=sandbox-target-control ;;
    *) print -u2 "unknown privileged audit host: $host"; return 64 ;;
  esac
  installer="$(mktemp "${TMPDIR:-/tmp}/secure-sandbox-boundary-audit.XXXXXX")" || return
  {
    print '#!/bin/bash'
    print 'set -euo pipefail'
    print -r -- "$command"
  } > "$installer"
  chmod 700 "$installer"
  local command_status=0
  "/usr/local/libexec/secure-sandbox-host/current/control_client" client --timeout-seconds 75 --ssh-config "$ssh_config" "$control_host" \
    deploy install-boundary-audit.sh --file "$installer:install-boundary-audit.sh" \
    || command_status=$?
  rm -f -- "$installer"
  return "$command_status"
}
agent_remote() {
  local command="$1"
  local encoded
  encoded="$(printf %s "$command" | base64 | tr -d '\n')"
  sudo_remote SecureSandbox-Research sandbox-research-admin \
    "printf %s $encoded | base64 -d | runuser -u agent -- /bin/bash"
}

execution_approval_authorities_match() {
  local identity schema generation epoch algorithm public_hash
  identity="$(/usr/local/libexec/secure-sandbox-host/current/authorization_broker execution-approval-public-key)" || return
  schema="$(jq -r .schema <<<"$identity")" || return
  if [[ "$schema" == secure-sandbox-execution-approval-key-v1 ]]; then
    sudo_remote SecureSandbox-Research sandbox-research-admin \
      "test \"\$(jq -r .schema /etc/secure-sandbox/execution-broker.json)\" = secure-sandbox-execution-broker-v2 && test ! -e /etc/secure-sandbox/execution-approval-floor.json"
    return
  fi
  [[ "$schema" == secure-sandbox-execution-approval-key-v2 ]] || return 1
  generation="$(jq -er .generation_id <<<"$identity")" || return
  epoch="$(jq -er .generation_epoch <<<"$identity")" || return
  algorithm="$(jq -er .algorithm <<<"$identity")" || return
  public_hash="$(jq -er .public_key_sha256 <<<"$identity")" || return
  sudo_remote SecureSandbox-Research sandbox-research-admin \
    "test \"\$(stat -c %U:%G:%a /etc/secure-sandbox/execution-approval-floor.json)\" = root:execution-broker:640 && jq -e --arg generation '$generation' --argjson epoch '$epoch' --arg algorithm '$algorithm' --arg public_hash '$public_hash' '.schema == \"secure-sandbox-execution-broker-v3\" and .approval.mode == \"active-v2\" and .approval.generation_id == \$generation and .approval.generation_epoch == \$epoch and .approval.minimum_protocol == 2 and .approval.minimum_epoch == \$epoch and .approval.algorithm == \$algorithm and .approval.public_key_sha256 == \$public_hash' /etc/secure-sandbox/execution-broker.json >/dev/null && jq -e --arg generation '$generation' --argjson epoch '$epoch' --arg algorithm '$algorithm' --arg public_hash '$public_hash' '.schema == \"secure-sandbox-execution-approval-floor-v2\" and .minimum_protocol == 2 and .minimum_epoch == \$epoch and .generation_id == \$generation and .algorithm == \$algorithm and .public_key_sha256 == \$public_hash' /etc/secure-sandbox/execution-approval-floor.json >/dev/null"
}

boundary_marker_active=0
clear_boundary_marker() {
  if (( boundary_marker_active )); then
    sudo_remote SecureSandbox-Research sandbox-research-admin \
      "/usr/local/libexec/secure-sandbox/manage_run_id.py clear-evidence boundary-test" >/dev/null 2>&1 || true
  fi
}
trap clear_boundary_marker EXIT HUP INT TERM

for vm in SecureSandbox-Gateway SecureSandbox-Research SecureSandbox-Target; do
  info="$(prlctl list -a -i "$vm" 2>/dev/null)"
  info_json="$(prlctl list -a -i -j "$vm" 2>/dev/null)"
  [[ "$info" == *"State: running"* ]] && pass "$vm is running" || fail "$vm is running"
  [[ "$info" == *"EFI Secure boot: on"* ]] && pass "$vm Secure Boot" || fail "$vm Secure Boot"
  [[ "$info" == *"GuestTools: state=not_installed"* ]] && pass "$vm has no Parallels Tools" || fail "$vm has no Parallels Tools"
  [[ "$info" == *"Host Shared Folders: (-)"* && "$info" == *"Shared clipboard mode: off"* ]] && pass "$vm host sharing disabled" || fail "$vm host sharing disabled"
  if jq -e '.[0].Hardware | [keys[] | select(startswith("cdrom"))] | length == 0' <<<"$info_json" >/dev/null; then
    pass "$vm has no virtual optical media device"
  else
    fail "$vm has no virtual optical media device"
  fi
  if jq -e '.[0]["USB and Bluetooth"] as $usb
      | $usb["Automatic sharing cameras"] == "off"
      and $usb["Automatic sharing bluetooth"] == "off"
      and $usb["Automatic sharing smart cards"] == "off"
      and $usb["Automatic sharing gamepads"] == "off"
      and $usb["Support USB 3.0"] == "off"' <<<"$info_json" >/dev/null; then
    pass "$vm automatic device sharing disabled"
  else
    fail "$vm automatic device sharing disabled"
  fi
  if [[ "$vm" == SecureSandbox-Gateway ]]; then
    expected_adapters='[{"key":"net0","enabled":true,"type":"shared","iface":null,"card":"virtio"},{"key":"net1","enabled":true,"type":"host","iface":"control-net","card":"virtio"}]'
  elif [[ "$vm" == SecureSandbox-Research ]]; then
    expected_adapters='[{"key":"net1","enabled":true,"type":"host","iface":"control-net","card":"virtio"},{"key":"net2","enabled":true,"type":"host","iface":"lab-net","card":"virtio"}]'
  else
    expected_adapters='[{"key":"net1","enabled":true,"type":"host","iface":"lab-net","card":"virtio"}]'
  fi
  if jq -e --argjson expected "$expected_adapters" '
      ([.[0].Hardware | to_entries[] | select(.key | startswith("net"))
        | {key,enabled:.value.enabled,type:.value.type,iface:(.value.iface // null),card:.value.card}]
       | sort_by(.key)) == $expected' \
      <<<"$info_json" >/dev/null; then
    pass "$vm has exactly its permitted adapter topology"
  else
    fail "$vm has exactly its permitted adapter topology"
  fi
done

check "Gateway control receipt ledger retains acceptance headroom" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "count=\$(find /var/lib/secure-sandbox/control/receipts -mindepth 1 -maxdepth 1 -type f | wc -l); test \"\$count\" -lt 3500"
check "Research control receipt ledger retains acceptance headroom" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "count=\$(find /var/lib/secure-sandbox/control/receipts -mindepth 1 -maxdepth 1 -type f | wc -l); test \"\$count\" -lt 3500"
check "Target control receipt ledger retains acceptance headroom" sudo_remote SecureSandbox-Target sandbox-target-admin \
  "count=\$(find /var/lib/secure-sandbox/control/receipts -mindepth 1 -maxdepth 1 -type f | wc -l); test \"\$count\" -lt 3500"

verify_control_plane sandbox-gateway sandbox-gateway-control gateway session-list
verify_control_plane sandbox-research-admin sandbox-research-control research source-plan
verify_control_plane sandbox-target-admin sandbox-target-control target pki-verify

if sudo_remote SecureSandbox-Research sandbox-research-admin \
    "/usr/local/libexec/secure-sandbox/manage_run_id.py set-evidence boundary-test" \
    >/dev/null 2>&1; then
  boundary_marker_active=1
  pass "boundary verification evidence is explicitly attributed without granting admission"
else
  fail "boundary verification evidence is explicitly attributed without granting admission"
fi

check "custom Parallels networks have no host adapter, DHCP, DHCPv6, or NAT" \
  python3 "$root_dir/scripts/verify-parallels-networks.py"
check "Research has no IPv4 default route" remote sandbox-research-admin "test -z \"\$(ip -4 route show default)\""
check "Research IPv6 is disabled" remote sandbox-research-admin "test \"\$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)\" = 1"
check "Target has no IPv4 default route" remote sandbox-target-admin "test -z \"\$(ip -4 route show default)\""
check "Target IPv6 is disabled" remote sandbox-target-admin "test \"\$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)\" = 1"
check "Target rootless Docker security profile is active" remote sandbox-target-admin \
  "systemctl --user is-active --quiet docker && DOCKER_HOST=unix:///run/user/1000/docker.sock docker info --format '{{json .SecurityOptions}}' | grep -q '\"name=rootless\"' && DOCKER_HOST=unix:///run/user/1000/docker.sock docker info --format '{{json .SecurityOptions}}' | grep -q '\"name=no-new-privileges\"'"
check "Target rootful Docker and containerd are masked, inactive, and socketless" \
  sudo_remote SecureSandbox-Target sandbox-target-admin \
  "for unit in docker.service docker.socket containerd.service; do test \"\$(systemctl is-enabled \"\$unit\")\" = masked && ! systemctl is-active --quiet \"\$unit\" || exit 1; done; test ! -e /var/run/docker.sock"
check "Research restoration packages match the source-bound identities" \
  sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(dpkg-query -W -f='\${Version}' age)\" = 1.2.1-1build1 && test \"\$(dpkg-query -W -f='\${Version}' auditd)\" = 1:4.1.2-1ubuntu0.1 && test -z \"\$(dpkg -V age)\" && test -z \"\$(dpkg -V auditd | grep -v ' /etc/audit/auditd.conf\$' || true)\""
check "Target Docker repository key bytes match the source-bound identity" \
  sudo_remote SecureSandbox-Target sandbox-target-admin \
  "test \"\$(sha256sum /etc/apt/keyrings/docker.asc | cut -d' ' -f1)\" = 1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570"
check "Target restoration packages match the source-bound identities" \
  sudo_remote SecureSandbox-Target sandbox-target-admin \
  "test \"\$(dpkg-query -W -f='\${Version}' ca-certificates)\" = 20260816ubuntu0.26.04.1 && test \"\$(dpkg-query -W -f='\${Version}' curl)\" = 8.18.0-1ubuntu2.8 && test \"\$(dpkg-query -W -f='\${Version}' uidmap)\" = 1:4.17.4-2ubuntu3 && test \"\$(dpkg-query -W -f='\${Version}' slirp4netns)\" = 1.3.3-1 && test \"\$(dpkg-query -W -f='\${Version}' fuse-overlayfs)\" = 1.14-1build2 && test \"\$(dpkg-query -W -f='\${Version}' containerd.io)\" = 2.4.2-3~ubuntu.26.04~resolute && test \"\$(dpkg-query -W -f='\${Version}' docker-ce)\" = 5:29.9.2-1~ubuntu.26.04~resolute && test \"\$(dpkg-query -W -f='\${Version}' docker-ce-cli)\" = 5:29.9.2-1~ubuntu.26.04~resolute && test \"\$(dpkg-query -W -f='\${Version}' docker-ce-rootless-extras)\" = 5:29.9.2-1~ubuntu.26.04~resolute && test \"\$(dpkg-query -W -f='\${Version}' docker-buildx-plugin)\" = 0.38.1-1~ubuntu.26.04~resolute && test \"\$(dpkg-query -W -f='\${Version}' docker-compose-plugin)\" = 5.6.1-1~ubuntu.26.04~resolute && test -z \"\$(dpkg -V containerd.io docker-ce docker-ce-cli docker-ce-rootless-extras docker-buildx-plugin docker-compose-plugin)\""
check "Research public TCP egress is blocked" remote sandbox-research-admin "! timeout 2 bash -c '</dev/tcp/8.8.8.8/443'"
check "Research metadata endpoint is blocked" remote sandbox-research-admin "! timeout 2 bash -c '</dev/tcp/169.254.169.254/80'"
check "Research home-LAN probe is blocked" remote sandbox-research-admin "! timeout 2 bash -c '</dev/tcp/192.168.1.1/80'"
check "Target cannot initiate toward Research" remote sandbox-target-admin "! timeout 2 bash -c '</dev/tcp/172.30.20.1/22'"
check "Research firewall has no agent path to Target SSH" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "agent_uid=\$(id -u agent); ! nft list chain inet filter output | grep -E \"meta skuid \$agent_uid.*172\\.30\\.20\\.2.*tcp dport 22.*accept\""
check "Research firewall admits only execution-broker to Target service" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "agent_uid=\$(id -u agent); broker_uid=\$(id -u execution-broker); ! nft list chain inet filter output | grep -E \"meta skuid \$agent_uid.*172\\.30\\.20\\.2.*tcp dport 8080.*accept\" && nft list chain inet filter output | grep -E \"meta skuid \$broker_uid.*172\\.30\\.20\\.2.*tcp dport 8080.*accept\""
check "Research agent has no noninteractive sudo" agent_remote "! sudo -n true"
check "Research agent cannot read relay private key" agent_remote "! test -r /etc/secure-sandbox/relay/client.key"
check "Research agent cannot read telemetry private key" agent_remote "! test -r /etc/secure-sandbox/telemetry/client.key"
check "Research agent cannot read conversation transport private key" agent_remote "! test -r /etc/secure-sandbox/conversation-transport/client.key"
check "Claude Code pinned binary is installed" remote sandbox-research-admin "test \"\$(claude --version)\" = '2.1.300 (Claude Code)'"
check "Research cannot call broker without its relay mTLS identity" remote sandbox-research-admin \
  "! curl -kfsS --max-time 3 https://172.30.10.1:8443/healthz"
check "Relay-to-broker mTLS health path works" remote sandbox-research-admin \
  "curl -fsS --max-time 3 http://127.0.0.1:18080/healthz | grep -q '\"status\":\"ok\"'"
check "Relay accepts only the exact beta=true compatibility marker" remote sandbox-research-admin \
  "test \"\$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -H 'Content-Type: application/json' --data '{}' 'http://127.0.0.1:18080/v1/messages?beta=true')\" = 403 && test \"\$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -H 'Content-Type: application/json' --data '{}' 'http://127.0.0.1:18080/v1/messages?beta=false')\" = 404"
check "Gateway local enforcement services are active" remote sandbox-gateway "systemctl is-active --quiet model-broker telemetry-receiver local-telemetry-exporter conversation-receiver"
check "Gateway local HTTP brokers use the approved bounded framing runtime" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "sha256sum /usr/local/libexec/secure-sandbox/shared/__init__.py | grep -q ^$approved_shared_init_hash && sha256sum /usr/local/libexec/secure-sandbox/shared/bounded_http.py | grep -q ^$approved_bounded_http_hash && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/shared/__init__.py)\" = root:root:644 && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/shared/bounded_http.py)\" = root:root:755"
broker_mode="$(sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "jq -r .mode /etc/secure-sandbox/broker.json" 2>/dev/null || print unknown)"
if [[ "$broker_mode" == production ]]; then
  check "Gateway provider credential is host-bound and broker-only" sudo_remote SecureSandbox-Gateway sandbox-gateway \
    "systemctl show -p DropInPaths --value model-broker.service | grep -q /etc/systemd/system/model-broker.service.d/production.conf && sha256sum /etc/systemd/system/model-broker.service.d/production.conf | grep -q '^$approved_broker_credential_dropin_hash ' && test \"\$(stat -c %U:%G:%a /etc/systemd/system/model-broker.service.d/production.conf)\" = root:root:644 && test \"\$(stat -c %U:%G:%a /etc/credstore.encrypted/model-broker.provider_token)\" = root:root:600 && ! sudo -u model-broker test -r /etc/credstore.encrypted/model-broker.provider_token"
else
  gate "Gateway provider credential is intentionally absent outside production mode"
fi
check "Gateway run leases are root-issued, broker-readable, and durably bounded" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "sha256sum /usr/local/libexec/secure-sandbox/run_lease.py | grep -q ^$approved_lease_manager_hash && sha256sum /etc/secure-sandbox/run-lease-profiles.json | grep -q ^$approved_lease_profiles_hash && sha256sum /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh | grep -q ^$approved_gateway_install_recovery_hash && sha256sum /etc/systemd/system/run-leases-install-recovery.service | grep -q ^$approved_gateway_install_recovery_unit_hash && systemctl is-enabled --quiet run-leases-install-recovery.service && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases)\" = root:model-broker:750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases/leases)\" = root:model-broker:2750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases/counters)\" = model-broker:model-broker:700 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases/summaries)\" = root:model-broker:750 && sudo -u model-broker test -x /var/lib/secure-sandbox/run-leases/summaries && ! sudo -u model-broker test -w /var/lib/secure-sandbox/run-leases/summaries && ! sudo -u model-broker test -w /var/lib/secure-sandbox/run-leases/leases && systemctl show -p ReadWritePaths --value model-broker.service | grep -q /var/lib/secure-sandbox/run-leases/counters"
lease_closure_probe_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
check "Finalized leases are denied to the production broker identity" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "probe=\$(mktemp -d /var/lib/secure-sandbox/run-leases/.closure-probe.XXXXXX); trap 'rm -rf -- \"\$probe\"' EXIT; chown root:model-broker \"\$probe\"; chmod 750 \"\$probe\"; install -d -o root -g model-broker -m 2750 \"\$probe/leases\"; install -d -o model-broker -g model-broker -m 700 \"\$probe/counters\"; install -d -o root -g model-broker -m 750 \"\$probe/summaries\"; install -o root -g root -m 444 /dev/null \"\$probe/summaries/$lease_closure_probe_id.json\"; touch \"\$probe/counters/.lock\"; chown model-broker:model-broker \"\$probe/counters/.lock\"; chmod 600 \"\$probe/counters/.lock\"; sudo -u model-broker /usr/bin/python3 -c 'import importlib.util,pathlib,sys; spec=importlib.util.spec_from_file_location(\"run_lease\",\"/usr/local/libexec/secure-sandbox/run_lease.py\"); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); module.INSTALL_PENDING=pathlib.Path(\"/nonexistent\"); store=module.LeaseStore(pathlib.Path(sys.argv[1]),pathlib.Path(\"/nonexistent\"),pathlib.Path(\"/nonexistent\"),pathlib.Path(\"/nonexistent\")); exec(\"try:\\n store.reserve(sys.argv[2], \\\"a\\\" * 64, \\\"abliterated-model-large-v2\\\", 1, 1)\\n raise SystemExit(2)\\nexcept module.LeaseDenied as error:\\n raise SystemExit(0 if error.code == \\\"lease_closed\\\" else 3)\")' \"\$probe\" '$lease_closure_probe_id'"
check "Research enforcement services are active" remote sandbox-research-admin "systemctl is-active --quiet claude-relay claude-tool-auditor telemetry-exporter conversation-capture conversation-shipper artifact-collector execution-broker corpus-broker codegraph-query run-lease-watchdog memory-proposal findings-broker review-bundle-mount && test -f /run/secure-sandbox/conversation-capture-ready && test ! -e /run/secure-sandbox/conversation-capture-fatal && test -f /run/secure-sandbox/artifact-capture-ready && test ! -e /run/secure-sandbox/artifact-capture-fatal"
check "Research lease watchdog is root-owned, networkless, and idle-safe" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/run_lease_watchdog.py | grep -q ^$approved_watchdog_hash && sha256sum /usr/local/libexec/secure-sandbox/run_lease_process.py | grep -q ^$approved_run_supervisor_hash && sha256sum /usr/local/libexec/secure-sandbox/research_agent_ssh_entry.py | grep -q ^$approved_agent_ssh_entry_hash && sha256sum /usr/local/libexec/secure-sandbox/run-leases-install-recovery.sh | grep -q ^$approved_research_install_recovery_hash && sha256sum /etc/systemd/system/run-leases-install-recovery.service | grep -q ^$approved_research_install_recovery_unit_hash && systemctl is-enabled --quiet run-leases-install-recovery.service && sha256sum /etc/sudoers.d/secure-sandbox-run-lease | grep -q ^$approved_run_supervisor_sudoers_hash && test \"\$(stat -c %U:%G:%a /etc/sudoers.d/secure-sandbox-run-lease)\" = root:root:440 && visudo -cf /etc/sudoers.d/secure-sandbox-run-lease >/dev/null && sha256sum /etc/systemd/system/run-lease-watchdog.service | grep -q ^$approved_watchdog_unit_hash && systemctl show -p PrivateNetwork --value run-lease-watchdog.service | grep -qx yes && systemctl show -p ProtectControlGroups --value run-lease-watchdog.service | grep -qx no && systemctl show -p ReadWritePaths --value run-lease-watchdog.service | grep -q /sys/fs/cgroup && systemctl show -p CapabilityBoundingSet --value run-lease-watchdog.service | grep -q cap_kill && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-lifecycle)\" = root:root:755 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-lifecycle/capture-receipts)\" = root:root:700 && test ! -e /run/secure-sandbox/run-id && test ! -e /run/secure-sandbox/run-lease.json && test ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && test ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json"
check "Root-created run scope clears every supplementary group before agent execution" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "unit=secure-sandbox-group-probe-\$\$.scope; expected=\$(id -g agent); observed=\$(systemd-run --quiet --scope --unit=\$unit --property=Delegate=no -- /usr/bin/setpriv --reuid=\$(id -u agent) --regid=\$expected --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- /usr/bin/id -G); test \"\$observed\" = \"\$expected\""
check "CodeGraph socket admits the agent primary identity after group clearing" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(stat -c %U:%G:%a /run/secure-sandbox-codegraph/query.sock)\" = codegraph-query:agent:660 && /usr/bin/setpriv --reuid=\$(id -u agent) --regid=\$(id -g agent) --clear-groups --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs -- test -w /run/secure-sandbox-codegraph/query.sock"
check "Research agent SSH is a fixed launcher with no user-controlled SSH startup hooks" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /etc/ssh/sshd_config.d/20-secure-sandbox-agent-command.conf | grep -q ^$approved_agent_sshd_policy_hash && effective=\$(sshd -T -C user=agent,host=localhost,addr=127.0.0.1) && printf '%s\\n' \"\$effective\" | grep -qx 'forcecommand /usr/local/libexec/secure-sandbox/research_agent_ssh_entry.py' && printf '%s\\n' \"\$effective\" | grep -qx 'disableforwarding yes' && printf '%s\\n' \"\$effective\" | grep -qx 'permituserrc no' && printf '%s\\n' \"\$effective\" | grep -qx 'permituserenvironment no'"
check "Execution broker is the only Research identity admitted to Target TCP/8080" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "broker_uid=\$(id -u execution-broker); nft list chain inet filter output | grep -q \"meta skuid \$broker_uid.*172.30.20.2.*tcp dport 8080\" && runuser -u execution-broker -- curl -fsS --max-time 3 http://172.30.20.2:8080/healthz | grep -q status"
check "Disposable execution requires the pinned one-time host approval authority" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "schema=\$(jq -r .schema /etc/secure-sandbox/execution-broker.json); if test \"\$schema\" = secure-sandbox-execution-broker-v2; then test \"\$(jq -r .allowed_signers /etc/secure-sandbox/execution-broker.json)\" = /etc/secure-sandbox/execution-approval.allowed_signers && grep -Eq '^secure-sandbox-host ssh-ed25519 [A-Za-z0-9+/=]+$' /etc/secure-sandbox/execution-approval.allowed_signers && test \"\$(stat -c %U:%G:%a /etc/secure-sandbox/execution-approval.allowed_signers)\" = root:execution-broker:640; else test \"\$schema\" = secure-sandbox-execution-broker-v3 && jq -e '(.allowed_signers? == null) and .approval.mode == \"active-v2\" and .approval.minimum_protocol == 2 and .approval.generation_epoch >= .approval.minimum_epoch and .approval.algorithm == \"ecdsa-p256-sha256-x962-low-s\" and (.approval.public_key_sha256 | test(\"^[0-9a-f]{64}$\"))' /etc/secure-sandbox/execution-broker.json >/dev/null && { test ! -e /etc/secure-sandbox/execution-approval.allowed_signers || { test -f /etc/secure-sandbox/execution-approval.allowed_signers && test ! -L /etc/secure-sandbox/execution-approval.allowed_signers && test \"\$(stat -c %h /etc/secure-sandbox/execution-approval.allowed_signers)\" = 1 && test \"\$(wc -l < /etc/secure-sandbox/execution-approval.allowed_signers)\" = 1 && awk '{ if (NR != 1 || \$0 !~ /^secure-sandbox-host ssh-ed25519 [A-Za-z0-9+\/=]+\$/) bad=1 } END { exit (bad || NR != 1) }' /etc/secure-sandbox/execution-approval.allowed_signers && test \"\$(stat -c %U:%G:%a /etc/secure-sandbox/execution-approval.allowed_signers)\" = root:execution-broker:640; }; }; fi && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/execution-approvals/pending)\" = execution-broker:execution-broker:700 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/execution-approvals/consumed)\" = execution-broker:execution-broker:700 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/execution-approvals/claims)\" = root:execution-broker:750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/execution-approvals/responses)\" = root:execution-broker:750 && systemctl show -p UMask --value execution-broker.service | grep -qx 0077"
check "Host and Research pin the same execution-approval generation and monotonic floor" \
  execution_approval_authorities_match
check "Disposable execution Target is rootless, fixed-image, and shell-free" remote sandbox-target-admin \
  "systemctl --user is-active --quiet secure-sandbox-execution.service && image=\$(jq -r .image_id /etc/secure-sandbox/execution-target.json) && test \"\$(DOCKER_HOST=unix:///run/user/1000/docker.sock docker image inspect --format '{{.Id}}' \"\$image\")\" = \"\$image\" && test \"\$(DOCKER_HOST=unix:///run/user/1000/docker.sock docker image inspect --format '{{.Config.User}} {{.Config.WorkingDir}} {{index .Config.Labels \"org.securesandbox.runtime\"}}' \"\$image\")\" = '65532:65532 /work python-fixture-v1' && ! DOCKER_HOST=unix:///run/user/1000/docker.sock docker run --rm --network none --entrypoint /bin/sh \"\$image\" -c true >/dev/null 2>&1 && test \"\$(stat -c %U:%G:%a /etc/secure-sandbox/execution-target.json)\" = root:labadmin:640 && test \"\$(stat -c %U:%G:%a /etc/systemd/user/secure-sandbox-execution.service)\" = root:root:644 && test ! -e /home/labadmin/.config/secure-sandbox-execution.json && test ! -e /home/labadmin/.config/systemd/user/secure-sandbox-execution.service"
check "Target execution broker uses the approved bounded framing runtime" remote sandbox-target-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/shared/__init__.py | grep -q ^$approved_shared_init_hash && sha256sum /usr/local/libexec/secure-sandbox/shared/bounded_http.py | grep -q ^$approved_bounded_http_hash && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/execution_service.py)\" = root:root:755 && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/shared/__init__.py)\" = root:root:644 && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/shared/bounded_http.py)\" = root:root:755 && test ! -e /home/labadmin/.local/libexec/secure-sandbox/execution_service.py"
check "Source acquisition components are installed with protected state" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "test -x /usr/local/libexec/secure-sandbox/source_controller.py && test -x /usr/local/libexec/secure-sandbox/source_fetcher.py && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition)\" = root:source-fetcher:750 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition/plans)\" = root:source-fetcher:2750 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition/spool)\" = source-fetcher:source-fetcher:700"
check "Research source importer is root-only and repository index is immutable to agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test -x /usr/local/libexec/secure-sandbox/source_importer.py && test -x /usr/local/sbin/secure-sandbox-source-import && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace)\" = agent:agent:750 && test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/repos/INDEX.json)\" = root:root:444 && sudo -u corpus-broker test -r /home/agent/research-workspace/repos/INDEX.json && sudo -u execution-broker test -r /home/agent/research-workspace/repos/INDEX.json && sudo -u findings-broker test -r /home/agent/research-workspace/repos/INDEX.json && ! sudo -u agent test -w /home/agent/research-workspace/repos/INDEX.json && ! sudo -u agent /usr/local/libexec/secure-sandbox/source_importer.py publish 00000000-0000-4000-8000-000000000000 >/dev/null 2>&1"
check "Dependency orchestration is root-only and published bundles are immutable to agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/dependency_orchestrator.py)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/dependency-orchestration)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/dependency-orchestration/plans)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/dependency-orchestration/transactions)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/dependency-bundles)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/dependency-bundles/INDEX.json)\" = root:root:444 && ! sudo -u agent test -w /home/agent/research-workspace/dependency-bundles && ! sudo -u agent /usr/local/libexec/secure-sandbox/dependency_orchestrator.py plan 00000000-0000-4000-8000-000000000000 >/dev/null 2>&1"
check "Corpus intelligence binaries and index directory are root-controlled" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/corpus-indexes)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/corpus_intelligence.py)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py)\" = root:root:755 && ! sudo -u agent test -w /home/agent/research-workspace/corpus-indexes && ! sudo -u agent /usr/local/libexec/secure-sandbox/corpus_intelligence.py index 00000000-0000-4000-8000-000000000000 >/dev/null 2>&1"
check "Evidence receipts are producer-minted and hidden from the agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/evidence_receipts.py | grep -q ^$approved_receipts_hash && sha256sum /usr/local/libexec/secure-sandbox/corpus_broker.py | grep -q ^$approved_corpus_broker_hash && sha256sum /etc/systemd/system/corpus-broker.service | grep -q ^$approved_corpus_broker_unit_hash && sha256sum /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py | grep -q ^$approved_corpus_mcp_hash && sha256sum /usr/local/libexec/secure-sandbox/execution_broker.py | grep -q ^$approved_execution_broker_hash && sha256sum /etc/systemd/system/execution-broker.service | grep -q ^$approved_execution_unit_hash && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts)\" = root:evidence-receipts:750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts/corpus)\" = corpus-broker:evidence-receipts:2750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts/execution)\" = execution-broker:evidence-receipts:2750 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox-corpus/corpus.sock)\" = corpus-broker:agent:660 && sudo -u agent test -w /run/secure-sandbox-corpus/corpus.sock && ! sudo -u agent test -r /var/lib/secure-sandbox/evidence-receipts && sudo -u corpus-broker test -w /var/lib/secure-sandbox/evidence-receipts/corpus && ! sudo -u corpus-broker test -w /var/lib/secure-sandbox/evidence-receipts/execution && sudo -u execution-broker test -w /var/lib/secure-sandbox/evidence-receipts/execution && ! sudo -u execution-broker test -w /var/lib/secure-sandbox/evidence-receipts/corpus"
check "Research local brokers use the approved bounded framing runtimes" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/bounded_unix_server.py | grep -q ^$approved_bounded_server_hash && sha256sum /usr/local/libexec/secure-sandbox/shared/__init__.py | grep -q ^$approved_shared_init_hash && sha256sum /usr/local/libexec/secure-sandbox/shared/bounded_http.py | grep -q ^$approved_bounded_http_hash && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/bounded_unix_server.py)\" = root:root:755 && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/shared/__init__.py)\" = root:root:644 && test \"\$(stat -c %U:%G:%a /usr/local/libexec/secure-sandbox/shared/bounded_http.py)\" = root:root:755"
check "CodeGraph manifests are root-controlled and immutable to the agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/codegraph-indexes)\" = root:root:755 && ! sudo -u agent test -w /home/agent/research-workspace/codegraph-indexes && for marker in /home/agent/research-workspace/codegraph-indexes/*.json; do if ! test -e \"\$marker\"; then ! test -L \"\$marker\" || exit 1; continue; fi; test -f \"\$marker\" && ! test -L \"\$marker\" && test \"\$(stat -c %U:%G:%a \"\$marker\")\" = root:root:444 && ! sudo -u agent test -w \"\$marker\" || exit 1; done"
check "Memory proposals are bounded, brokered, and non-authoritative" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/memory_proposal.py | grep -q ^$approved_memory_broker_hash && sha256sum /usr/local/libexec/secure-sandbox/memory_proposal_mcp.py | grep -q ^$approved_memory_mcp_hash && sha256sum /etc/systemd/system/memory-proposal.service | grep -q ^$approved_memory_unit_hash && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/memory-proposals)\" = memory-proposal:agent:700 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox-memory/memory-proposal.sock)\" = memory-proposal:agent:660 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox)\" = root:conversation-shipper:755 && sudo -u agent test -w /run/secure-sandbox-memory/memory-proposal.sock && ! sudo -u agent test -r /var/lib/secure-sandbox/memory-proposals && ! test -e /home/agent/.claude/projects/-home-agent-research-workspace/memory && ! test -e /home/agent/research-workspace/CLAUDE.md && ! test -e /home/agent/CLAUDE.md && ! test -e /home/agent/.claude/CLAUDE.md"
check "Candidate findings are brokered and adjudication remains root-only" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/findings_broker.py | grep -q ^$approved_findings_broker_hash && sha256sum /usr/local/libexec/secure-sandbox/findings_mcp.py | grep -q ^$approved_findings_mcp_hash && sha256sum /usr/local/libexec/secure-sandbox/finding_admin.py | grep -q ^$approved_finding_admin_hash && sha256sum /etc/systemd/system/findings-broker.service | grep -q ^$approved_findings_unit_hash && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/findings)\" = findings-broker:agent:700 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox-findings/findings.sock)\" = findings-broker:agent:660 && sudo -u agent test -w /run/secure-sandbox-findings/findings.sock && ! sudo -u agent test -r /var/lib/secure-sandbox/findings && ! sudo -u agent /usr/local/libexec/secure-sandbox/finding_admin.py list >/dev/null 2>&1"
check "Gateway services wait for restricted network interfaces" remote sandbox-gateway \
  "systemctl show -p After --value model-broker.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value model-broker.service | grep -q sys-subsystem-net-devices-uplink0.device && systemctl show -p After --value telemetry-receiver.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value conversation-receiver.service | grep -q sys-subsystem-net-devices-ctl0.device && { test \"\$(systemctl show -p LoadState --value azure-shipper.service)\" = not-found || systemctl show -p After --value azure-shipper.service | grep -q sys-subsystem-net-devices-uplink0.device; } && systemctl show -p After --value conversation-azure-shipper.service | grep -q sys-subsystem-net-devices-uplink0.device"
check "Research services wait for the restricted control interface" remote sandbox-research-admin \
  "systemctl show -p After --value claude-relay.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value telemetry-exporter.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value conversation-shipper.service | grep -q sys-subsystem-net-devices-ctl0.device"
check "Artifact collector is networkless and isolated from writable agent state" remote sandbox-research-admin \
  "systemctl show -p PrivateNetwork --value artifact-collector.service | grep -qx yes && systemctl show -p ProtectSystem --value artifact-collector.service | grep -qx strict && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/artifact-capture)\" = root:root:700 && ! sudo -u agent test -r /var/lib/secure-sandbox/artifact-capture/state.json"
check "Claude tool auditor is networkless and read-only" remote sandbox-research-admin \
  "systemctl show -p PrivateNetwork --value claude-tool-auditor.service | grep -qx yes && systemctl show -p ProtectSystem --value claude-tool-auditor.service | grep -qx strict && systemctl show -p ReadWritePaths --value claude-tool-auditor.service | grep -q /var/lib/secure-sandbox/tool-auditor"
check "Conversation collector is networkless and fail-closed" remote sandbox-research-admin \
  "systemctl show -p PrivateNetwork --value conversation-capture.service | grep -qx yes && systemctl show -p ProtectSystem --value conversation-capture.service | grep -qx strict && systemctl show -p CapabilityBoundingSet --value conversation-capture.service | grep -q cap_kill"
check "Conversation shipper quarantines malformed bounded chunks without a poison-head retry loop" remote sandbox-research-admin \
  "test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/conversation-quarantine)\" = root:conversation-shipper:2770 && systemctl show -p ReadWritePaths --value conversation-shipper.service | grep -q /var/lib/secure-sandbox/conversation-outbox && systemctl show -p ReadWritePaths --value conversation-shipper.service | grep -q /var/lib/secure-sandbox/conversation-quarantine && systemctl show -p OnFailure --value conversation-shipper.service | grep -q conversation-capture-failure.service"
check "Gateway kernel policy is default-drop and non-forwarding" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "source_fetcher_uid=\$(id -u source-fetcher) && test \"\$(nft list ruleset | grep -c \"policy drop\")\" -eq 3 && test \"\$(sysctl -n net.ipv4.ip_forward)\" -eq 0 && test \"\$(sysctl -n kernel.io_uring_disabled)\" -eq 2 && nft list chain inet filter output | grep -q \"meta skuid \$source_fetcher_uid.*tcp dport 443\""
check "Research kernel policy is default-drop and non-forwarding" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(nft list ruleset | grep -c \"policy drop\")\" -eq 3 && test \"\$(sysctl -n net.ipv4.ip_forward)\" -eq 0 && test \"\$(sysctl -n kernel.io_uring_disabled)\" -eq 2 && nft list chain inet filter output | grep -q \"meta skuid.*tcp dport 8443\" && nft list chain inet filter output | grep -q \"meta skuid.*tcp dport 9443\" && nft list chain inet filter output | grep -q \"meta skuid.*tcp dport 9553\""
check "Target kernel policy is default-drop and non-forwarding" sudo_remote SecureSandbox-Target sandbox-target-admin \
  "test \"\$(nft list ruleset | grep -c \"policy drop\")\" -eq 3 && test \"\$(sysctl -n net.ipv4.ip_forward)\" -eq 0 && test \"\$(sysctl -n kernel.io_uring_disabled)\" -eq 2"
check "Gateway runtime DNS is disabled" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "test \"\$(systemctl is-enabled systemd-resolved.service 2>/dev/null || true)\" = masked && test -f /etc/resolv.conf && test ! -L /etc/resolv.conf && test ! -s /etc/resolv.conf"
check "Research runtime DNS is disabled" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(systemctl is-enabled systemd-resolved.service 2>/dev/null || true)\" = masked && test -f /etc/resolv.conf && test ! -L /etc/resolv.conf && test ! -s /etc/resolv.conf"
check "Target runtime DNS is disabled" sudo_remote SecureSandbox-Target sandbox-target-admin \
  "test \"\$(systemctl is-enabled systemd-resolved.service 2>/dev/null || true)\" = masked && test -f /etc/resolv.conf && test ! -L /etc/resolv.conf && test ! -s /etc/resolv.conf"
check "Gateway CA and server certificate have more than 48 hours remaining" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/pki/ca.crt && openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/pki/server.crt"
check "Research client certificates have more than 48 hours remaining" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/relay/client.crt && openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/telemetry/client.crt && openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/conversation-transport/client.crt"
check "Gateway PKI generation is source-pinned, active, and internally consistent" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "sha256sum /usr/local/libexec/secure-sandbox/pki_lifecycle.py | grep -q ^$approved_pki_lifecycle_hash && sha256sum /usr/local/libexec/secure-sandbox/pki_generation.py | grep -q ^$approved_gateway_pki_hash && sha256sum /etc/systemd/system/pki-expiry-check.service | grep -q ^$approved_pki_expiry_service_hash && sha256sum /etc/systemd/system/pki-expiry-check.timer | grep -q ^$approved_pki_expiry_timer_hash && systemctl is-active --quiet pki-expiry-check.timer && /usr/local/libexec/secure-sandbox/pki_generation.py verify >/dev/null"
check "Research PKI generation is source-pinned, active, and internally consistent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/pki_lifecycle.py | grep -q ^$approved_pki_lifecycle_hash && sha256sum /usr/local/libexec/secure-sandbox/pki_guest_helpers.py | grep -q ^$approved_pki_helpers_hash && sha256sum /usr/local/libexec/secure-sandbox/pki_generation.py | grep -q ^$approved_research_pki_hash && sha256sum /etc/systemd/system/pki-expiry-check.service | grep -q ^$approved_pki_expiry_service_hash && sha256sum /etc/systemd/system/pki-expiry-check.timer | grep -q ^$approved_pki_expiry_timer_hash && systemctl is-active --quiet pki-expiry-check.timer && /usr/local/libexec/secure-sandbox/pki_generation.py verify >/dev/null"
check "Privileged workflow engine is source-pinned on every role" zsh -c '
  expected="$1"; ssh_config="$2"; shift 2
  for host in "$@"; do
    ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 "$host" \
      "test \"\$(sha256sum /usr/local/libexec/secure-sandbox/shared/privileged_workflow.py | awk '\''{print \$1}'\'')\" = \"$expected\" && test \"\$(stat -c '\''%U:%G:%a'\'' /usr/local/libexec/secure-sandbox/shared/privileged_workflow.py)\" = root:root:755" || exit 1
  done
' _ "$approved_privileged_workflow_hash" "$ssh_config" sandbox-gateway sandbox-research-admin sandbox-target-admin
pki_anchor_json="$(/usr/local/libexec/secure-sandbox-host/current/pki_anchor verify 2>/dev/null || true)"
pki_gateway_json="$(sudo_remote SecureSandbox-Gateway sandbox-gateway '/usr/local/libexec/secure-sandbox/pki_generation.py verify' 2>/dev/null || true)"
pki_research_json="$(sudo_remote SecureSandbox-Research sandbox-research-admin '/usr/local/libexec/secure-sandbox/pki_generation.py verify' 2>/dev/null || true)"
if jq -n -e --argjson host "${pki_anchor_json:-null}" --argjson gateway "${pki_gateway_json:-null}" --argjson research "${pki_research_json:-null}" \
    '$host.generation_id == $gateway.generation_id and $host.generation_id == $research.generation_id and $host.manifest_sha256 == $gateway.manifest_sha256 and $host.manifest_sha256 == $research.manifest_sha256' \
    >/dev/null 2>&1; then
  pass "Host, Gateway, and Research bind the same PKI generation"
else
  fail "Host, Gateway, and Research bind the same PKI generation"
fi
pki_canary_since="$(freshness_cutoff)"
pki_canary_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
if sudo_remote SecureSandbox-Gateway sandbox-gateway \
    "systemctl start pki-expiry-check.service && test \"\$(systemctl show -p Result --value pki-expiry-check.service)\" = success && systemd-cat -t secure-sandbox-pki -- /usr/local/libexec/secure-sandbox/pki_lifecycle.py expiry --evidence-id '$pki_canary_id'" \
    >/dev/null 2>&1; then
  if sudo_remote SecureSandbox-Gateway sandbox-gateway \
    "generation=\$(jq -r .generation_id /etc/secure-sandbox/pki-generation.json); for _ in {1..20}; do jq -e --arg generation \"\$generation\" --arg since '$pki_canary_since' --arg evidence '$pki_canary_id' 'select(.EventType == \"pki_expiry_status\" and .RequestId == \$generation and (.Message | endswith(\":\" + \$evidence)) and .TimeGenerated >= \$since)' /var/lib/secure-sandbox/telemetry/current.jsonl >/dev/null && exit 0; sleep 0.5; done; exit 1" \
    >/dev/null 2>&1; then
    pass "Fresh active-generation PKI expiry evidence reached the content-free spool"
  else
    fail "Fresh active-generation PKI expiry evidence reached the content-free spool"
  fi
else
  fail "Fresh active-generation PKI expiry evidence reached the content-free spool"
fi
check "Research agent and execution-broker network syscalls are audited" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(id -u agent)\" = 1001 && test \"\$(awk -F= '/^[[:space:]]*log_format[[:space:]]*=/{gsub(/[[:space:]]/, \"\", \$2); print \$2}' /etc/audit/auditd.conf)\" = ENRICHED && auditctl -l | grep -q \"connect,sendto,sendmsg,sendmmsg.*uid=1001.*key=agent-network\" && broker_uid=\$(id -u execution-broker) && auditctl -l | grep -q \"connect,sendto,sendmsg,sendmmsg.*uid=\$broker_uid.*key=execution-network\""
network_canary_since="$(freshness_cutoff)"
IFS=' ' read -r network_canary_destination network_canary_port <<< "$(python3 -c 'import secrets; value=secrets.randbits(39); print(f"198.{18 + ((value >> 31) & 1)}.{(value >> 23) & 255}.{(value >> 15) & 255} {16384 + (value & 32767)}")')"
[[ "$network_canary_destination" == 198.1[89].* && "$network_canary_port" == <16384-49151> ]] \
  || { print -u2 "FAIL  Network canary generation"; exit 1; }
if agent_remote "/usr/bin/python3 -c 'import socket; socket.create_connection((\"$network_canary_destination\",$network_canary_port),0.5)'" \
    >/dev/null 2>&1; then
  fail "Agent audit canary is blocked before telemetry correlation"
else
  pass "Agent audit canary is blocked before telemetry correlation"
fi
# The connection remains bounded at 0.5 seconds. Exact evidence correlation is
# performed inside one authenticated request so polling consumes one receipt.
if sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "for _ in {1..20}; do jq -e --arg since '$network_canary_since' --arg destination '$network_canary_destination' --argjson port '$network_canary_port' 'select(.EventType == \"network_connect_unapproved\" and .RunId == \"boundary-test\" and .Destination == \$destination and .DestinationPort == \$port and .TimeGenerated >= \$since)' /var/lib/secure-sandbox/telemetry/current.jsonl >/dev/null && exit 0; sleep 0.5; done; exit 1" \
  >/dev/null 2>&1; then
  pass "Fresh agent network-denial canary reached the metadata spool"
else
  fail "Fresh agent network-denial canary reached the metadata spool"
fi
check "Gateway has no failed systemd unit" remote sandbox-gateway "test -z \"\$(systemctl --failed --no-legend)\""
check "Research has no failed systemd unit" remote sandbox-research-admin "test -z \"\$(systemctl --failed --no-legend)\""
check "Target has no failed systemd unit" remote sandbox-target-admin "test -z \"\$(systemctl --failed --no-legend)\""

[[ "$broker_mode" == production ]] && pass "model broker is in production mode" || gate "model broker remains in safe mock mode"
if remote sandbox-gateway "systemctl is-enabled --quiet azure-shipper" >/dev/null 2>&1; then
  check "Azure off-host shipper is active" remote sandbox-gateway \
    "systemctl is-active --quiet azure-shipper"
else
  gate "Azure off-host shipper awaits cloud deployment"
fi
remote sandbox-gateway "systemctl is-active --quiet conversation-azure-shipper" >/dev/null 2>&1 \
  && pass "Azure encrypted conversation shipper is active" || gate "Azure encrypted conversation shipper awaits cloud deployment"
approved_settings_hash="$(shasum -a 256 "$root_dir/research/managed-settings.proposed.json" | awk '{print $1}')"
approved_launcher_hash="$(shasum -a 256 "$root_dir/research/research-claude.proposed" | awk '{print $1}')"
approved_registry_hash="$(shasum -a 256 "$root_dir/research/session_registry.py" | awk '{print $1}')"
approved_mcp_hash="$(shasum -a 256 "$root_dir/research/managed-mcp.json" | awk '{print $1}')"
approved_integrity_hash="$(shasum -a 256 "$root_dir/research/source_integrity.py" | awk '{print $1}')"
approved_integrity_server_hash="$(shasum -a 256 "$root_dir/research/source_integrity_mcp.py" | awk '{print $1}')"
approved_review_bundle_hash="$(shasum -a 256 "$root_dir/research/review_bundle.py" | awk '{print $1}')"
approved_review_publisher_hash="$(shasum -a 256 "$root_dir/research/review_bundle_publisher.py" | awk '{print $1}')"
approved_review_mount_hash="$(shasum -a 256 "$root_dir/research/review-bundle-mount.service" | awk '{print $1}')"
approved_telemetry_exporter_hash="$(shasum -a 256 "$root_dir/research/telemetry_exporter.py" | awk '{print $1}')"
approved_corpus_hash="$(shasum -a 256 "$root_dir/research/corpus_intelligence.py" | awk '{print $1}')"
approved_corpus_server_hash="$(shasum -a 256 "$root_dir/research/corpus_intelligence_mcp.py" | awk '{print $1}')"
approved_execution_broker_hash="$(shasum -a 256 "$root_dir/research/execution_broker.py" | awk '{print $1}')"
approved_execution_mcp_hash="$(shasum -a 256 "$root_dir/research/execution_mcp.py" | awk '{print $1}')"
approved_dependency_hash="$(shasum -a 256 "$root_dir/research/dependency_orchestrator.py" | awk '{print $1}')"
check "Review bundles have a pinned canonical read-only workspace view" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /etc/systemd/system/review-bundle-mount.service | grep -q ^$approved_review_mount_hash && systemctl is-active --quiet review-bundle-mount.service && mountpoint -q /home/agent/research-workspace/review-bundles && test \"\$(stat -c %d:%i /var/lib/secure-sandbox/review-bundles)\" = \"\$(stat -c %d:%i /home/agent/research-workspace/review-bundles)\" && findmnt -n -o OPTIONS --target /home/agent/research-workspace/review-bundles | grep -q ^ro, && ! sudo -u agent test -w /home/agent/research-workspace/review-bundles"
if sudo_remote SecureSandbox-Research sandbox-research-admin \
    "test \"\$(sha256sum /etc/claude-code/managed-settings.json | cut -d' ' -f1)\" = '$approved_settings_hash' && test \"\$(sha256sum /usr/local/bin/research-claude | cut -d' ' -f1)\" = '$approved_launcher_hash' && test \"\$(sha256sum /etc/claude-code/secure-sandbox-persona.md | cut -d' ' -f1)\" = '$approved_persona_hash' && test \"\$(stat -c %U:%G:%a /etc/claude-code/secure-sandbox-persona.md)\" = root:root:444 && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/session_registry.py | cut -d' ' -f1)\" = '$approved_registry_hash' && test \"\$(sha256sum /etc/claude-code/managed-mcp.json | cut -d' ' -f1)\" = '$approved_mcp_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/source_integrity.py | cut -d' ' -f1)\" = '$approved_integrity_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/source_integrity_mcp.py | cut -d' ' -f1)\" = '$approved_integrity_server_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/review_bundle.py | cut -d' ' -f1)\" = '$approved_review_bundle_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/review_bundle_publisher.py | cut -d' ' -f1)\" = '$approved_review_publisher_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/telemetry_exporter.py | cut -d' ' -f1)\" = '$approved_telemetry_exporter_hash' && test \"\$(stat -c %U:%G:%a /home/agent/research-workspace/review-bundles)\" = root:root:755 && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/corpus_intelligence.py | cut -d' ' -f1)\" = '$approved_corpus_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py | cut -d' ' -f1)\" = '$approved_corpus_server_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/execution_broker.py | cut -d' ' -f1)\" = '$approved_execution_broker_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/execution_mcp.py | cut -d' ' -f1)\" = '$approved_execution_mcp_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/memory_proposal.py | cut -d' ' -f1)\" = '$approved_memory_broker_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/memory_proposal_mcp.py | cut -d' ' -f1)\" = '$approved_memory_mcp_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/findings_broker.py | cut -d' ' -f1)\" = '$approved_findings_broker_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/findings_mcp.py | cut -d' ' -f1)\" = '$approved_findings_mcp_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/finding_admin.py | cut -d' ' -f1)\" = '$approved_finding_admin_hash' && test \"\$(sha256sum /usr/local/libexec/secure-sandbox/dependency_orchestrator.py | cut -d' ' -f1)\" = '$approved_dependency_hash' && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/claude-sessions.txt)\" = root:root:644 && test \"\$(stat -c %U:%G:%a /home/agent/research-workspace/repos)\" = root:root:755 && test \"\$(stat -c %U:%G:%a /home/agent/research-workspace/baselines)\" = root:root:755 && test \"\$(stat -c %U:%G:%a /home/agent/research-workspace/source-manifests)\" = root:root:755 && ! /usr/local/bin/research-claude --version >/dev/null 2>&1 && ! /usr/local/bin/research-claude --resume 00000000-0000-0000-0000-000000000000 >/dev/null 2>&1" \
    >/dev/null 2>&1; then
  pass "Claude policy, fixed launcher, managed MCPs, and root-owned anchors match approved artifacts"
else
  gate "Claude managed policy awaits approval or differs from approved artifacts"
fi

if (( failures )); then
  print "\nBOUNDARY VERIFICATION FAILED: $failures check(s)"
  exit 1
fi
print "\nBOUNDARY VERIFICATION PASSED; review GATE lines before high-risk use."
