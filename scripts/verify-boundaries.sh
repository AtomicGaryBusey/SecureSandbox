#!/bin/zsh
set -u

root_dir="${0:A:h:h}"
ssh_config="$root_dir/config/ssh_config"
failures=0
approved_broker_credential_dropin_hash="$(shasum -a 256 "$root_dir/gateway/model-broker-production.conf" | awk '{print $1}')"
approved_lease_manager_hash="$(shasum -a 256 "$root_dir/gateway/run_lease.py" | awk '{print $1}')"
approved_lease_profiles_hash="$(shasum -a 256 "$root_dir/gateway/run-lease-profiles.json" | awk '{print $1}')"
approved_watchdog_hash="$(shasum -a 256 "$root_dir/research/run_lease_watchdog.py" | awk '{print $1}')"
approved_run_supervisor_hash="$(shasum -a 256 "$root_dir/research/run_lease_process.py" | awk '{print $1}')"
approved_run_supervisor_sudoers_hash="$(shasum -a 256 "$root_dir/research/run-lease-supervisor.sudoers" | awk '{print $1}')"
approved_watchdog_unit_hash="$(shasum -a 256 "$root_dir/research/run-lease-watchdog.service" | awk '{print $1}')"
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

pass() { print "PASS  $1"; }
fail() { print "FAIL  $1"; failures=$((failures + 1)); }
gate() { print "GATE  $1"; }
check() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then pass "$description"; else fail "$description"; fi
}
check "Host Claude controller is an immutable release matching approved source" \
  python3 "$root_dir/scripts/host-controller-release.py" verify
remote() { ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 "$@"; }
sudo_remote() {
  local item="$1"
  local host="$2"
  local command="$3"
  op-agents read "op://Agents/$item/password" \
    | ssh -F "$ssh_config" -o BatchMode=yes -o ConnectTimeout=5 "$host" \
      "sudo -S -p '' sh -c '$command'"
}

boundary_marker_active=0
clear_boundary_marker() {
  if (( boundary_marker_active )); then
    # Allow the real-time audit tail to correlate the final test syscall before
    # removing the marker. This writes no workload content.
    sleep 2
    sudo_remote SecureSandbox-Research sandbox-research-admin \
      "/usr/local/libexec/secure-sandbox/manage_run_id.py clear boundary-test" >/dev/null 2>&1 || true
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
done

if sudo_remote SecureSandbox-Research sandbox-research-admin \
    "/usr/local/libexec/secure-sandbox/manage_run_id.py set boundary-test" \
    >/dev/null 2>&1; then
  boundary_marker_active=1
  pass "boundary verification telemetry is explicitly marked"
else
  fail "boundary verification telemetry is explicitly marked"
fi

check "custom Parallels networks have no host adapter, DHCP, DHCPv6, or NAT" \
  python3 "$root_dir/scripts/verify-parallels-networks.py"
check "Research has no IPv4 default route" remote sandbox-research "test -z \"\$(ip -4 route show default)\""
check "Research IPv6 is disabled" remote sandbox-research "test \"\$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)\" = 1"
check "Target has no IPv4 default route" remote sandbox-target-admin "test -z \"\$(ip -4 route show default)\""
check "Target IPv6 is disabled" remote sandbox-target-admin "test \"\$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)\" = 1"
check "Target rootless Docker security profile is active" remote sandbox-target-admin \
  "systemctl --user is-active --quiet docker && DOCKER_HOST=unix:///run/user/1000/docker.sock docker info --format '{{json .SecurityOptions}}' | grep -q '\"name=rootless\"' && DOCKER_HOST=unix:///run/user/1000/docker.sock docker info --format '{{json .SecurityOptions}}' | grep -q '\"name=no-new-privileges\"'"
check "Research public TCP egress is blocked" remote sandbox-research "! timeout 2 bash -c '</dev/tcp/8.8.8.8/443'"
check "Research metadata endpoint is blocked" remote sandbox-research "! timeout 2 bash -c '</dev/tcp/169.254.169.254/80'"
check "Research home-LAN probe is blocked" remote sandbox-research "! timeout 2 bash -c '</dev/tcp/192.168.1.1/80'"
check "Target cannot initiate toward Research" remote sandbox-target-admin "! timeout 2 bash -c '</dev/tcp/172.30.20.1/22'"
check "Research agent cannot initiate Target SSH" remote sandbox-research "! timeout 2 bash -c '</dev/tcp/172.30.20.2/22'"
check "Research agent cannot call Target execution service directly" remote sandbox-research "! curl -fsS --max-time 2 http://172.30.20.2:8080/healthz"
check "Research agent has no noninteractive sudo" remote sandbox-research "! sudo -n true"
check "Research agent cannot read relay private key" remote sandbox-research "! test -r /etc/secure-sandbox/relay/client.key"
check "Research agent cannot read telemetry private key" remote sandbox-research "! test -r /etc/secure-sandbox/telemetry/client.key"
check "Research agent cannot read conversation transport private key" remote sandbox-research "! test -r /etc/secure-sandbox/conversation-transport/client.key"
check "Claude Code pinned binary is installed" remote sandbox-research "test \"\$(claude --version)\" = '2.1.300 (Claude Code)'"
check "Research cannot call broker without its relay mTLS identity" remote sandbox-research \
  "! curl -kfsS --max-time 3 https://172.30.10.1:8443/healthz"
check "Relay-to-broker mTLS health path works" remote sandbox-research \
  "curl -fsS --max-time 3 http://127.0.0.1:18080/healthz | grep -q '\"status\":\"ok\"'"
check "Relay accepts only the exact beta=true compatibility marker" remote sandbox-research \
  "test \"\$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -H 'Content-Type: application/json' --data '{}' 'http://127.0.0.1:18080/v1/messages?beta=true')\" = 403 && test \"\$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 -H 'Content-Type: application/json' --data '{}' 'http://127.0.0.1:18080/v1/messages?beta=false')\" = 404"
check "Gateway enforcement services are active" remote sandbox-gateway "systemctl is-active --quiet model-broker telemetry-receiver local-telemetry-exporter conversation-receiver conversation-azure-shipper"
check "Gateway provider credential is host-bound and broker-only" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "systemctl show -p DropInPaths --value model-broker.service | grep -q /etc/systemd/system/model-broker.service.d/production.conf && sha256sum /etc/systemd/system/model-broker.service.d/production.conf | grep -q '^$approved_broker_credential_dropin_hash ' && test \"\$(stat -c %U:%G:%a /etc/systemd/system/model-broker.service.d/production.conf)\" = root:root:644 && test \"\$(stat -c %U:%G:%a /etc/credstore.encrypted/model-broker.provider_token)\" = root:root:600 && ! sudo -u model-broker test -r /etc/credstore.encrypted/model-broker.provider_token"
check "Gateway run leases are root-issued, broker-readable, and durably bounded" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "sha256sum /usr/local/libexec/secure-sandbox/run_lease.py | grep -q ^$approved_lease_manager_hash && sha256sum /etc/secure-sandbox/run-lease-profiles.json | grep -q ^$approved_lease_profiles_hash && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases)\" = root:model-broker:750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases/leases)\" = root:model-broker:2750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases/counters)\" = model-broker:model-broker:700 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/run-leases/summaries)\" = root:model-broker:750 && sudo -u model-broker test -x /var/lib/secure-sandbox/run-leases/summaries && ! sudo -u model-broker test -w /var/lib/secure-sandbox/run-leases/summaries && ! sudo -u model-broker test -w /var/lib/secure-sandbox/run-leases/leases && systemctl show -p ReadWritePaths --value model-broker.service | grep -q /var/lib/secure-sandbox/run-leases/counters"
check "Research enforcement services are active" remote sandbox-research-admin "systemctl is-active --quiet claude-relay claude-tool-auditor telemetry-exporter conversation-capture conversation-shipper artifact-collector execution-broker corpus-broker run-lease-watchdog memory-proposal findings-broker review-bundle-mount && test -f /run/secure-sandbox/conversation-capture-ready && test ! -e /run/secure-sandbox/conversation-capture-fatal && test -f /run/secure-sandbox/artifact-capture-ready && test ! -e /run/secure-sandbox/artifact-capture-fatal"
check "Research lease watchdog is root-owned, networkless, and idle-safe" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/run_lease_watchdog.py | grep -q ^$approved_watchdog_hash && sha256sum /usr/local/libexec/secure-sandbox/run_lease_process.py | grep -q ^$approved_run_supervisor_hash && sha256sum /etc/sudoers.d/secure-sandbox-run-lease | grep -q ^$approved_run_supervisor_sudoers_hash && test \"\$(stat -c %U:%G:%a /etc/sudoers.d/secure-sandbox-run-lease)\" = root:root:440 && visudo -cf /etc/sudoers.d/secure-sandbox-run-lease >/dev/null && sha256sum /etc/systemd/system/run-lease-watchdog.service | grep -q ^$approved_watchdog_unit_hash && systemctl show -p PrivateNetwork --value run-lease-watchdog.service | grep -qx yes && systemctl show -p CapabilityBoundingSet --value run-lease-watchdog.service | grep -q cap_kill && test ! -e /run/secure-sandbox/run-lease.json"
check "Execution broker is the only Research identity admitted to Target TCP/8080" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "broker_uid=\$(id -u execution-broker); nft list chain inet filter output | grep -q \"meta skuid \$broker_uid.*172.30.20.2.*tcp dport 8080\" && runuser -u execution-broker -- curl -fsS --max-time 3 http://172.30.20.2:8080/healthz | grep -q status"
check "Disposable execution Target is rootless, fixed-image, and shell-free" remote sandbox-target-admin \
  "systemctl --user is-active --quiet secure-sandbox-execution.service && image=\$(jq -r .image_id /home/labadmin/.config/secure-sandbox-execution.json) && test \"\$(DOCKER_HOST=unix:///run/user/1000/docker.sock docker image inspect --format '{{.Id}}' \"\$image\")\" = \"\$image\" && test \"\$(DOCKER_HOST=unix:///run/user/1000/docker.sock docker image inspect --format '{{.Config.User}} {{.Config.WorkingDir}} {{index .Config.Labels \"org.securesandbox.runtime\"}}' \"\$image\")\" = '65532:65532 /work python-fixture-v1' && ! DOCKER_HOST=unix:///run/user/1000/docker.sock docker run --rm --network none --entrypoint /bin/sh \"\$image\" -c true >/dev/null 2>&1"
check "Source acquisition components are installed with protected state" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "test -x /usr/local/libexec/secure-sandbox/source_controller.py && test -x /usr/local/libexec/secure-sandbox/source_fetcher.py && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition)\" = root:source-fetcher:750 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition/plans)\" = root:source-fetcher:2750 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition/spool)\" = source-fetcher:source-fetcher:700"
check "Research source importer is root-only and repository index is immutable to agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test -x /usr/local/libexec/secure-sandbox/source_importer.py && test -x /usr/local/sbin/secure-sandbox-source-import && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/source-acquisition)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/repos/INDEX.json)\" = root:root:444 && ! sudo -u agent test -w /home/agent/research-workspace/repos/INDEX.json && ! sudo -u agent /usr/local/libexec/secure-sandbox/source_importer.py publish 00000000-0000-4000-8000-000000000000 >/dev/null 2>&1"
check "Dependency orchestration is root-only and published bundles are immutable to agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/dependency_orchestrator.py)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/dependency-orchestration)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/dependency-orchestration/plans)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/dependency-orchestration/transactions)\" = root:root:700 && test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/dependency-bundles)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/dependency-bundles/INDEX.json)\" = root:root:444 && ! sudo -u agent test -w /home/agent/research-workspace/dependency-bundles && ! sudo -u agent /usr/local/libexec/secure-sandbox/dependency_orchestrator.py plan 00000000-0000-4000-8000-000000000000 >/dev/null 2>&1"
check "Corpus intelligence binaries and index directory are root-controlled" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/corpus-indexes)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/corpus_intelligence.py)\" = root:root:755 && test \"\$(stat -c '%U:%G:%a' /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py)\" = root:root:755 && ! sudo -u agent test -w /home/agent/research-workspace/corpus-indexes && ! sudo -u agent /usr/local/libexec/secure-sandbox/corpus_intelligence.py index 00000000-0000-4000-8000-000000000000 >/dev/null 2>&1"
check "Evidence receipts are producer-minted and hidden from the agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/evidence_receipts.py | grep -q ^$approved_receipts_hash && sha256sum /usr/local/libexec/secure-sandbox/corpus_broker.py | grep -q ^$approved_corpus_broker_hash && sha256sum /etc/systemd/system/corpus-broker.service | grep -q ^$approved_corpus_broker_unit_hash && sha256sum /usr/local/libexec/secure-sandbox/corpus_intelligence_mcp.py | grep -q ^$approved_corpus_mcp_hash && sha256sum /usr/local/libexec/secure-sandbox/execution_broker.py | grep -q ^$approved_execution_broker_hash && sha256sum /etc/systemd/system/execution-broker.service | grep -q ^$approved_execution_unit_hash && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts)\" = root:evidence-receipts:750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts/corpus)\" = corpus-broker:evidence-receipts:2750 && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/evidence-receipts/execution)\" = execution-broker:evidence-receipts:2750 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox-corpus/corpus.sock)\" = corpus-broker:agent:660 && sudo -u agent test -w /run/secure-sandbox-corpus/corpus.sock && ! sudo -u agent test -r /var/lib/secure-sandbox/evidence-receipts && sudo -u corpus-broker test -w /var/lib/secure-sandbox/evidence-receipts/corpus && ! sudo -u corpus-broker test -w /var/lib/secure-sandbox/evidence-receipts/execution && sudo -u execution-broker test -w /var/lib/secure-sandbox/evidence-receipts/execution && ! sudo -u execution-broker test -w /var/lib/secure-sandbox/evidence-receipts/corpus"
check "Receipt brokers use the approved fair bounded socket server" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/bounded_unix_server.py | grep -q ^$approved_bounded_server_hash"
check "CodeGraph manifests are root-controlled and immutable to the agent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(stat -c '%U:%G:%a' /home/agent/research-workspace/codegraph-indexes)\" = root:root:755 && ! sudo -u agent test -w /home/agent/research-workspace/codegraph-indexes && for marker in /home/agent/research-workspace/codegraph-indexes/*.json; do if ! test -e \"\$marker\"; then ! test -L \"\$marker\" || exit 1; continue; fi; test -f \"\$marker\" && ! test -L \"\$marker\" && test \"\$(stat -c %U:%G:%a \"\$marker\")\" = root:root:444 && ! sudo -u agent test -w \"\$marker\" || exit 1; done"
check "Memory proposals are bounded, brokered, and non-authoritative" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/memory_proposal.py | grep -q ^$approved_memory_broker_hash && sha256sum /usr/local/libexec/secure-sandbox/memory_proposal_mcp.py | grep -q ^$approved_memory_mcp_hash && sha256sum /etc/systemd/system/memory-proposal.service | grep -q ^$approved_memory_unit_hash && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/memory-proposals)\" = memory-proposal:agent:700 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox-memory/memory-proposal.sock)\" = memory-proposal:agent:660 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox)\" = root:conversation-shipper:755 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox/run-id)\" = root:root:644 && sudo -u agent test -w /run/secure-sandbox-memory/memory-proposal.sock && ! sudo -u agent test -r /var/lib/secure-sandbox/memory-proposals && ! test -e /home/agent/.claude/projects/-home-agent-research-workspace/memory && ! test -e /home/agent/research-workspace/CLAUDE.md && ! test -e /home/agent/CLAUDE.md && ! test -e /home/agent/.claude/CLAUDE.md"
check "Candidate findings are brokered and adjudication remains root-only" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/findings_broker.py | grep -q ^$approved_findings_broker_hash && sha256sum /usr/local/libexec/secure-sandbox/findings_mcp.py | grep -q ^$approved_findings_mcp_hash && sha256sum /usr/local/libexec/secure-sandbox/finding_admin.py | grep -q ^$approved_finding_admin_hash && sha256sum /etc/systemd/system/findings-broker.service | grep -q ^$approved_findings_unit_hash && test \"\$(stat -c %U:%G:%a /var/lib/secure-sandbox/findings)\" = findings-broker:agent:700 && test \"\$(stat -c %U:%G:%a /run/secure-sandbox-findings/findings.sock)\" = findings-broker:agent:660 && sudo -u agent test -w /run/secure-sandbox-findings/findings.sock && ! sudo -u agent test -r /var/lib/secure-sandbox/findings && ! sudo -u agent /usr/local/libexec/secure-sandbox/finding_admin.py list >/dev/null 2>&1"
check "Gateway services wait for restricted network interfaces" remote sandbox-gateway \
  "systemctl show -p After --value model-broker.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value model-broker.service | grep -q sys-subsystem-net-devices-uplink0.device && systemctl show -p After --value telemetry-receiver.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value conversation-receiver.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value azure-shipper.service | grep -q sys-subsystem-net-devices-uplink0.device && systemctl show -p After --value conversation-azure-shipper.service | grep -q sys-subsystem-net-devices-uplink0.device"
check "Research services wait for the restricted control interface" remote sandbox-research-admin \
  "systemctl show -p After --value claude-relay.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value telemetry-exporter.service | grep -q sys-subsystem-net-devices-ctl0.device && systemctl show -p After --value conversation-shipper.service | grep -q sys-subsystem-net-devices-ctl0.device"
check "Artifact collector is networkless and isolated from writable agent state" remote sandbox-research-admin \
  "systemctl show -p PrivateNetwork --value artifact-collector.service | grep -qx yes && systemctl show -p ProtectSystem --value artifact-collector.service | grep -qx strict && test \"\$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/artifact-capture)\" = root:root:700 && ! sudo -u agent test -r /var/lib/secure-sandbox/artifact-capture/state.json"
check "Claude tool auditor is networkless and read-only" remote sandbox-research-admin \
  "systemctl show -p PrivateNetwork --value claude-tool-auditor.service | grep -qx yes && systemctl show -p ProtectSystem --value claude-tool-auditor.service | grep -qx strict && systemctl show -p ReadWritePaths --value claude-tool-auditor.service | grep -q /var/lib/secure-sandbox/tool-auditor"
check "Conversation collector is networkless and fail-closed" remote sandbox-research-admin \
  "systemctl show -p PrivateNetwork --value conversation-capture.service | grep -qx yes && systemctl show -p ProtectSystem --value conversation-capture.service | grep -qx strict && systemctl show -p CapabilityBoundingSet --value conversation-capture.service | grep -q cap_kill"
check "Gateway kernel policy is default-drop and non-forwarding" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "test \"\$(nft list ruleset | grep -c \"policy drop\")\" -eq 3 && test \"\$(sysctl -n net.ipv4.ip_forward)\" -eq 0 && test \"\$(sysctl -n kernel.io_uring_disabled)\" -eq 2 && nft list chain inet filter output | grep -q 'meta skuid.*source-fetcher.*tcp dport 443'"
check "Research kernel policy is default-drop and non-forwarding" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "test \"\$(nft list ruleset | grep -c \"policy drop\")\" -eq 3 && test \"\$(sysctl -n net.ipv4.ip_forward)\" -eq 0 && test \"\$(sysctl -n kernel.io_uring_disabled)\" -eq 2 && nft list chain inet filter output | grep -q \"meta skuid.*tcp dport 8443\" && nft list chain inet filter output | grep -q \"meta skuid.*tcp dport 9443\" && nft list chain inet filter output | grep -q \"meta skuid.*tcp dport 9553\""
check "Target kernel policy is default-drop and non-forwarding" sudo_remote SecureSandbox-Target sandbox-target-admin \
  "test \"\$(nft list ruleset | grep -c \"policy drop\")\" -eq 3 && test \"\$(sysctl -n net.ipv4.ip_forward)\" -eq 0 && test \"\$(sysctl -n kernel.io_uring_disabled)\" -eq 2"
check "Gateway runtime DNS is disabled" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "systemctl is-enabled systemd-resolved.service | grep -q masked && test ! -s /etc/resolv.conf"
check "Research runtime DNS is disabled" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "systemctl is-enabled systemd-resolved.service | grep -q masked && test ! -s /etc/resolv.conf"
check "Target runtime DNS is disabled" sudo_remote SecureSandbox-Target sandbox-target-admin \
  "systemctl is-enabled systemd-resolved.service | grep -q masked && test ! -s /etc/resolv.conf"
check "Gateway CA and server certificate have more than 48 hours remaining" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/pki/ca.crt && openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/pki/server.crt"
check "Research client certificates have more than 48 hours remaining" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/relay/client.crt && openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/telemetry/client.crt && openssl x509 -checkend 172800 -noout -in /etc/secure-sandbox/conversation-transport/client.crt"
check "Gateway PKI generation is source-pinned, active, and internally consistent" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "sha256sum /usr/local/libexec/secure-sandbox/pki_lifecycle.py | grep -q ^$approved_pki_lifecycle_hash && sha256sum /usr/local/libexec/secure-sandbox/pki_generation.py | grep -q ^$approved_gateway_pki_hash && sha256sum /etc/systemd/system/pki-expiry-check.service | grep -q ^$approved_pki_expiry_service_hash && sha256sum /etc/systemd/system/pki-expiry-check.timer | grep -q ^$approved_pki_expiry_timer_hash && systemctl is-active --quiet pki-expiry-check.timer && /usr/local/libexec/secure-sandbox/pki_generation.py verify >/dev/null"
check "Research PKI generation is source-pinned, active, and internally consistent" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "sha256sum /usr/local/libexec/secure-sandbox/pki_lifecycle.py | grep -q ^$approved_pki_lifecycle_hash && sha256sum /usr/local/libexec/secure-sandbox/pki_guest_helpers.py | grep -q ^$approved_pki_helpers_hash && sha256sum /usr/local/libexec/secure-sandbox/pki_generation.py | grep -q ^$approved_research_pki_hash && sha256sum /etc/systemd/system/pki-expiry-check.service | grep -q ^$approved_pki_expiry_service_hash && sha256sum /etc/systemd/system/pki-expiry-check.timer | grep -q ^$approved_pki_expiry_timer_hash && systemctl is-active --quiet pki-expiry-check.timer && /usr/local/libexec/secure-sandbox/pki_generation.py verify >/dev/null"
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
check "Active PKI generation emitted content-free expiry evidence" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "generation=\$(jq -r .generation_id /etc/secure-sandbox/pki-generation.json) && jq -e --arg generation \"\$generation\" \"select((.EventType | startswith(\\\"pki_\\\")) and .RequestId == \\\$generation)\" /var/lib/secure-sandbox/telemetry/current.jsonl >/dev/null"
check "Research agent and execution-broker network syscalls are audited" sudo_remote SecureSandbox-Research sandbox-research-admin \
  "auditctl -l | grep -q \"connect,sendto,sendmsg,sendmmsg.*uid=1001.*key=agent-network\" && broker_uid=\$(id -u execution-broker) && auditctl -l | grep -q \"connect,sendto,sendmsg,sendmmsg.*uid=\$broker_uid.*key=execution-network\""
check "Unrouted egress attempts reached the metadata spool" sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "grep -q \"\\\"EventType\\\":\\\"network_connect_unapproved\\\"\" /var/lib/secure-sandbox/telemetry/current.jsonl"
check "Gateway has no failed systemd unit" remote sandbox-gateway "test -z \"\$(systemctl --failed --no-legend)\""
check "Research has no failed systemd unit" remote sandbox-research-admin "test -z \"\$(systemctl --failed --no-legend)\""
check "Target has no failed systemd unit" remote sandbox-target-admin "test -z \"\$(systemctl --failed --no-legend)\""

broker_mode="$(sudo_remote SecureSandbox-Gateway sandbox-gateway \
  "jq -r .mode /etc/secure-sandbox/broker.json" 2>/dev/null || print unknown)"
[[ "$broker_mode" == production ]] && pass "model broker is in production mode" || gate "model broker remains in safe mock mode"
remote sandbox-gateway "systemctl is-active --quiet azure-shipper" >/dev/null 2>&1 \
  && pass "Azure off-host shipper is active" || gate "Azure off-host shipper awaits cloud deployment"
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
if remote sandbox-research \
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
