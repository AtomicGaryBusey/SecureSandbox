#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
ssh_config="/usr/local/libexec/secure-sandbox-host/current/ssh_config"
state_root="${SECURE_SANDBOX_STATE_ROOT:-}"
coordination_parent="${SECURE_SANDBOX_COORDINATION_PARENT_PID:-}"
coordination_holder="${SECURE_SANDBOX_COORDINATION_HOLDER_PID:-}"
expected_state_root="$HOME/Library/Application Support/SecureSandbox/controller-state"
pid_file="$state_root/coordination.lock/pid"
[[ "$state_root" = "$expected_state_root" && "$coordination_parent" = "$PPID" \
    && "$coordination_holder" == <-> && -f "$pid_file" && ! -L "$pid_file" \
    && "$(< "$pid_file")" = "$coordination_holder" ]] || {
  print -u2 'Run through: python3 scripts/pki-operation.py rotate --requesting-agent NAME --requesting-session LABEL'
  exit 1
}
requested_generation="${1:-}"
pki_recovery="${SECURE_SANDBOX_PKI_RECOVERY:-0}"
[[ "$pki_recovery" = 0 || "$pki_recovery" = 1 ]] || {
  print -u2 'Invalid PKI recovery mode.'
  exit 2
}
if [[ -n "$requested_generation" && "$pki_recovery" != 1 ]]; then
  print -u2 'An explicit PKI generation requires recovery mode.'
  exit 2
fi
exchange="$(mktemp -d /tmp/secure-sandbox-pki-v2.XXXXXX)"
trap 'rm -rf -- "$exchange"' EXIT HUP INT TERM
umask 077

gateway_root='/usr/local/libexec/secure-sandbox'
research_root='/usr/local/libexec/secure-sandbox'

sudo_gateway() {
  control_root sandbox-gateway-control "$@"
}
sudo_research() {
  control_root sandbox-research-control "$@"
}
control_root() {
  local host="$1" command="$2" installer
  shift 2
  installer="$(mktemp /tmp/secure-sandbox-pki-operation.XXXXXX)"
  {
    print '#!/bin/bash'
    print 'set -euo pipefail'
    print -r -- "$command"
  } > "$installer"
  chmod 700 "$installer"
  local command_status=0
  "/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" "$host" \
    deploy install-pki-operation.sh --file "$installer:install-pki-operation.sh" "$@" \
    || command_status=$?
  rm -f -- "$installer"
  return "$command_status"
}
probe_paths() {
  sudo_research "/usr/sbin/runuser -u agent -- curl -fsS --retry 10 --retry-connrefused --retry-delay 1 --retry-max-time 10 --max-time 5 http://127.0.0.1:18080/healthz >/dev/null"
  sudo_research "/usr/sbin/runuser -u telemetry-exporter -- /usr/local/libexec/secure-sandbox/telemetry_exporter.py --health"
  sudo_research "/usr/sbin/runuser -u conversation-shipper -- /usr/local/libexec/secure-sandbox/conversation_shipper.py --health"
}

"$root_dir/scripts/sync-lab-time.sh" --check
"/usr/local/libexec/secure-sandbox-host/current/control_client" client --ssh-config "$ssh_config" \
  sandbox-research-control run lifecycle-idle >/dev/null

anchor=/usr/local/libexec/secure-sandbox-host/current/pki_anchor
authorization_broker=/usr/local/libexec/secure-sandbox-host/current/authorization_broker
if [[ ! -x "$anchor" ]]; then
  print -u2 'The repaired host-controller release containing pki_anchor is not deployed.'
  exit 1
fi
if [[ ! -x "$authorization_broker" || -z "${SECURE_SANDBOX_REQUESTING_AGENT:-}" \
    || -z "${SECURE_SANDBOX_REQUESTING_SESSION:-}" ]]; then
  print -u2 'Protected authorization broker or requesting-agent provenance is unavailable.'
  exit 1
fi
pending_generation="$("$anchor" pending 2>/dev/null | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["generation_id"])' 2>/dev/null || true)"
anchored_generation="$("$anchor" verify 2>/dev/null | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["generation_id"])' 2>/dev/null || true)"
if [[ -n "$requested_generation" && -n "$pending_generation" && "$requested_generation" != "$pending_generation" ]]; then
  print -u2 "A different PKI generation is pending: $pending_generation"
  exit 1
fi
generation="${requested_generation:-${pending_generation:-$(uuidgen | tr '[:upper:]' '[:lower:]')}}"
if [[ ! "$generation" =~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' ]]; then
  print -u2 'Invalid generation UUIDv4.'
  exit 2
fi
if [[ "$pki_recovery" = 1 && "$generation" != "$pending_generation" \
    && "$generation" != "$anchored_generation" ]]; then
  print -u2 'PKI recovery generation is neither pending nor currently anchored.'
  exit 1
fi
admin_anchor() {
  local action="$1" parameters purpose
  shift
  case "$action" in
    begin)
      [[ "$#" = 1 ]] || return 2
      parameters="$(/usr/bin/python3 -c 'import json,sys; print(json.dumps({"generation_id":sys.argv[1]},separators=(",",":"),sort_keys=True))' "$1")"
      purpose="Begin host rollback protection for PKI generation $1"
      ;;
    commit)
      [[ "$#" = 2 || "$#" = 4 ]] || return 2
      local expected=''
      if [[ "$#" = 4 ]]; then
        [[ "$3" = --expected-current ]] || return 2
        expected="$4"
      fi
      parameters="$(/usr/bin/python3 -c 'import json,sys; print(json.dumps({"generation_id":sys.argv[1],"manifest_sha256":sys.argv[2],"expected_current":sys.argv[3] or None},separators=(",",":"),sort_keys=True))' "$1" "$2" "$expected")"
      purpose="Commit the verified PKI generation $1 to the host rollback anchor"
      ;;
    *) return 2 ;;
  esac
  "$authorization_broker" request \
    --agent "$SECURE_SANDBOX_REQUESTING_AGENT" \
    --session "$SECURE_SANDBOX_REQUESTING_SESSION" \
    --purpose "$purpose" \
    --resource '/usr/local/var/lib/secure-sandbox/pki' \
    --operation "pki-anchor-$action" \
    --parameters-json "$parameters"
}
admin_anchor begin "$generation" >/dev/null
remote_exchange="/var/lib/secure-sandbox/pki-exchange/$generation"

print "PKI generation: $generation"
sudo_research "$research_root/pki_generation.py prepare $generation"
sudo_gateway "$gateway_root/pki_generation.py prepare $generation"

# Public exchange artifacts only. Private keys remain inside each root-only
# generation directory and are never copied through /tmp or the host.
sudo_research "rm -rf '$remote_exchange'; install -d -o root -g root -m 755 '$remote_exchange'; for role in broker telemetry conversation; do install -o root -g root -m 644 /var/lib/secure-sandbox/pki-lifecycle/generations/$generation/\$role.csr '$remote_exchange'/\$role.csr; done"
scp -F "$ssh_config" "sandbox-research-admin:$remote_exchange/broker.csr" "sandbox-research-admin:$remote_exchange/telemetry.csr" "sandbox-research-admin:$remote_exchange/conversation.csr" "$exchange/"
sudo_gateway "rm -rf '$remote_exchange'; install -d -o root -g root -m 755 '$remote_exchange'; install -o root -g root -m 444 /tmp/broker.csr '$remote_exchange/broker.csr'; install -o root -g root -m 444 /tmp/telemetry.csr '$remote_exchange/telemetry.csr'; install -o root -g root -m 444 /tmp/conversation.csr '$remote_exchange/conversation.csr'; $gateway_root/pki_generation.py sign $generation --broker-csr '$remote_exchange/broker.csr' --telemetry-csr '$remote_exchange/telemetry.csr' --conversation-csr '$remote_exchange/conversation.csr'; for item in ca.crt broker.crt telemetry.crt conversation.crt manifest.json; do install -o root -g root -m 644 /var/lib/secure-sandbox/pki-lifecycle/generations/$generation/\$item '$remote_exchange'/\$item; done" \
  --file "$exchange/broker.csr" --file "$exchange/telemetry.csr" --file "$exchange/conversation.csr"
scp -F "$ssh_config" "sandbox-gateway:$remote_exchange/ca.crt" "sandbox-gateway:$remote_exchange/broker.crt" "sandbox-gateway:$remote_exchange/telemetry.crt" "sandbox-gateway:$remote_exchange/conversation.crt" "sandbox-gateway:$remote_exchange/manifest.json" "$exchange/"
sudo_research "install -o root -g root -m 444 /tmp/ca.crt '$remote_exchange/ca.crt'; install -o root -g root -m 444 /tmp/broker.crt '$remote_exchange/broker.crt'; install -o root -g root -m 444 /tmp/telemetry.crt '$remote_exchange/telemetry.crt'; install -o root -g root -m 444 /tmp/conversation.crt '$remote_exchange/conversation.crt'; install -o root -g root -m 444 /tmp/manifest.json '$remote_exchange/manifest.json'; $research_root/pki_generation.py import-signed $generation --ca '$remote_exchange/ca.crt' --manifest '$remote_exchange/manifest.json' --broker-cert '$remote_exchange/broker.crt' --telemetry-cert '$remote_exchange/telemetry.crt' --conversation-cert '$remote_exchange/conversation.crt'" \
  --file "$exchange/ca.crt" --file "$exchange/broker.crt" --file "$exchange/telemetry.crt" \
  --file "$exchange/conversation.crt" --file "$exchange/manifest.json"

# Each remote transition verifies its postcondition before journaling. The
# second journal is advanced only after the first side has returned success.
sudo_research "$research_root/pki_generation.py activate-dual-trust $generation"
probe_paths
sudo_gateway "$gateway_root/pki_lifecycle.py advance $generation prepared research_dual_trust"
sudo_gateway "$gateway_root/pki_generation.py activate-dual $generation"
probe_paths
sudo_research "$research_root/pki_lifecycle.py advance $generation research_dual_trust gateway_dual_trust"
sudo_research "$research_root/pki_generation.py activate-clients $generation"
probe_paths
sudo_gateway "$gateway_root/pki_lifecycle.py advance $generation gateway_dual_trust research_new_clients"
sudo_gateway "$gateway_root/pki_generation.py activate-new-only $generation"
probe_paths
sudo_research "$research_root/pki_lifecycle.py advance $generation research_new_clients gateway_new_only"
sudo_research "$research_root/pki_generation.py commit $generation"
probe_paths
sudo_gateway "$gateway_root/pki_generation.py commit $generation"
sudo_gateway "$gateway_root/pki_generation.py verify"
sudo_research "$research_root/pki_generation.py verify"
sudo_gateway "systemctl enable --now pki-expiry-check.timer >/dev/null; systemctl start pki-expiry-check.service; test \"\$(systemctl show -p Result --value pki-expiry-check.service)\" = success; systemctl is-active --quiet pki-expiry-check.timer"
sudo_research "systemctl enable --now pki-expiry-check.timer >/dev/null; systemctl start pki-expiry-check.service; test \"\$(systemctl show -p Result --value pki-expiry-check.service)\" = success; systemctl is-active --quiet pki-expiry-check.timer"

sudo_gateway "$gateway_root/update-policy-hash.sh gateway >/dev/null"
sudo_research "$research_root/update-policy-hash.sh research >/dev/null"
probe_paths

/usr/bin/python3 "$root_dir/scripts/pki_lifecycle.py" validate-manifest "$exchange/manifest.json" >/dev/null
declared_hash="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["manifest_sha256"])' "$exchange/manifest.json")"
# manifest_sha256 binds the canonical body without its own field; the host
# anchor intentionally records that declared semantic digest.
current="$("$anchor" verify 2>/dev/null | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["generation_id"])' 2>/dev/null || true)"
if [[ -n "$current" ]]; then
  admin_anchor commit "$generation" "$declared_hash" --expected-current "$current"
else
  admin_anchor commit "$generation" "$declared_hash"
fi

sudo_gateway "rm -rf '$remote_exchange'"
sudo_research "rm -rf '$remote_exchange'"
print "PKI generation committed and host-anchored: $generation"
