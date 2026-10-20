#!/bin/zsh
set -euo pipefail

root_dir="${0:A:h:h}"
ssh_config="$root_dir/config/ssh_config"
[[ "${SECURE_SANDBOX_COORDINATION_LOCK_HELD:-}" = 1 ]] || {
  print -u2 'Run through: python3 scripts/pki-operation.py rotate [generation-id]'
  exit 1
}
requested_generation="${1:-}"
exchange="$(mktemp -d /tmp/secure-sandbox-pki-v2.XXXXXX)"
trap 'rm -rf -- "$exchange"' EXIT HUP INT TERM
umask 077

gateway_root='/usr/local/libexec/secure-sandbox'
research_root='/usr/local/libexec/secure-sandbox'

sudo_gateway() {
  op-agents read 'op://Agents/SecureSandbox-Gateway/password' \
    | ssh -F "$ssh_config" -o BatchMode=yes sandbox-gateway "sudo -S -p '' /bin/sh -c '$1'"
}
sudo_research() {
  op-agents read 'op://Agents/SecureSandbox-Research/password' \
    | ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin "sudo -S -p '' /bin/sh -c '$1'"
}
probe_paths() {
  ssh -F "$ssh_config" sandbox-research 'curl -fsS --retry 10 --retry-connrefused --retry-delay 1 --retry-max-time 10 --max-time 5 http://127.0.0.1:18080/healthz >/dev/null'
  sudo_research "/usr/sbin/runuser -u telemetry-exporter -- /usr/local/libexec/secure-sandbox/telemetry_exporter.py --health"
  sudo_research "/usr/sbin/runuser -u conversation-shipper -- /usr/local/libexec/secure-sandbox/conversation_shipper.py --health"
}

"$root_dir/scripts/sync-lab-time.sh" --check
active_run="$(ssh -F "$ssh_config" -o BatchMode=yes sandbox-research-admin 'if test -f /run/secure-sandbox/run-id; then cat /run/secure-sandbox/run-id; fi')"
[[ -z "$active_run" ]] || { print -u2 "Refusing PKI rotation while Claude run $active_run is active."; exit 1; }

anchor=/usr/local/libexec/secure-sandbox-host/current/pki_anchor
if [[ ! -x "$anchor" ]]; then
  print -u2 'The repaired host-controller release containing pki_anchor is not deployed.'
  exit 1
fi
pending_generation="$("$anchor" pending 2>/dev/null | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["generation_id"])' 2>/dev/null || true)"
if [[ -n "$requested_generation" && -n "$pending_generation" && "$requested_generation" != "$pending_generation" ]]; then
  print -u2 "A different PKI generation is pending: $pending_generation"
  exit 1
fi
generation="${requested_generation:-${pending_generation:-$(uuidgen | tr '[:upper:]' '[:lower:]')}}"
if [[ ! "$generation" =~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' ]]; then
  print -u2 'Invalid generation UUIDv4.'
  exit 2
fi
admin_anchor() {
  local command="$anchor"
  local argument
  for argument in "$@"; do
    [[ "$argument" = begin || "$argument" = commit || "$argument" = --expected-current \
        || "$argument" =~ '^[0-9a-f-]+$' ]] || {
      print -u2 'Invalid host-anchor argument.'
      return 2
    }
    command="$command $argument"
  done
  /usr/bin/osascript -e "do shell script \"$command\" with administrator privileges"
}
admin_anchor begin "$generation" >/dev/null
remote_exchange="/tmp/secure-sandbox-pki-$generation"

print "PKI generation: $generation"
sudo_research "$research_root/pki_generation.py prepare $generation"
sudo_gateway "$gateway_root/pki_generation.py prepare $generation"

# Public exchange artifacts only. Private keys remain inside each root-only
# generation directory and are never copied through /tmp or the host.
ssh -F "$ssh_config" sandbox-research-admin "rm -rf '$remote_exchange'; install -d -m 700 '$remote_exchange'"
sudo_research "for role in broker telemetry conversation; do install -o root -g root -m 644 /var/lib/secure-sandbox/pki-lifecycle/generations/$generation/\$role.csr '$remote_exchange'/\$role.csr; done"
scp -F "$ssh_config" "sandbox-research-admin:$remote_exchange/broker.csr" "sandbox-research-admin:$remote_exchange/telemetry.csr" "sandbox-research-admin:$remote_exchange/conversation.csr" "$exchange/"
ssh -F "$ssh_config" sandbox-gateway "rm -rf '$remote_exchange'; install -d -m 700 '$remote_exchange'"
scp -F "$ssh_config" "$exchange/broker.csr" "$exchange/telemetry.csr" "$exchange/conversation.csr" sandbox-gateway:"$remote_exchange/"
sudo_gateway "chown root:root '$remote_exchange'/*.csr; chmod 444 '$remote_exchange'/*.csr; $gateway_root/pki_generation.py sign $generation --broker-csr '$remote_exchange/broker.csr' --telemetry-csr '$remote_exchange/telemetry.csr' --conversation-csr '$remote_exchange/conversation.csr'; for item in ca.crt broker.crt telemetry.crt conversation.crt manifest.json; do install -o root -g root -m 644 /var/lib/secure-sandbox/pki-lifecycle/generations/$generation/\$item '$remote_exchange'/\$item; done"
scp -F "$ssh_config" "sandbox-gateway:$remote_exchange/ca.crt" "sandbox-gateway:$remote_exchange/broker.crt" "sandbox-gateway:$remote_exchange/telemetry.crt" "sandbox-gateway:$remote_exchange/conversation.crt" "sandbox-gateway:$remote_exchange/manifest.json" "$exchange/"
scp -F "$ssh_config" "$exchange/ca.crt" "$exchange/broker.crt" "$exchange/telemetry.crt" "$exchange/conversation.crt" "$exchange/manifest.json" sandbox-research-admin:"$remote_exchange/"
sudo_research "chown root:root '$remote_exchange'/ca.crt '$remote_exchange'/broker.crt '$remote_exchange'/telemetry.crt '$remote_exchange'/conversation.crt '$remote_exchange'/manifest.json; chmod 444 '$remote_exchange'/ca.crt '$remote_exchange'/broker.crt '$remote_exchange'/telemetry.crt '$remote_exchange'/conversation.crt '$remote_exchange'/manifest.json; $research_root/pki_generation.py import-signed $generation --ca '$remote_exchange/ca.crt' --manifest '$remote_exchange/manifest.json' --broker-cert '$remote_exchange/broker.crt' --telemetry-cert '$remote_exchange/telemetry.crt' --conversation-cert '$remote_exchange/conversation.crt'"

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
