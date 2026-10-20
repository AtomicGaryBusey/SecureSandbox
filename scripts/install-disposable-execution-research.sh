#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
[[ ! -e /run/secure-sandbox/run-id ]] || { echo "active agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
broker="${1:-/tmp/execution_broker.py}"; mcp="${2:-/tmp/execution_mcp.py}"
unit="${3:-/tmp/execution-broker.service}"; token_file="${4:-/tmp/execution-token}"
settings="${5:-/tmp/managed-settings.proposed.json}"; managed_mcp="${6:-/tmp/managed-mcp.json}"
firewall="${7:-/tmp/render_research_firewall.py}"; telemetry="${8:-/tmp/telemetry_exporter.py}"
for path in "$broker" "$mcp" "$unit" "$token_file" "$settings" "$managed_mcp" "$firewall" "$telemetry"; do
  [[ -f "$path" && ! -L "$path" ]] || { echo "Missing artifact: $path" >&2; exit 2; }
done
python3 -m py_compile "$broker" "$mcp" "$firewall" "$telemetry"
python3 -m json.tool "$settings" >/dev/null; python3 -m json.tool "$managed_mcp" >/dev/null
token="$(tr -d '\r\n' < "$token_file")"; [[ "$token" =~ ^[A-Za-z0-9]{64}$ ]] || { echo "Invalid execution token." >&2; exit 2; }
getent passwd execution-broker >/dev/null || useradd --system --home /nonexistent --shell /usr/sbin/nologin execution-broker
usermod -a -G agent execution-broker
broker_uid="$(id -u execution-broker)"
chown agent:agent /home/agent/research-workspace
chmod 750 /home/agent/research-workspace

backup_id="disposable-execution-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 "$backup"
for current in /etc/claude-code/managed-settings.json /etc/claude-code/managed-mcp.json /etc/nftables.conf /usr/local/libexec/secure-sandbox/telemetry_exporter.py; do
  cp --no-dereference "$current" "$backup/$(basename "$current")"
done

install -d -o root -g root -m 755 /etc/secure-sandbox /usr/local/libexec/secure-sandbox
install -o root -g root -m 755 "$broker" /usr/local/libexec/secure-sandbox/execution_broker.py
install -o root -g root -m 755 "$mcp" /usr/local/libexec/secure-sandbox/execution_mcp.py
install -o root -g root -m 755 "$firewall" /usr/local/libexec/secure-sandbox/render_research_firewall.py
install -o root -g root -m 755 "$telemetry" /usr/local/libexec/secure-sandbox/telemetry_exporter.py
install -o root -g root -m 644 "$unit" /etc/systemd/system/execution-broker.service
install -o root -g root -m 644 "$settings" /etc/claude-code/managed-settings.json
install -o root -g root -m 644 "$managed_mcp" /etc/claude-code/managed-mcp.json
config_tmp="$(mktemp /tmp/secure-sandbox-execution-broker-config.XXXXXX)"
trap 'rm -f -- "$config_tmp"' EXIT
jq -n --arg token "$token" '{schema:"secure-sandbox-execution-broker-v1",token:$token}' \
  > "$config_tmp"
install -o root -g execution-broker -m 640 "$config_tmp" /etc/secure-sandbox/execution-broker.json
rm -f "$token_file"
printf '%s\n' "-a always,exit -F arch=b64 -S connect,sendto,sendmsg,sendmmsg -F uid=$broker_uid -k execution-network" \
  > /etc/audit/rules.d/51-secure-sandbox-execution.rules
chmod 600 /etc/audit/rules.d/51-secure-sandbox-execution.rules
/usr/local/libexec/secure-sandbox/render_research_firewall.py --output /etc/nftables.conf
nft -c -f /etc/nftables.conf; nft -f /etc/nftables.conf
augenrules --load >/dev/null
systemctl daemon-reload
systemctl enable execution-broker.service
systemctl restart execution-broker.service
systemctl restart telemetry-exporter.service
systemctl is-active --quiet execution-broker.service telemetry-exporter.service
echo "disposable-execution-research:installed:$backup_id"
