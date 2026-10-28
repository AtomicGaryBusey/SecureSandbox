#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
collector="${1:-/tmp/artifact_collector.py}"
collector_unit="${2:-/tmp/artifact-collector.service}"
failure_unit="${3:-/tmp/artifact-capture-failure.service}"
watchdog="${4:-/tmp/run_lease_watchdog.py}"
for source in "$collector" "$collector_unit" "$failure_unit" "$watchdog"; do
  [[ -f "$source" ]] || { echo "Missing $source" >&2; exit 2; }
done
getent group conversation-shipper >/dev/null || { echo "conversation-shipper group is missing" >&2; exit 2; }
id agent >/dev/null 2>&1 || { echo "agent user is missing" >&2; exit 2; }
[[ -f /etc/secure-sandbox/conversation-recipient.txt ]] || { echo "age recipient is missing" >&2; exit 2; }
[[ -x /usr/local/bin/age ]] || { echo "age is missing" >&2; exit 2; }
install -d -o agent -g agent -m 700 /home/agent/.claude /home/agent/.claude/projects
test "$(stat -c %U:%G:%a /home/agent/.claude/projects)" = agent:agent:700
install -d -o agent -g agent -m 750 /home/agent/research-workspace
install -d -o agent -g agent -m 700 /home/agent/research-workspace/reports
install -d -o root -g root -m 700 /var/lib/secure-sandbox/artifact-capture
install -d -o root -g conversation-shipper -m 2770 /var/lib/secure-sandbox/conversation-outbox
install -o root -g root -m 755 "$collector" /usr/local/libexec/secure-sandbox/artifact_collector.py
install -o root -g root -m 755 "$watchdog" /usr/local/libexec/secure-sandbox/run_lease_watchdog.py
install -o root -g root -m 644 "$collector_unit" /etc/systemd/system/artifact-collector.service
install -o root -g root -m 644 "$failure_unit" /etc/systemd/system/artifact-capture-failure.service
python3 -m py_compile /usr/local/libexec/secure-sandbox/artifact_collector.py \
  /usr/local/libexec/secure-sandbox/run_lease_watchdog.py
systemd-analyze verify /etc/systemd/system/artifact-collector.service /etc/systemd/system/artifact-capture-failure.service >/dev/null
systemctl daemon-reload
systemctl enable --now artifact-collector.service
for _ in $(seq 1 20); do
  [[ -f /run/secure-sandbox/artifact-capture-ready ]] && break
  sleep 0.25
done
systemctl is-active --quiet artifact-collector.service
test -f /run/secure-sandbox/artifact-capture-ready
test ! -e /run/secure-sandbox/artifact-capture-fatal
systemctl reset-failed artifact-capture-failure.service >/dev/null 2>&1 || true
echo artifact-collector:active
