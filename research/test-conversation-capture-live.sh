#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
test ! -e /run/secure-sandbox/run-id
test ! -e /run/secure-sandbox/conversation-capture-fatal
run_id="$(cat /proc/sys/kernel/random/uuid)"
probe="/home/agent/.claude/projects/-home-agent-research-workspace/$run_id.jsonl"
cleanup() {
  /usr/local/libexec/secure-sandbox/manage_run_id.py clear "$run_id" >/dev/null 2>&1 || true
  rm -f "$probe"
}
trap cleanup EXIT HUP INT TERM

/usr/local/libexec/secure-sandbox/manage_run_id.py set "$run_id"
printf '%s\n%s' '{"type":"capture-probe","phase":1}' '{"type":"capture-probe","phase"' > "$probe"
chown agent:agent "$probe"
chmod 600 "$probe"
sleep 2
systemctl is-active --quiet conversation-capture.service
test ! -e /run/secure-sandbox/conversation-capture-fatal

printf '%s\n' ':2}' >> "$probe"
sleep 2
systemctl is-active --quiet conversation-capture.service
test ! -e /run/secure-sandbox/conversation-capture-fatal
journalctl --since '10 seconds ago' --no-pager -u conversation-capture.service \
  | grep -F conversation_chunk_captured | grep -F "$run_id" >/dev/null

printf '%s\n%s\n' 'not-json' '{"type":"capture-probe","phase":3}' >> "$probe"
sleep 2
systemctl is-active --quiet conversation-capture.service
test ! -e /run/secure-sandbox/conversation-capture-fatal
journalctl --since '10 seconds ago' --no-pager -u conversation-capture.service \
  | grep -F conversation_journal_record_wrapped | grep -F "$run_id" >/dev/null
echo conversation-capture-partial-write:passed
echo conversation-capture-corrupt-record-wrapper:passed
