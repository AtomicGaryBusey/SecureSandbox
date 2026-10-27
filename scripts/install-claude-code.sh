#!/bin/bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "This script must run as root on Research." >&2
  exit 1
fi

claude_source="${1:-/tmp/claude-2.1.300-linux-arm64}"
bubblewrap_source="${2:-/tmp/bubblewrap_0.11.1-1ubuntu0.3_arm64.deb}"
socat_source="${3:-/tmp/socat_1.8.1.1-1ubuntu0.1_arm64.deb}"
assembled_claude=""
if [[ -f "$claude_source" && "$claude_source" == *.gz ]]; then
  assembled_claude="$(mktemp /var/tmp/claude-2.1.300-linux-arm64.XXXXXX)"
  trap 'rm -f -- "$assembled_claude"' EXIT
  gzip -cd -- "$claude_source" > "$assembled_claude"
  chmod 0600 "$assembled_claude"
  claude_source="$assembled_claude"
elif [[ ! -f "$claude_source" ]]; then
  parts=(/tmp/claude-2.1.300-linux-arm64.part.00 /tmp/claude-2.1.300-linux-arm64.part.01 /tmp/claude-2.1.300-linux-arm64.part.02)
  for part in "${parts[@]}"; do
    [[ -f "$part" && ! -L "$part" ]] || { echo "Missing artifact: $part" >&2; exit 2; }
  done
  assembled_claude="$(mktemp /var/tmp/claude-2.1.300-linux-arm64.XXXXXX)"
  trap 'rm -f -- "$assembled_claude"' EXIT
  cat "${parts[@]}" > "$assembled_claude"
  chmod 0600 "$assembled_claude"
  claude_source="$assembled_claude"
fi

verify() {
  local expected="$1"
  local path="$2"
  [[ -f "$path" ]] || { echo "Missing artifact: $path" >&2; exit 2; }
  printf '%s  %s\n' "$expected" "$path" | sha256sum --check --status
}
verify ae2295ae2da156936bf5831ab01971ce924d0c9a0af174e28d96fffa8d5fa0a6 "$claude_source"
verify 739af54b7ff1199fb15e01b1dfd6869565b316a5bf4063ce2696162c934d2e03 "$bubblewrap_source"
verify c796502432803176662289cac6a3e29d6af0623b362a0fc569e3895324f6d9f2 "$socat_source"

dpkg --install "$bubblewrap_source" "$socat_source"
install -o root -g root -m 755 "$claude_source" /usr/local/bin/claude
id agent >/dev/null 2>&1 || { echo "agent account is missing" >&2; exit 2; }
install -d -o agent -g agent -m 700 /home/agent/.claude /home/agent/.claude/projects
test "$(stat -c %U:%G:%a /home/agent/.claude)" = agent:agent:700
test "$(stat -c %U:%G:%a /home/agent/.claude/projects)" = agent:agent:700
test "$(/usr/local/bin/claude --version)" = "2.1.300 (Claude Code)"

echo "claude-code:2.1.300-installed-unconfigured"
