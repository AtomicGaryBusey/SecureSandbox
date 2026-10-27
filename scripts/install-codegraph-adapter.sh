#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Research." >&2; exit 1; }
archive="${1:-/tmp/codegraph-linux-arm64.tar.gz}"
runner="${2:-/tmp/codegraph_runner.cjs}"
adapter="${3:-/tmp/codegraph_adapter.py}"
service_code="${4:-/tmp/codegraph_query_service.py}"
indexer="${5:-/tmp/codegraph_indexer.py}"
unit="${6:-/tmp/codegraph-query.service}"
corpus="${7:-/tmp/corpus_intelligence.py}"
bounded_server="${8:-/tmp/bounded_unix_server.py}"
for source in "$archive" "$runner" "$adapter" "$service_code" "$indexer" "$unit" "$corpus" "$bounded_server"; do
  [[ -f "$source" && ! -L "$source" ]] || { echo "Missing deployment artifact: $source" >&2; exit 2; }
done
[[ ! -e /run/secure-sandbox/run-id && ! -e /run/secure-sandbox/evidence-run-id && ! -e /var/lib/secure-sandbox/run-lifecycle/active.json && ! -e /var/lib/secure-sandbox/run-lifecycle/failure-latched.json ]] || { echo "active or unreconciled agent run" >&2; exit 1; }
! pgrep -x claude >/dev/null || { echo "Claude Code is running" >&2; exit 1; }
expected=d75e7f0f7b754443ae01a02643df2af46e281f6dc4abd3fb272f01281113b528
[[ "$(sha256sum "$archive" | awk '{print $1}')" == "$expected" ]] || { echo "CodeGraph bundle hash mismatch" >&2; exit 1; }
python3 -m py_compile "$adapter" "$service_code" "$indexer" "$corpus"
node_count="$(tar -tzf "$archive" | awk '$0=="codegraph-linux-arm64/node"{n++} END{print n+0}')"
[[ "$node_count" == 1 ]] || { echo "Invalid CodeGraph bundle layout" >&2; exit 1; }
if tar -tzf "$archive" | grep -Eq '(^|/)(\.\.?)(/|$)|^/'; then echo "Unsafe CodeGraph bundle path" >&2; exit 1; fi

getent group codegraph-runtime >/dev/null || groupadd --system codegraph-runtime
getent group codegraph-client >/dev/null || groupadd --system codegraph-client
id codegraph-indexer >/dev/null 2>&1 || useradd --system --gid codegraph-runtime --home-dir /nonexistent --shell /usr/sbin/nologin codegraph-indexer
id codegraph-query >/dev/null 2>&1 || useradd --system --gid codegraph-runtime --home-dir /nonexistent --shell /usr/sbin/nologin codegraph-query
usermod -a -G codegraph-client agent

backup_id="codegraph-adapter-$(date -u +%Y%m%dT%H%M%SZ)-$$"
backup="/var/lib/secure-sandbox/policy-backups/$backup_id"
install -d -o root -g root -m 700 /var/lib/secure-sandbox/policy-backups "$backup"
for current in \
  /usr/local/libexec/secure-sandbox/codegraph_runner.cjs \
  /usr/local/libexec/secure-sandbox/codegraph_adapter.py \
  /usr/local/libexec/secure-sandbox/codegraph_query_service.py \
  /usr/local/libexec/secure-sandbox/codegraph_indexer.py \
  /usr/local/libexec/secure-sandbox/corpus_intelligence.py \
  /usr/local/libexec/secure-sandbox/bounded_unix_server.py \
  /etc/systemd/system/codegraph-query.service; do
  name="$(basename "$current")"
  if [[ -f "$current" && ! -L "$current" ]]; then cp --no-dereference "$current" "$backup/$name"; else : > "$backup/$name.absent"; fi
done
if [[ -d /opt/secure-sandbox/codegraph ]]; then mv /opt/secure-sandbox/codegraph "$backup/codegraph"; fi

staging="/opt/secure-sandbox/.codegraph-new-$$"
install -d -o root -g root -m 755 /opt/secure-sandbox "$staging"
trap 'rm -rf "$staging"' EXIT
tar -xzf "$archive" --strip-components=1 -C "$staging" --no-same-owner --no-same-permissions
chown -R root:codegraph-runtime "$staging"
find "$staging" -type d -exec chmod 550 {} +
find "$staging" -type f -exec chmod 440 {} +
chmod 550 "$staging/node" "$staging/bin/codegraph"
mv "$staging" /opt/secure-sandbox/codegraph
trap - EXIT

install -d -o root -g root -m 755 /usr/local/libexec/secure-sandbox /home/agent/research-workspace/codegraph-indexes
install -d -o root -g root -m 755 /var/lib/secure-sandbox/codegraph-builds /var/lib/secure-sandbox/codegraph-indexes
install -o root -g root -m 644 "$runner" /usr/local/libexec/secure-sandbox/codegraph_runner.cjs
install -o root -g root -m 644 "$adapter" /usr/local/libexec/secure-sandbox/codegraph_adapter.py
install -o root -g root -m 755 "$service_code" /usr/local/libexec/secure-sandbox/codegraph_query_service.py
install -o root -g root -m 755 "$bounded_server" /usr/local/libexec/secure-sandbox/bounded_unix_server.py
install -o root -g root -m 755 "$indexer" /usr/local/libexec/secure-sandbox/codegraph_indexer.py
install -o root -g root -m 755 "$corpus" /usr/local/libexec/secure-sandbox/corpus_intelligence.py
install -o root -g root -m 644 "$unit" /etc/systemd/system/codegraph-query.service
rm -f -- /etc/sudoers.d/secure-sandbox-codegraph
visudo -c >/dev/null
systemctl daemon-reload
systemctl enable codegraph-query.service
systemctl restart codegraph-query.service
systemctl is-active --quiet codegraph-query.service
if [[ -x /usr/local/libexec/secure-sandbox/update-policy-hash.sh ]]; then /usr/local/libexec/secure-sandbox/update-policy-hash.sh research >/dev/null; fi
printf '%s\n' "$backup_id" > /var/lib/secure-sandbox/policy-backups/codegraph-adapter-latest
chmod 600 /var/lib/secure-sandbox/policy-backups/codegraph-adapter-latest
echo "codegraph-adapter:installed:$backup_id"
