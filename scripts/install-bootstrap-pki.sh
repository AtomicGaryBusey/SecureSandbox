#!/bin/bash
set -euo pipefail

action="${1:-}"
role_file=/etc/secure-sandbox/control-role
exchange=/var/lib/secure-sandbox/pki-exchange/bootstrap
[[ "$(id -u)" -eq 0 ]] || { echo "root_required" >&2; exit 1; }
[[ -f "$role_file" && ! -L "$role_file" ]] || { echo "role_file_invalid" >&2; exit 2; }
role="$(cat "$role_file")"

[[ -d /var/lib/secure-sandbox && ! -L /var/lib/secure-sandbox \
  && ! -L /var/lib/secure-sandbox/pki-exchange && ! -L "$exchange" ]] || {
  echo "exchange_path_invalid" >&2
  exit 2
}
install -d -o root -g root -m 0755 /var/lib/secure-sandbox/pki-exchange "$exchange"
[[ "$(stat -c '%U:%G:%a' /var/lib/secure-sandbox/pki-exchange)" == root:root:755 \
  && "$(stat -c '%U:%G:%a' "$exchange")" == root:root:755 ]] || {
  echo "exchange_path_invalid" >&2
  exit 2
}

require_private_key() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" && "$(stat -c %h "$path")" == 1 ]] \
    || { echo "private_key_invalid:$path" >&2; exit 2; }
  openssl pkey -in "$path" -noout >/dev/null 2>&1 \
    || { echo "private_key_invalid:$path" >&2; exit 2; }
}

publish_csr() {
  local key="$1"
  local subject="$2"
  local output="$3"
  local temporary
  require_private_key "$key"
  temporary="$(mktemp "$exchange/.csr.XXXXXX")"
  openssl req -new -key "$key" -out "$temporary" -subj "/CN=$subject"
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$output"
}

require_csr_subject() {
  local name="$1"
  local expected="$2"
  local path="/tmp/$name.csr"
  [[ -f "$path" && ! -L "$path" ]] || { echo "csr_missing:$name" >&2; exit 2; }
  [[ "$(openssl req -in "$path" -noout -subject -nameopt RFC2253)" == "subject=CN=$expected" ]] \
    || { echo "csr_subject_invalid:$name" >&2; exit 2; }
  openssl req -in "$path" -noout -verify >/dev/null 2>&1 \
    || { echo "csr_signature_invalid:$name" >&2; exit 2; }
}

same_public_key() {
  local key="$1"
  local certificate="$2"
  local key_public certificate_public result=0
  key_public="$(mktemp "$exchange/.key-public.XXXXXX")"
  certificate_public="$(mktemp "$exchange/.certificate-public.XXXXXX")"
  openssl pkey -in "$key" -pubout -out "$key_public" >/dev/null 2>&1 \
    && openssl x509 -in "$certificate" -pubkey -noout > "$certificate_public" \
    && cmp -s "$key_public" "$certificate_public" || result=$?
  rm -f -- "$key_public" "$certificate_public"
  return "$result"
}

same_private_key() {
  local first="$1"
  local second="$2"
  local first_public second_public result=0
  first_public="$(mktemp "$exchange/.first-key-public.XXXXXX")"
  second_public="$(mktemp "$exchange/.second-key-public.XXXXXX")"
  openssl pkey -in "$first" -pubout -out "$first_public" >/dev/null 2>&1 \
    && openssl pkey -in "$second" -pubout -out "$second_public" >/dev/null 2>&1 \
    && cmp -s "$first_public" "$second_public" || result=$?
  rm -f -- "$first_public" "$second_public"
  return "$result"
}

case "$action" in
  gateway-init)
    [[ "$role" == gateway ]] || { echo "role_mismatch" >&2; exit 2; }
    /bin/bash /tmp/init-gateway-broker-pki.sh
    ;;
  research-create)
    [[ "$role" == research ]] || { echo "role_mismatch" >&2; exit 2; }
    broker_key=/etc/secure-sandbox/relay/client.key
    broker_source_key=/home/agent/.config/secure-sandbox/client.key
    [[ ! -L "$broker_key" ]] || { echo "private_key_invalid:$broker_key" >&2; exit 2; }
    [[ ! -L "$broker_source_key" ]] || { echo "private_key_invalid:$broker_source_key" >&2; exit 2; }
    if [[ -e "$broker_key" && -e "$broker_source_key" ]]; then
      require_private_key "$broker_key"
      require_private_key "$broker_source_key"
      same_private_key "$broker_key" "$broker_source_key" \
        || { echo "broker_private_key_conflict" >&2; exit 2; }
    fi
    if [[ ! -e "$broker_key" ]]; then
      broker_key="$broker_source_key"
      if [[ ! -e "$broker_key" ]]; then
        [[ ! -e /etc/secure-sandbox/relay/client.crt && ! -L /etc/secure-sandbox/relay/client.crt \
          && ! -e /home/agent/.config/secure-sandbox/client.csr && ! -L /home/agent/.config/secure-sandbox/client.csr ]] \
          || { echo "broker_identity_descendant_without_key" >&2; exit 2; }
        /bin/bash /tmp/create-research-broker-identity.sh
      fi
    fi
    telemetry_key=/etc/secure-sandbox/telemetry/client.key
    [[ ! -L "$telemetry_key" ]] || { echo "private_key_invalid:$telemetry_key" >&2; exit 2; }
    if [[ ! -e "$telemetry_key" ]]; then
      [[ ! -e /etc/secure-sandbox/telemetry/client.crt && ! -L /etc/secure-sandbox/telemetry/client.crt ]] \
        || { echo "telemetry_identity_descendant_without_key" >&2; exit 2; }
      /bin/bash /tmp/create-research-telemetry-identity.sh
    fi
    conversation_key=/etc/secure-sandbox/conversation-transport/client.key
    [[ ! -L "$conversation_key" ]] || { echo "private_key_invalid:$conversation_key" >&2; exit 2; }
    if [[ ! -e "$conversation_key" ]]; then
      [[ ! -e /etc/secure-sandbox/conversation-transport/client.crt && ! -L /etc/secure-sandbox/conversation-transport/client.crt ]] \
        || { echo "conversation_identity_descendant_without_key" >&2; exit 2; }
      /bin/bash /tmp/create-research-conversation-identity.sh
    fi
    publish_csr "$broker_key" secure-sandbox-research "$exchange/broker.csr"
    publish_csr "$telemetry_key" secure-sandbox-research-telemetry "$exchange/telemetry.csr"
    publish_csr "$conversation_key" secure-sandbox-research-conversation "$exchange/conversation.csr"
    ;;
  gateway-sign)
    [[ "$role" == gateway ]] || { echo "role_mismatch" >&2; exit 2; }
    require_csr_subject broker secure-sandbox-research
    require_csr_subject telemetry secure-sandbox-research-telemetry
    require_csr_subject conversation secure-sandbox-research-conversation
    /bin/bash /tmp/sign-research-broker-csr.sh /tmp/broker.csr "$exchange/broker.crt"
    /bin/bash /tmp/sign-research-telemetry-csr.sh /tmp/telemetry.csr "$exchange/telemetry.crt"
    /bin/bash /tmp/sign-research-conversation-csr.sh /tmp/conversation.csr "$exchange/conversation.crt"
    install -o root -g root -m 0644 /etc/secure-sandbox/pki/ca.crt "$exchange/ca.crt"
    ;;
  research-validate)
    [[ "$role" == research ]] || { echo "role_mismatch" >&2; exit 2; }
    ca=/etc/secure-sandbox/relay/ca.crt
    for path in \
      "$ca" \
      /etc/secure-sandbox/relay/client.key \
      /etc/secure-sandbox/relay/client.crt \
      /etc/secure-sandbox/telemetry/client.key \
      /etc/secure-sandbox/telemetry/client.crt \
      /etc/secure-sandbox/conversation-transport/client.key \
      /etc/secure-sandbox/conversation-transport/client.crt; do
      [[ -f "$path" && ! -L "$path" ]] || { echo "installed_identity_incomplete" >&2; exit 3; }
    done
    for certificate in \
      /etc/secure-sandbox/relay/client.crt \
      /etc/secure-sandbox/telemetry/client.crt \
      /etc/secure-sandbox/conversation-transport/client.crt; do
      openssl verify -purpose sslclient -CAfile "$ca" "$certificate" >/dev/null 2>&1 \
        || { echo "installed_identity_invalid" >&2; exit 3; }
    done
    [[ "$(openssl x509 -in /etc/secure-sandbox/relay/client.crt -noout -subject -nameopt RFC2253)" == "subject=CN=secure-sandbox-research" \
      && "$(openssl x509 -in /etc/secure-sandbox/telemetry/client.crt -noout -subject -nameopt RFC2253)" == "subject=CN=secure-sandbox-research-telemetry" \
      && "$(openssl x509 -in /etc/secure-sandbox/conversation-transport/client.crt -noout -subject -nameopt RFC2253)" == "subject=CN=secure-sandbox-research-conversation" ]] \
      || { echo "installed_identity_subject_invalid" >&2; exit 3; }
    same_public_key /etc/secure-sandbox/relay/client.key /etc/secure-sandbox/relay/client.crt \
      && same_public_key /etc/secure-sandbox/telemetry/client.key /etc/secure-sandbox/telemetry/client.crt \
      && same_public_key /etc/secure-sandbox/conversation-transport/client.key /etc/secure-sandbox/conversation-transport/client.crt \
      || { echo "installed_identity_key_mismatch" >&2; exit 3; }
    install -o root -g root -m 0644 "$ca" "$exchange/installed-ca.crt"
    install -o root -g root -m 0644 /etc/secure-sandbox/relay/client.crt "$exchange/installed-broker.crt"
    install -o root -g root -m 0644 /etc/secure-sandbox/telemetry/client.crt "$exchange/installed-telemetry.crt"
    install -o root -g root -m 0644 /etc/secure-sandbox/conversation-transport/client.crt "$exchange/installed-conversation.crt"
    ;;
  cleanup)
    rm -rf -- "$exchange"
    ;;
  *)
    echo "action_invalid" >&2
    exit 2
    ;;
esac

echo "bootstrap-pki:$action:complete"
