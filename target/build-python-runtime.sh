#!/bin/bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on Target." >&2; exit 1; }
uid="$(id -u labadmin)"
runtime_dir="/run/user/$uid"
docker=(sudo -u labadmin env HOME=/home/labadmin XDG_RUNTIME_DIR="$runtime_dir" DOCKER_HOST="unix://$runtime_dir/docker.sock" docker)
work="$(mktemp -d /tmp/secure-sandbox-python-rootfs.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT
root="$work/rootfs"
install -d -m 755 "$root"

copy_path() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  if [[ -d "$path" ]]; then
    cp -a --parents "$path" "$root"
  else
    cp -L --preserve=mode,timestamps --parents "$path" "$root"
  fi
}

copy_path /usr/bin/python3.14
copy_path /usr/lib/python3.14
copy_path /usr/lib/aarch64-linux-gnu/libpython3.14.so.1.0

mapfile -t objects < <(find /usr/lib/python3.14 -type f -name '*.so' -o -type f -name '*.so.*')
objects+=(/usr/bin/python3.14)
for object in "${objects[@]}"; do
  while IFS= read -r library; do copy_path "$library"; done < <(
    ldd "$object" 2>/dev/null | awk '/=> \/|^\// {for (i=1;i<=NF;i++) if ($i ~ /^\//) {print $i; break}}' | sort -u
  )
done
copy_path /lib/ld-linux-aarch64.so.1
install -d -m 755 "$root/etc" "$root/work" "$root/tmp"
printf 'nobody:x:65532:65532:nobody:/nonexistent:/usr/sbin/nologin\n' > "$root/etc/passwd"
printf 'nogroup:x:65532:\n' > "$root/etc/group"
chmod 1777 "$root/tmp"

image_id="$(tar -C "$root" -cf - . | "${docker[@]}" import \
  --change 'ENTRYPOINT ["/usr/bin/python3.14","-I","-B","/work/main.py"]' \
  --change 'WORKDIR /work' \
  --change 'LABEL org.securesandbox.runtime=python-fixture-v1' \
  --change 'USER 65532:65532' - secure-sandbox/python-fixture:3.14-v1)"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Invalid imported image ID." >&2; exit 1; }
printf '%s\n' "$image_id"
