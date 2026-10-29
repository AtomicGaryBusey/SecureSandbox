#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artwork="$root_dir/Artwork/icon.svg"
iconset="$root_dir/.build/AppIcon.iconset"
output="$root_dir/.build/AppIcon.icns"
atsign="$(printf '\100')"
mkdir -p "$iconset"
for pixels in 16 32 64 128 256 512 1024; do
  rsvg-convert --width "$pixels" --height "$pixels" "$artwork" \
    --output "$iconset/icon_${pixels}x${pixels}.png"
done
cp "$iconset/icon_32x32.png" "$iconset/icon_16x16${atsign}2x.png"
cp "$iconset/icon_64x64.png" "$iconset/icon_32x32${atsign}2x.png"
cp "$iconset/icon_128x128.png" "$iconset/icon_64x64${atsign}2x.png"
cp "$iconset/icon_256x256.png" "$iconset/icon_128x128${atsign}2x.png"
cp "$iconset/icon_512x512.png" "$iconset/icon_256x256${atsign}2x.png"
cp "$iconset/icon_1024x1024.png" "$iconset/icon_512x512${atsign}2x.png"
iconutil -c icns "$iconset" -o "$output"
printf '%s\n' "$output"
