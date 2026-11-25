#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
spec=libprotobuf23=3.12.4-1ubuntu7.22.04.6
apt-cache policy libprotobuf23
apt-cache show "$spec" > debs/libprotobuf23.index
file=$(sed -n 's/^Filename: //p' debs/libprotobuf23.index)
sum=$(sed -n 's/^SHA256: //p' debs/libprotobuf23.index)
deb=debs/${file##*/}
curl --proto '=https' --proto-redir '=https' -fsSL --retry 2 "https://archive.ubuntu.com/ubuntu/$file" -o "$deb"
printf '%s  %s\n' "$sum" "$deb" | sha256sum -c -
test "$(dpkg-deb -f "$deb" Package)" = libprotobuf23
test "$(dpkg-deb -f "$deb" Version)" = "${spec#*=}"
dpkg-deb -x "$deb" ship/runtime
printf '%s %s %s %s\n' libprotobuf23 "${spec#*=}" "$sum" "$file"
