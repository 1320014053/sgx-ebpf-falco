#!/usr/bin/env bash
set -euo pipefail

if (( $# != 1 )); then
    echo "usage: bash fetch-raven.sh NEW_SOURCE_DIRECTORY" >&2
    exit 2
fi

dest=$(realpath -m -- "$1")
if [[ -e $dest ]]; then
    echo "source directory already exists: $dest" >&2
    exit 1
fi
mkdir -p -- "$(dirname -- "$dest")"
stage=$(mktemp -d -- "${dest}.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
commit=3b5fbf5f33e2d1287d3ff0f546023106f787a92e
curl --fail --location --silent --show-error --retry 2 \
    "https://codeload.github.com/Arthurs011/raven/tar.gz/$commit" -o "$stage/raven.tar.gz"
(
    cd "$stage"
    echo 'f53bbce4f31287a3528a5060aa52e056ca1ec10945121b7f64058be6aab0bd69  raven.tar.gz' | sha256sum -c -
    mkdir source
    tar --extract --gzip --file raven.tar.gz --strip-components=1 --no-same-owner -C source
)
mv -T -- "$stage/source" "$dest"
