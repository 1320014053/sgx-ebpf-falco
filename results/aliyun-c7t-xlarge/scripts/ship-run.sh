#!/usr/bin/env bash
set -euo pipefail
if (( EUID != 0 || $# > 1 )); then
    echo 'usage (as root, from the ship root): bash src/results/aliyun-c7t-xlarge/scripts/ship-run.sh [EXISTING_BATCH]' >&2
    exit 2
fi
sha256sum --quiet -c SHA256SUMS
export LD_LIBRARY_PATH="$PWD/runtime/usr/lib/x86_64-linux-gnu"
S=$PWD/src/results/aliyun-c7t-xlarge/scripts
B=$PWD/src/poc/build-falco
P=$B/deps/package
L=$PWD/src/poc/build-falco-live
M=$PWD/src/probe/poc/build-falco

if (( $# )); then
    batch=$(realpath -e -- "$1")
    cmp evidence/source-snapshot.sha256 "$batch/evidence/source-snapshot.sha256"
    cmp evidence/enclaves.tsv "$batch/evidence/enclaves.tsv"
else
    read -r commit < evidence/source-commit.txt
    batch=$PWD/src/results/aliyun-c7t-xlarge/runs/$(date -u +%Y%m%dT%H%M%SZ)-${commit:0:12}
    mkdir -- "$batch"
fi
cp -a -- evidence "$batch/"
printf 'batch=%s\n' "$batch"
exec bash "$S/run-all.sh" "$P" "$B" "$L" "$M" "$batch"
