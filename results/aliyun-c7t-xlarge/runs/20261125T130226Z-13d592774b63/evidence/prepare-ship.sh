#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
W=$PWD
S=$W/ship
E=$S/evidence
mkdir "$E"
cp -a evidence/. "$E/"
cp build.sh build.log runtime.py identity.py prepare-ship.sh verify-ship.sh "$E/"
cp runtime.log "$E/runtime-packages.txt"
cp protobuf.sh protobuf.log debs/libprotobuf23.index "$E/"
tail -1 protobuf.log >> "$E/runtime-packages.txt"
cp debs/Packages "$E/Intel-jammy-Packages"
cd source
for b in poc/build-falco probe/poc/build-falco; do
    for suffix in bin/falco-sgx lib/libraven_zeek.so falco-enclave.signed trusted/enclave.conf; do
        cp -a --parents "$b/$suffix" "$S/src"
    done
    grep -Fx FALCO_SGX_HARDWARE:BOOL=ON "$b/CMakeCache.txt"
done
grep -Fx FALCO_SGX_HARDWARE:BOOL=ON poc/build-falco-live/CMakeCache.txt
cp -a --parents poc/build-falco-live/falco-live poc/build-falco/deps/bpftool/bpftool "$S/src"
cp -a --parents poc/build-falco/deps/package "$S/src"
for b in poc/build-falco poc/build-falco-live probe/poc/build-falco; do
    grep -m1 -F 'liboehost.a' "$b/build.ninja"
done > "$E/oehost-link.txt"
(cd "$S/src" && sha256sum --quiet -c "$E/new-files.sha256")
cd "$S"
python3 "$E/identity.py" src/{poc,probe/poc}/build-falco/falco-enclave.signed > "$E/enclaves.tsv"
cat "$E/enclaves.tsv"
