#!/usr/bin/env bash
set -euxo pipefail
W=$(cd "$(dirname "$0")" && pwd)
cd "$W"
sha256sum -c initial.sha256
mkdir source
tar -xf initial.tar -C source
cd source
R=$PWD
S=$R/results/aliyun-c7t-xlarge/scripts
B=$R/poc/build-falco
L=$R/poc/build-falco-live
D=$B/deps
P=$D/package
export CC=clang CXX=clang++
clang --version
clang++ --version
cmake --version
opts=(-G Ninja -DFALCO_SGX_HARDWARE=ON -DCMAKE_BUILD_TYPE=Release
      -DCMAKE_C_FLAGS_RELEASE=-O1 -DCMAKE_CXX_FLAGS_RELEASE=-O1)
bash poc/falco/fetch.sh "$D"
mkdir -p "$D/bpftool"
curl -fsSL https://github.com/libbpf/bpftool/releases/download/v7.5.0/bpftool-v7.5.0-amd64.tar.gz |
    tar -xz -C "$D/bpftool" bpftool
chmod u+x "$D/bpftool/bpftool"
"$D/bpftool/bpftool" version
cmake -S poc/falco -B "$B" "${opts[@]}"
cmake --build "$B" --parallel 2
cmake -S poc/falco/live -B "$L" "${opts[@]}" -DMODERN_BPFTOOL_EXE="$D/bpftool/bpftool"
cmake --build "$L" --parallel 2
T=$R/probe
mkdir -p "$T/poc"
cp -a poc/falco "$T/poc/"
patch -p1 -d "$T/poc/falco" < "$S/memory-probe.patch"
M=$T/poc/build-falco
cmake -S "$T/poc/falco" -B "$M" "${opts[@]}" -DDEPS="$D"
cmake --build "$M" --parallel 2
