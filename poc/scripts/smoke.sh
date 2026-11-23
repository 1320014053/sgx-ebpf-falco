#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export SGX_SDK=${SGX_SDK:-/opt/intel/sgxsdk}
export LD_LIBRARY_PATH="$SGX_SDK/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mode=${SGX_MODE:-SIM}
build="build/${mode,,}${SGX_DEBUG:-1}"
"$build/ring_tests" "$build/enclave.signed.so"
for mode in host ecall batch step direct; do
    timeout 180 "$build/poc" --mode "$mode" --count 10003 --interval-us 1000
done
timeout 180 "$build/poc" --mode direct --count 20000 --interval-us 0 --pause-ms 3000 --allow-drops
