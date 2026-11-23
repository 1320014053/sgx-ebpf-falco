#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export SGX_SDK=${SGX_SDK:-/opt/intel/sgxsdk}
export LD_LIBRARY_PATH="$SGX_SDK/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mode=${SGX_MODE:-SIM}
exec "build/${mode,,}${SGX_DEBUG:-1}/poc" "$@"
