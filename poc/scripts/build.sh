#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export SGX_SDK=${SGX_SDK:-/opt/intel/sgxsdk}
make -j2 SGX_MODE="${SGX_MODE:-SIM}" SGX_DEBUG="${SGX_DEBUG:-1}"
