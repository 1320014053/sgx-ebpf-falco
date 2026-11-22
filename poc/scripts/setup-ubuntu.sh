#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID != 0 ]]; then
    echo 'Run: sudo bash scripts/setup-ubuntu.sh [SDK_INSTALLER]' >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y build-essential clang llvm libbpf-dev libelf-dev zlib1g-dev \
    pkg-config openssl curl ca-certificates python3 linux-tools-common "linux-tools-$(uname -r)"
sdk_installer=${1:-/tmp/sgx_linux_x64_sdk_2.25.100.3.bin}
if [[ ! -f $sdk_installer ]]; then
    curl -fL --retry 3 -o "$sdk_installer" \
        https://download.01.org/intel-sgx/sgx-linux/2.25/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.25.100.3.bin
fi
if [[ ! -d /opt/intel/sgxsdk ]]; then
    mkdir -p /opt/intel
    bash "$sdk_installer" --prefix=/opt/intel
fi
echo 'Installed build dependencies and Intel SGX SDK Simulation (no PSW/AESM required).'
