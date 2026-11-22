#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -m) == x86_64 ]]
uname -a
cat /etc/os-release
lscpu
clang --version
gcc --version | head -n 1
pkg-config --modversion libbpf
test -r /sys/kernel/btf/vmlinux
test -x "${SGX_SDK:-/opt/intel/sgxsdk}/bin/x64/sgx_edger8r"
if ! mountpoint -q /sys/kernel/tracing; then
    sudo mount -t tracefs tracefs /sys/kernel/tracing
fi
sudo test -e /sys/kernel/tracing/events/syscalls/sys_enter_getpid/id
sudo bpftool feature probe kernel
if [[ -r /boot/config-$(uname -r) ]]; then
    grep -E '^CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|BPF_EVENTS|PERF_EVENTS|FTRACE_SYSCALLS|DEBUG_INFO_BTF)=' "/boot/config-$(uname -r)"
fi
grep -E 'VERSION|SGX_SDK' "${SGX_SDK:-/opt/intel/sgxsdk}/environment" || true
