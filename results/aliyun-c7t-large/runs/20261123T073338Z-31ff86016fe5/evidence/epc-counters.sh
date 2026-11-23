set -eu
export LC_ALL=C
printf 'proc_vmstat SGX/EPC matches\n'
grep -Ei 'sgx|epc' /proc/vmstat || true
for dir in /sys/devices/system/node/node0/x86 /sys/kernel/debug/x86/sgx /sys/kernel/mm/sgx /sys/kernel/tracing/events/sgx; do
  if test -d "$dir"; then ls -1 "$dir"; else printf 'not exposed: %s\n' "$dir"; fi
done
printf 'root CPU affinity\n'
grep Cpus_allowed_list /proc/self/status
