export LC_ALL=C
date -u +remote_utc=%Y-%m-%dT%H:%M:%SZ
id -u
cat /etc/os-release
uname -srmo
getconf PAGESIZE
lscpu -e=CPU,CORE,SOCKET,ONLINE
awk '/^MemTotal:|^MemAvailable:|^SwapTotal:/ {print}' /proc/meminfo
df -hP / /tmp
cat /proc/loadavg
for path in /dev/sgx_enclave /dev/sgx/enclave /dev/sgx_provision /sys/kernel/btf/vmlinux /sys/devices/system/node/node*/x86/sgx_total_bytes; do
  if test -e "$path"; then
    ls -ld "$path"
    case "$path" in */sgx_total_bytes) cat "$path" ;; esac
  fi
done
awk '/^flags[[:space:]]*:/ {for(i=1;i<=NF;i++) if($i ~ /^(sgx|sgx_lc|pks|pcid|invpcid)$/) print "cpu_feature=" $i; exit}' /proc/cpuinfo
dmesg | grep -i 'EPC section' | head -10
for tool in bpftool clang cmake ninja gcc openssl; do command -v "$tool" || true; done
for path in /opt/intel/sgxsdk /opt/alibaba/teesdk/intel/sgxsdk /opt/edgelessrt; do
  if test -d "$path"; then ls -d "$path"; fi
done
