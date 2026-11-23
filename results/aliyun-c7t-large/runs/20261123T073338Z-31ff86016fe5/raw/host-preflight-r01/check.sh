set -u
export LC_ALL=C
date -u +%FT%TZ
cat /etc/os-release
uname -srm
lscpu
getconf PAGESIZE
ls -l /dev/sgx* /dev/sgx/* /sys/kernel/btf/vmlinux 2>/dev/null
for ep in /sys/devices/system/node/node*/x86/sgx*; do if test -f "$ep"; then echo "$ep"; cat "$ep"; fi; done
dmesg | grep -Ei 'sgx|EPC section' | tail -20
free -b
df -h /
for tool in gcc g++ make cmake clang bpftool strace python3 dpkg-query; do command -v "$tool"; done
ldconfig -p | grep -E 'sgx_|openenclave|libbpf|libelf' || true
cat /proc/loadavg
token=$(curl -fsS --max-time 3 -X PUT -H 'X-aliyun-ecs-metadata-token-ttl-seconds: 60' http://100.100.100.200/latest/api/token) || token=''
if test -n "$token"; then for attribute in instance/instance-type region-id image-id; do printf '%s ' "$attribute"; curl -fsS --max-time 3 -H "X-aliyun-ecs-metadata-token: $token" "http://100.100.100.200/latest/meta-data/$attribute"; printf '\n'; done; fi
unset token
printf 'preflight_complete\n'
