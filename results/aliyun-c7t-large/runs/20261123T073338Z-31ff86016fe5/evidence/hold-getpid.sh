set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
job=$(cat getpid-matrix.pid)
test "$(tr '\0' ' ' < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "
kill -STOP "$job"
for tick in $(seq 1 80); do
  if ! ps -o stat= --ppid "$job" | grep -Eq '^[[:space:]]*[^Z[:space:]]'; then
    date -u +%FT%TZ
    echo "GETPID runner held between samples"
    exit 0
  fi
  sleep 1
done
exit 1
