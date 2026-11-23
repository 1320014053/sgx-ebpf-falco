set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
tar -xzf capacity-control.tgz
job=$(cat getpid-matrix.pid)
test "$(tr '\0' ' ' < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "
test -s data/alert-latency-hw-full-r05/trial.json
kill -STOP "$job"
trap 'kill -CONT "$job"; date -u +%FT%TZ' EXIT
while ps -o stat= --ppid "$job" | grep -Eq '^[[:space:]]*[^Z[:space:]]'; do sleep 1; done
date -u +%FT%TZ
python3 falco-replay-bench.py falco-offline-r02 5000 > large-replay.log 2>&1
python3 replay-heap.py > replay-heap.log 2>&1 || echo "replay heap diagnostic exit=$?"
python3 falco-capacity.py > capacity.log 2>&1
echo "FALCO_CAPACITY_COMPLETE"
