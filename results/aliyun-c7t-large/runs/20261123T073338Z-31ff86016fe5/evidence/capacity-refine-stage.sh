set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
deadline=$((SECONDS+600))
while ! grep -q 'FALCO_CAPACITY_COMPLETE' capacity-launch/run.log; do
  if (( SECONDS > deadline )); then exit 1; fi
  sleep 5
done
job=$(cat getpid-matrix.pid)
test "$(tr '\0' ' ' < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "
while test "$(ps -o state= -p "$job" | tr -d ' ')" = T; do sleep 1; done
kill -STOP "$job"
trap 'kill -CONT "$job"; date -u +%FT%TZ' EXIT
while ps -o stat= --ppid "$job" | grep -Eq '^[[:space:]]*[^Z[:space:]]'; do sleep 1; done
date -u +%FT%TZ
tar -xzf capacity-refine-control.tgz
python3 falco-capacity-refine.py > capacity-refine.log 2>&1
echo "FALCO_REFINED_STAGE_COMPLETE"
