set -euo pipefail
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
while ! grep -q 'FALCO_REFINED_STAGE_COMPLETE' refine-launch/run.log; do sleep 5; done
job=$(cat getpid-matrix.pid)
test "$(tr '\0' ' ' < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "
while test "$(ps -o state= -p "$job" | tr -d ' ')" = T; do sleep 1; done
kill -STOP "$job"
trap 'kill -CONT "$job"; date -u +%FT%TZ' EXIT
while ps -o stat= --ppid "$job" | grep -Eq '^[[:space:]]*[^Z[:space:]]'; do sleep 1; done
date -u +%FT%TZ
python3 -u - <<'PY' > capacity-floor.log 2>&1
import runpy
sample = runpy.run_path("falco-capacity.py")["sample"]
for i in range(1, 6):
    sample("hw-full", 4000, 2, "floor-warmup", i)
    sample("hw-full", 4000, 60, "floor", i)
print("FALCO_FLOOR_CAPACITY_COMPLETE")
PY
echo "FALCO_FLOOR_STAGE_COMPLETE"
