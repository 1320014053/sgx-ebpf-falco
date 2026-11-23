set -eu
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
job=$(cat getpid-matrix.pid)
test "$(tr '\0' ' ' < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "
kill -CONT "$job"
date -u +%FT%TZ
