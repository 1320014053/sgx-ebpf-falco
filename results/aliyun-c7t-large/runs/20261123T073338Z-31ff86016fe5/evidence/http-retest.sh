set -eu
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
tar -xzf http-retest-control.tgz
trap 'job=$(cat getpid-matrix.pid); if test "$(tr "\0" " " < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "; then kill -CONT "$job"; fi; date -u +%FT%TZ' EXIT
python3 http-benchmark.py retry-full > http-retry.log 2>&1
python3 http-benchmark.py > http-formal.log 2>&1
echo "HTTP_FORMAL_COMPLETE"
