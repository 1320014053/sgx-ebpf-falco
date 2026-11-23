set -u
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
tar -xzf falco-perf-control.tgz
trap 'job=$(cat getpid-matrix.pid); if test "$(tr "\0" " " < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "; then kill -CONT "$job"; fi; date -u +%FT%TZ' EXIT
python3 http-benchmark.py smoke > http-smoke.log 2>&1
if test "$(grep -c ' ok$' http-smoke.log)" -eq 4; then
    python3 http-benchmark.py > http-formal.log 2>&1
    echo "http_formal_exit=$?"
fi
python3 plugin-replay-bench.py > plugin-perf.log 2>&1
echo "plugin_replay_exit=$?"
python3 falco-memory.py > raven-memory.log 2>&1
echo "raven_memory_exit=$?"
