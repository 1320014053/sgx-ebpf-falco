set -eu
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
test ! -e getpid-matrix.log
nohup python3 getpid-benchmark.py >getpid-matrix.log 2>&1 < /dev/null &
echo $! > getpid-matrix.pid
cat getpid-matrix.pid
