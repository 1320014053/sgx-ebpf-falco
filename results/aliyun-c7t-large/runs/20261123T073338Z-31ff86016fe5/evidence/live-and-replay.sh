set -u
cd /var/tmp/sgx-bench-20261123T073338Z-31ff86016fe5
export LD_LIBRARY_PATH=$PWD/deps/runtime/usr/lib/x86_64-linux-gnu
export SGX_SDK=$PWD/deps/intel/sgxsdk
export FALCO_WORKLOAD_USER=nobody
b=$PWD/falco-poc/build-ert
p=$PWD/falco-poc/deps/package
live=$PWD/falco-poc/build-live
d=$PWD/data
tar -xzf control.tgz
trap 'job=$(cat getpid-matrix.pid); if test "$(tr "\0" " " < /proc/$job/cmdline)" = "python3 getpid-benchmark.py "; then kill -CONT "$job"; fi; date -u +%FT%TZ' EXIT
mkdir "$d/getpid-ring-r02"
make -C poc SGX_MODE=HW SGX_DEBUG=0 CLANG=clang-14 build/hw0/ring_tests > "$d/getpid-ring-r02/build.log" 2>&1 && poc/build/hw0/ring_tests poc/build/hw0/enclave.signed.so > "$d/getpid-ring-r02/report.txt" 2>&1
echo "getpid_ring_exit=$?"
FALCO_SGX_REPORT=1 timeout 110 bash poc/falco/live/check.sh "$p" "$b" "$live" "$d/falco-live-official-r01" > live-official.log 2>&1
echo "live_official_exit=$?"
FALCO_SGX_REPORT=1 timeout 180 python3 poc/falco/live/check-detectors.py "$p" "$b" "$live" "$d/falco-live-detectors-r01" > live-detectors.log 2>&1
echo "live_detectors_exit=$?"
python3 falco-replay-bench.py falco-offline-r02 > offline-perf.log 2>&1
echo "offline_perf_exit=$?"
