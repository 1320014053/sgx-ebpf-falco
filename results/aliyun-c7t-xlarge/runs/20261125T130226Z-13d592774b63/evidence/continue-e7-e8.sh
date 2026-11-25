set -euo pipefail
cd /root/c7t-xlarge-ship
export LD_LIBRARY_PATH="$PWD/runtime/usr/lib/x86_64-linux-gnu"
batch=/root/c7t-xlarge-ship/src/results/aliyun-c7t-xlarge/runs/20261125T130226Z-13d592774b63
S=$PWD/src/results/aliyun-c7t-xlarge/scripts
B=$PWD/src/poc/build-falco
P=$B/deps/package
M=$PWD/src/probe/poc/build-falco
exec 9>"$batch/.run-all.lock"
flock -n 9
python3 "$S/memory-bench.py" --package "$P" --build "$M" --out "$batch/e7"
touch "$batch/e7/.complete"
python3 "$S/replay-bench.py" --package "$P" --build "$B" --out "$batch/e8"
touch "$batch/e8/.complete"
