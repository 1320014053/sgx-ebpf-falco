set -euo pipefail
cd /root/c7t-xlarge-ship
export LD_LIBRARY_PATH="$PWD/runtime/usr/lib/x86_64-linux-gnu"
batch=/root/c7t-xlarge-ship/src/results/aliyun-c7t-xlarge/runs/20261125T130226Z-13d592774b63
S=/root/c7t-xlarge-ship/supplement/src/results/aliyun-c7t-xlarge/scripts
B=$PWD/src/poc/build-falco
P=$B/deps/package
L=$PWD/src/poc/build-falco-live
mode=(e2 --configs S2,S4 --background-alerts-ok --package "$P" --build "$B" --live "$L" --out "$batch")
if [[ ${1-} == --dry-run ]]; then
    python3 "$S/bench.py" "${mode[@]}" --dry-run
else
    python3 "$S/bench.py" "${mode[@]}"
fi
