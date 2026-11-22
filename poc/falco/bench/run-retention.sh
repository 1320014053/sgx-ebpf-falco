#!/usr/bin/env bash
set -eu
# PACKAGE BUILD LIVE_BUILD BASELINE REFERENCE ARCHIVED_100K RAVEN_SOURCE NEW_OUTPUT
package=$(realpath "$1")
build=$(realpath "$2")
live=$(realpath "$3")
baseline=$(realpath "$4")
reference=$(realpath "$5")
archive=$(realpath "$6")
oracle=$(realpath "$7")
out=$(realpath -m "$8")
bench=$(cd "$(dirname "$0")" && pwd)
export TZ=UTC PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0
mkdir "$out"
cd "$out"
sha256sum "$package/usr/bin/falco" "$build/lib/libraven_zeek.so" "$build/bin/falco-sgx" \
          "$build/falco-enclave.signed" "$live/falco-live" > binaries.sha256
python3 "$bench/../plugin/check.py" "$package" "$build" "$baseline" "$reference" parity > parity.log
mkdir original
for case in repeat churn; do
    ln -s "$archive/$case.jsonl" "original/$case.jsonl"
    for mode in native sgx; do
        trial="original/$case-$mode-release-0"
        python3 "$bench/raven-retention.py" run "$package" "$build" "$baseline" "$trial" "$archive/$case.jsonl" \
                "$mode" "$case" --offline --events 100000 --high 1073741824
        ln -s alerts.jsonl "$trial/output.jsonl"
    done
done
python3 - "$bench" "$oracle" <<'PY'
import json,runpy,sys
from pathlib import Path
check=runpy.run_path(str(Path(sys.argv[1])/"raven-memory.py"))["verify_upstream"]
result=check(Path(sys.argv[2]),Path("original").resolve())
assert all(x["matching_complete_records"]=={"native":10,"sgx":10} for x in result.values())
Path("original/comparison.json").write_text(json.dumps(result,indent=2))
PY
python3 "$bench/check-retention.py" "$package" "$build" "$baseline" boundaries
deps=$(sed -n 's/^DEPS:PATH=//p' "$build/CMakeCache.txt")
c++ -std=c++17 -I"$deps/njson/single_include" "$bench/retention-idle.cpp" -L"$build/lib" \
    -Wl,-rpath,"$build/lib" -lraven_zeek -o retention-idle
./retention-idle
echo PASS > idle.result
if [ -n "${RETENTION_INPUTS:-}" ]; then
    ln -s "$(realpath "$RETENTION_INPUTS")" million
else
    python3 "$bench/raven-retention.py" generate million
fi
for case in repeat churn; do
    for mode in native sgx; do
        python3 "$bench/raven-retention.py" run "$package" "$build" "$baseline" "$case-$mode" \
                "million/$case.jsonl" "$mode" "$case" --events 1000000
    done
done
cc -O2 -Wall -Wextra "$bench/retention-workload.c" -o rz-load
for case in repeat churn; do
    d="$out/actual-$case"
    mkdir "$d"
    ln -s "$baseline/falco_rules.yaml" "$d/falco_rules.yaml"
    ln -s "$bench/../plugin/rules.yaml" "$d/raven_zeek_rules.yaml"
    sed '/^  - name: raven_zeek$/a\    open_params: '\''{"retention_metrics":true}'\''' "$bench/../plugin/live.yaml" > "$d/live.yaml"
    (
        cd "$d"
        sudo -n env TZ=UTC FALCO_HOSTNAME=raven-actual /usr/bin/time -q -o maxrss.kib -f %M \
           "$live/falco-live" "$build/falco-enclave.signed" live.yaml 65536 - --record-inputs events.jsonl - \
           falco_rules.yaml raven_zeek_rules.yaml -- "$out/rz-load" "$case" 1000000 "$d/process.log" >alerts.jsonl 2>process.log
    )
    python3 "$bench/check-retention-live.py" "$d" "$case" 1000000
    count=$(wc -l < "$d/events.jsonl")
    python3 "$bench/raven-retention.py" run "$package" "$build" "$baseline" "actual-$case-native" \
             "$d/events.jsonl" native actual --events "$count" --hostname raven-actual
done
python3 "$bench/summarize-retention.py" "$out"
