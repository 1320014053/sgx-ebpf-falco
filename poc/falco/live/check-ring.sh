#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
package=$(realpath "${1:?usage: bash check-ring.sh FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY}")
build=$(realpath "${2:?missing enclave build directory}")
live=$(realpath "${3:?missing live build directory}")
mkdir "${4:?missing run directory}"
cd "$4"
export TZ=UTC FALCO_HOSTNAME=falco-sgx-ring-test
cp "$here/reference.yaml" "$package/etc/falco/falco_rules.yaml" .
ln -s "$package/usr/share/falco/plugins/libcontainer.so" .
python3 "$here/fixture.py"
timeout 60 "$live/falco-ring-test" "$build/falco-enclave.signed" reference.yaml reference.scap falco_rules.yaml expected.scap \
    >sgx-alerts.jsonl 2>sgx.log
"$package/usr/bin/falco" --version >versions.txt
"$package/usr/bin/falco" -c reference.yaml -o engine.replay.capture_file=expected.scap -L >native-rules.json 2>native-rules.log
"$package/usr/bin/falco" -c reference.yaml -o engine.replay.capture_file=expected.scap >native-alerts.jsonl 2>native.log
python3 "$here/compare.py" . --captured | tee comparison.json

python3 - <<'PY' | tee ring-check.json
import json
from pathlib import Path

rows = [json.loads(line) for line in Path("sgx.log").read_text().splitlines() if line.startswith("{")]
ring = next(row for row in rows if row.get("mode") == "live")
assert ring["busy_observations"] > 0 and ring["wrapped"] == 1
assert ring["records"] == 223 and ring["accepted"] == ring["events"] == ring["alerts"] == 220
assert ring["discarded"] == 1 and ring["format_rejected"] == 2
assert ring["consumer"] == ring["producer"]
assert rows[-1]["busy_waited"] and rows[-1]["source_mutated_before_batch_finished"]
assert 0 < rows[-1]["alerts_formatted_before_mutation"] < ring["alerts"]
comparison = json.loads(Path("comparison.json").read_text())
assert comparison["alerts_by_rule"] == {"Run shell untrusted": 220}
print(json.dumps({"pass": True, "enclave": ring, **rows[-1]}, indent=2))
PY
