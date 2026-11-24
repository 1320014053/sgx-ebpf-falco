#!/usr/bin/env bash
set -euo pipefail
strict=0
if [[ ${1:-} == --strict ]]; then strict=1; shift; fi
here=$(cd "$(dirname "$0")/.." && pwd)
package=$(realpath "${1:?usage: bash check.sh FALCO_PACKAGE BUILD_DIR LIVE_BUILD_DIR NEW_RUN_DIRECTORY}")
build=$(realpath "${2:?missing enclave build directory}")
live=$(realpath "${3:?missing live build directory}")
mkdir "${4:?missing run directory}"
cd "$4"
export TZ=UTC FALCO_HOSTNAME=falco-sgx-live
cp "$here/reference.yaml" "$package/etc/falco/falco_rules.yaml" .
ln -s "$package/usr/share/falco/plugins/libcontainer.so" .
work=$(mktemp -d /tmp/falco-sgx.XXXXXX)
trap 'rm -f -- "$work/httpd" "$work/worker"; rmdir -- "$work"' EXIT
if [[ -n ${FALCO_WORKLOAD_USER:-} ]]; then chmod 755 "$work"; fi
cp "$live/httpd" "$work/worker"
cp "$live/httpd" "$work/httpd"

as_root=()
if (( EUID != 0 )); then as_root=(sudo -n); fi
"${as_root[@]}" env TZ="$TZ" FALCO_HOSTNAME="$FALCO_HOSTNAME" \
    "$live/falco-live" "$build/falco-enclave.signed" reference.yaml 1024 reference.scap falco_rules.yaml \
    -- runuser -u "${FALCO_WORKLOAD_USER:-$(id -un)}" -- "$work/httpd" "$work/worker" >sgx-alerts.jsonl 2>sgx.log
sha256sum falco_rules.yaml reference.yaml reference.scap >inputs.sha256
"$package/usr/bin/falco" --version >versions.txt
"$package/usr/bin/falco" -c reference.yaml -L >native-rules.json 2>native-rules.log
"$package/usr/bin/falco" -c reference.yaml >native-alerts.jsonl 2>native.log
python3 "$here/compare.py" . --captured | tee comparison.json

mkdir replayed
ln -s ../native-alerts.jsonl ../native-rules.json ../versions.txt replayed/
"$build/bin/falco-sgx" "$build/falco-enclave.signed" reference.yaml reference.scap falco_rules.yaml \
    >replayed/sgx-alerts.jsonl 2>replayed/sgx.log
python3 "$here/compare.py" replayed --captured | tee replayed/comparison.json

python3 - "$strict" <<'PY' | tee live-check.json
import json
import sys
from pathlib import Path

diagnostics = [json.loads(line) for line in Path("sgx.log").read_text().splitlines() if line.startswith("{")]
consumer = next(row for row in diagnostics if row.get("mode") == "live")
if int(sys.argv[1]) and any(consumer["errors"].values()):
    raise SystemExit(f"live errors: {consumer['errors']}")
driver = next(row for row in diagnostics if row.get("mode") == "modern_ebpf")
replayed = [json.loads(line) for line in Path("replayed/sgx.log").read_text().splitlines() if line.startswith("{")][-1]
alerts = [json.loads(line) for line in Path("sgx-alerts.jsonl").read_text().splitlines()]
assert any(row["rule"] == "Run shell untrusted" for row in alerts)
assert not driver["driver_drops"] and not consumer["format_rejected"] and not consumer["discarded"]
assert driver["driver_events"] == consumer["records"] == consumer["accepted"]
assert 0 < consumer["events"] == replayed["events"] <= consumer["accepted"]
assert driver["consumer"] == driver["producer"] == consumer["consumer"] == consumer["producer"]
assert driver["data_ecalls"] == 4 and driver["trace_ocalls"] > 0
assert {"execve", "openat", "connect", "procexit"} <= consumer["event_types"].keys()
assert consumer["min_event_bytes"] < consumer["max_event_bytes"]
assert consumer["snapshot_bytes"] + consumer["trace_bytes"] == Path("reference.scap").stat().st_size
print(json.dumps({"pass": True, "driver": driver, "enclave": consumer}, indent=2))
PY
