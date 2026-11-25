#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
package=$(realpath "${1:?usage: check-runtime.sh PACKAGE BUILD LIVE RUN FIXTURE RUNTIME_BINARY SOCKET}")
build=$(realpath "${2:?missing enclave build directory}")
live=$(realpath "${3:?missing live build directory}")
fixture=$(realpath "${5:?missing fixture image archive}")
runtime=${6:?missing runtime binary}
engine=$(basename "$runtime")
socket=${7:?missing runtime socket}
case "$engine" in
    docker) client=("$runtime" --host "unix://$socket") ;;
    podman) client=("$runtime" --remote --url "unix://$socket") ;;
    *) exit 2 ;;
esac
mkdir "${4:?missing run directory}"
cd "$(realpath "$4")"
export TZ=UTC FALCO_HOSTNAME=falco-sgx-runtime
image=localhost/falco-poc/fixture:1
prefix=$(printf '%s' "$PWD" | sha256sum | cut -c1-12)
prefix=falco-$prefix
trap 'sudo -n "${client[@]}" rm -f "$prefix-existing" "$prefix-native-new" "$prefix-sgx-new" >/dev/null 2>&1 || true' EXIT
sudo -n "${client[@]}" version >runtime-version.txt
rootless=false
if [[ "$engine" == podman ]]; then
    rootless=$(sudo -n "${client[@]}" info --format '{{.Host.Security.Rootless}}')
fi
printf 'runtime=%s\nsocket=%s\nrootless=%s\n' "$engine" "$socket" "$rootless" >runtime.txt
sudo -n "${client[@]}" load -i "$fixture" >image-import.log
sudo -n "${client[@]}" run --detach --network=none --name "$prefix-existing" \
    "$image" /bin/busybox sleep 600 >existing-id.txt

cp "$package/etc/falco/falco_rules.yaml" .
ln -s "$package/usr/share/falco/plugins/libcontainer.so" .
sed -e 's|rules_files: \[falco_rules.yaml\]|rules_files: [falco_rules.yaml, cases.yaml]|' \
    -e "s|$engine: {enabled: false}|$engine: {enabled: true, sockets: [$socket]}|" \
    -e 's|extra_fields: \[evt.num, evt.type, thread.tid\]|extra_fields: [evt.num, evt.type, thread.tid, proc.args, container.full_id, container.name, container.type, container.image.repository, container.privileged]|' \
    "$here/reference.yaml" >reference.yaml
echo 'base_syscalls: {all: true}' >>reference.yaml
cat >cases.yaml <<'YAML'
- rule: POC Runtime test shell
  desc: Record metadata for shells in the existing and newly created test containers.
  condition: evt.type in (execve, execveat) and evt.dir=< and proc.name=sh and proc.args contains falco_runtime_case_
  output: Runtime test shell | command=%proc.cmdline
  priority: NOTICE
YAML
cat >workload.sh <<'SH'
set -euo pipefail
phase=$1
prefix=$2
image=$3
rootless=$4
shift 4
client=("$@")
flags=()
if [[ "$rootless" == false ]]; then flags+=(--privileged); fi
"${client[@]}" run --detach --network=none --name "$prefix-$phase-new" \
    "${flags[@]}" "$image" /bin/busybox sleep 600 >"$phase-new-id.txt"
sleep 3
for kind in existing new; do
    name=$prefix-existing
    if [[ "$kind" == new ]]; then name=$prefix-$phase-new; fi
    command=("${client[@]}" exec --tty "$name" /bin/sh -c 'exit 0' "falco_runtime_case_$kind")
    script -qefc "$(printf '%q ' "${command[@]}")" /dev/null >>"$phase-workload.log" 2>&1
    "${client[@]}" inspect "$name" | python3 -c '
import json
import sys

row, = json.load(sys.stdin)
print(json.dumps({"case": sys.argv[1], "id": row.get("Id") or row["ID"],
                  "name": row["Name"].lstrip("/"), "image": row.get("ImageName") or row["Config"]["Image"],
                  "privileged": row["HostConfig"]["Privileged"]}))
' "$kind" >>"$phase-identities.jsonl"
done
sleep 2
SH

sudo -n env TZ="$TZ" FALCO_HOSTNAME="$FALCO_HOSTNAME" timeout 95 bash -eu -c '
    "$1" -c reference.yaml -o engine.kind=modern_ebpf -o engine.modern_ebpf.disable_iterators=true \
        >native-live-alerts.jsonl 2>native-live.log &
    capture=$!
    trap "kill -INT $capture 2>/dev/null || true" EXIT
    shift
    for _ in $(seq 1 30); do
        kill -0 "$capture"
        if grep -q "with modern BPF probe" native-live.log; then break; fi
        sleep 1
    done
    grep -q "with modern BPF probe" native-live.log
    sleep 8
    bash workload.sh native "$@"
    kill -INT "$capture"
    wait "$capture"
' bash "$package/usr/bin/falco" "$prefix" "$image" "$rootless" "${client[@]}"
sudo -n env TZ="$TZ" FALCO_HOSTNAME="$FALCO_HOSTNAME" timeout 95 \
    "$live/falco-live" "$build/falco-enclave.signed" reference.yaml 16384 reference.scap falco_rules.yaml cases.yaml \
    -- bash "$PWD/workload.sh" sgx "$prefix" "$image" "$rootless" "${client[@]}" >sgx-alerts.jsonl 2>sgx.log

sha256sum falco_rules.yaml cases.yaml reference.yaml reference.scap "$fixture" >inputs.sha256
"$package/usr/bin/falco" --version >versions.txt
"$package/usr/bin/falco" -c reference.yaml -L >native-rules.json 2>native-rules.log
"$package/usr/bin/falco" -c reference.yaml >native-alerts.jsonl 2>native.log
python3 "$here/compare.py" . --captured | tee comparison.json
mkdir replayed
ln -s ../native-alerts.jsonl ../native-rules.json ../versions.txt replayed/
"$build/bin/falco-sgx" "$build/falco-enclave.signed" reference.yaml reference.scap falco_rules.yaml cases.yaml \
    >replayed/sgx-alerts.jsonl 2>replayed/sgx.log
python3 "$here/compare.py" replayed --captured | tee replayed/comparison.json

python3 - "$engine" "$rootless" "$image" <<'PY' | tee runtime-check.json
import json
import sys
from pathlib import Path

engine, rootless, image = sys.argv[1:]
rules = {"POC Runtime test shell", "Terminal shell in container"}
result = {}
for phase, alerts in (("native", "native-live-alerts.jsonl"), ("sgx", "sgx-alerts.jsonl")):
    identities = {row["case"]: row for row in map(json.loads, Path(f"{phase}-identities.jsonl").read_text().splitlines())}
    assert set(identities) == {"existing", "new"}, identities
    matches = set()
    for row in (json.loads(line) for line in Path(alerts).read_text().splitlines() if line.startswith("{")):
        fields = row["output_fields"]
        for case, inspected in identities.items():
            if row["rule"] not in rules or f"falco_runtime_case_{case}" not in (fields.get("proc.args") or ""):
                continue
            assert inspected["image"] == image, inspected
            assert inspected["privileged"] == (case == "new" and rootless == "false"), inspected
            assert fields["container.type"] == engine, fields
            assert fields["container.full_id"] == inspected["id"], fields
            assert fields["container.name"] == inspected["name"], fields
            assert fields["container.image.repository"] == image.rsplit(":", 1)[0], fields
            assert fields["container.privileged"] == inspected["privileged"], fields
            matches.add((case, row["rule"]))
    assert matches == {(case, rule) for case in identities for rule in rules}, (phase, matches)
    result[phase] = {"containers": identities, "alerts": sorted(matches)}

stats = [json.loads(line) for line in Path("sgx.log").read_text().splitlines() if line.startswith("{")]
driver = next(row for row in stats if row.get("mode") == "modern_ebpf")
enclave = next(row for row in stats if row.get("mode") == "live")
assert driver["driver_drops"] == enclave["format_rejected"] == 0
assert driver["driver_events"] == enclave["accepted"] == enclave["records"]
assert driver["consumer"] == driver["producer"] == enclave["consumer"] == enclave["producer"]
assert enclave["snapshot_bytes"] + enclave["trace_bytes"] == Path("reference.scap").stat().st_size
print(json.dumps({"pass": True, "runtime": engine, "rootless": rootless == "true",
                  "live": result, "driver": driver, "enclave": enclave}, indent=2))
PY
